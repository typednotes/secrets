use aes_gcm::Aes256Gcm;
use aes_gcm::aead::array::Array;
use aes_gcm::aead::{Aead as _, Generate, KeyInit, Nonce};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("encryption failed")]
    Seal,
    #[error("decryption failed (tampered or wrong key)")]
    Open,
}

pub trait Aead: Send + Sync {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn open(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Whether this blob is already sealed under the key `seal` would use.
    /// Rewrapping asks this so it can skip values that need no work; a
    /// single-key implementation has nothing to rotate to, hence the default.
    fn is_current(&self, _blob: &[u8]) -> bool {
        true
    }

    /// A short, stable label for the key `seal` is using, so an operator can
    /// confirm which key a replica actually holds.
    fn active_key_id(&self) -> String {
        "unversioned".to_string()
    }
}

/// Marks a blob that carries its key id. Values written before key rotation
/// existed begin directly with the nonce and carry no id, so they are
/// recognised by *failing* to decrypt as versioned — the GCM tag is what makes
/// that safe rather than a guess.
const VERSIONED_MARKER: u8 = 0x01;
const KEY_ID_LEN: usize = 4;
const NONCE_LEN: usize = 12;

/// Identifies a key by a prefix of its own SHA-256, rather than by a
/// configured label. Nothing to keep in sync between replicas, and an
/// operator cannot mislabel a key.
pub fn key_id(key: &[u8; 32]) -> u32 {
    let digest = Sha256::digest(key);
    u32::from_be_bytes(digest[..KEY_ID_LEN].try_into().expect("sha256 is 32 bytes"))
}

struct Key {
    id: u32,
    cipher: Aes256Gcm,
}

/// One active key for sealing plus any number of retired keys kept only for
/// opening. This is what makes the master key rotatable: run with both, rewrap
/// the store, then drop the old key.
pub struct KeyRing {
    active: Key,
    retired: Vec<Key>,
}

impl KeyRing {
    pub fn new(active: &[u8; 32], retired: &[[u8; 32]]) -> Self {
        Self {
            active: Key {
                id: key_id(active),
                cipher: Aes256Gcm::new(active.into()),
            },
            retired: retired
                .iter()
                .map(|key| Key {
                    id: key_id(key),
                    cipher: Aes256Gcm::new(key.into()),
                })
                .collect(),
        }
    }

    pub fn active_key_id(&self) -> u32 {
        self.active.id
    }

    /// The number of keys that exist only to read old data. Zero means the
    /// store is fully rewrapped, or was never rotated.
    pub fn retired_key_count(&self) -> usize {
        self.retired.len()
    }

    /// The key id recorded in a blob, or `None` for a pre-rotation value.
    fn embedded_key_id(blob: &[u8]) -> Option<u32> {
        if blob.len() < 1 + KEY_ID_LEN + NONCE_LEN || blob[0] != VERSIONED_MARKER {
            return None;
        }
        Some(u32::from_be_bytes(
            blob[1..1 + KEY_ID_LEN].try_into().expect("checked length"),
        ))
    }

    fn keys(&self) -> impl Iterator<Item = &Key> {
        std::iter::once(&self.active).chain(self.retired.iter())
    }
}

impl Aead for KeyRing {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = Nonce::<Aes256Gcm>::generate();
        let ciphertext = self
            .active
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| CryptoError::Seal)?;

        let mut out = Vec::with_capacity(1 + KEY_ID_LEN + nonce.len() + ciphertext.len());
        out.push(VERSIONED_MARKER);
        out.extend_from_slice(&self.active.id.to_be_bytes());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn open(&self, blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Versioned: go straight to the named key. A blob whose id is not in
        // the ring means the operator dropped a key that is still in use.
        if let Some(id) = Self::embedded_key_id(blob)
            && let Some(key) = self.keys().find(|key| key.id == id)
        {
            let (nonce, ciphertext) = blob[1 + KEY_ID_LEN..].split_at(NONCE_LEN);
            let nonce = Array::try_from(nonce).map_err(|_| CryptoError::Open)?;
            if let Ok(plaintext) = key.cipher.decrypt(&nonce, ciphertext) {
                return Ok(plaintext);
            }
        }

        // Pre-rotation layout: the whole blob is `nonce || ciphertext`. Trying
        // every key is safe because GCM authenticates — a wrong key cannot
        // produce a plausible plaintext.
        if blob.len() >= NONCE_LEN {
            let (nonce, ciphertext) = blob.split_at(NONCE_LEN);
            if let Ok(nonce) = Array::try_from(nonce) {
                for key in self.keys() {
                    if let Ok(plaintext) = key.cipher.decrypt(&nonce, ciphertext) {
                        return Ok(plaintext);
                    }
                }
            }
        }
        Err(CryptoError::Open)
    }

    fn is_current(&self, blob: &[u8]) -> bool {
        Self::embedded_key_id(blob) == Some(self.active.id)
    }

    fn active_key_id(&self) -> String {
        format!("{:08x}", self.active.id)
    }
}

/// AES-256-GCM in the pre-rotation layout: `nonce || ciphertext || tag`, with
/// no key id. Retained because it is what every value written before 1.0 looks
/// like, and `KeyRing` still reads that form — new deployments should use
/// `KeyRing`, which is what the server wires up.
pub struct Aes256GcmAead {
    cipher: Aes256Gcm,
}

impl Aes256GcmAead {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new(key.into()),
        }
    }
}

impl Aead for Aes256GcmAead {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = Nonce::<Aes256Gcm>::generate();
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| CryptoError::Seal)?;
        let mut out = Vec::with_capacity(nonce.len() + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn open(&self, blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if blob.len() < 12 {
            return Err(CryptoError::Open);
        }
        let (nonce, ciphertext) = blob.split_at(12);
        let nonce = Array::try_from(nonce).map_err(|_| CryptoError::Open)?;
        self.cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| CryptoError::Open)
    }
}

pub trait MasterKeyProvider: Send + Sync {
    fn current_key(&self) -> [u8; 32];

    /// Keys kept only so previously-written values still open. Empty unless a
    /// rotation is in progress.
    fn retired_keys(&self) -> Vec<[u8; 32]> {
        Vec::new()
    }
}

/// v1 master key source: a hex-encoded 32-byte key from an env var, or (if
/// the env var holds a path instead) read from a file. Swappable later for
/// a KMS-backed provider without touching `Barrier` or its callers.
pub struct StaticMasterKeyProvider {
    key: [u8; 32],
    retired: Vec<[u8; 32]>,
}

impl StaticMasterKeyProvider {
    pub fn from_hex(hex_key: &str) -> Result<Self, CryptoError> {
        Ok(Self {
            key: decode_key(hex_key)?,
            retired: Vec::new(),
        })
    }

    pub fn from_env(var: &str) -> Result<Self, CryptoError> {
        Self::from_hex(&read_env_or_file(var)?)
    }

    /// Adds decrypt-only keys from a comma-separated env var. Absent or empty
    /// is normal — it means no rotation is in flight.
    pub fn with_retired_from_env(mut self, var: &str) -> Result<Self, CryptoError> {
        let Ok(raw) = read_env_or_file(var) else {
            return Ok(self);
        };
        for candidate in raw.split(',').map(str::trim).filter(|c| !c.is_empty()) {
            self.retired.push(decode_key(candidate)?);
        }
        Ok(self)
    }
}

fn decode_key(hex_key: &str) -> Result<[u8; 32], CryptoError> {
    let bytes = hex::decode(hex_key.trim()).map_err(|_| CryptoError::Seal)?;
    bytes.try_into().map_err(|_| CryptoError::Seal)
}

fn read_env_or_file(var: &str) -> Result<String, CryptoError> {
    let value = std::env::var(var).map_err(|_| CryptoError::Seal)?;
    // The env var may hold the key itself or a path to a file containing it.
    Ok(std::fs::read_to_string(&value).unwrap_or(value))
}

impl MasterKeyProvider for StaticMasterKeyProvider {
    fn current_key(&self) -> [u8; 32] {
        self.key
    }

    fn retired_keys(&self) -> Vec<[u8; 32]> {
        self.retired.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aead() -> Aes256GcmAead {
        Aes256GcmAead::new(&[7u8; 32])
    }

    #[test]
    fn round_trip() {
        let aead = aead();
        let plaintext = b"super secret value";
        let sealed = aead.seal(plaintext).unwrap();
        assert_eq!(aead.open(&sealed).unwrap(), plaintext);
    }

    #[test]
    fn tamper_detection() {
        let aead = aead();
        let mut sealed = aead.seal(b"super secret value").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert!(aead.open(&sealed).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let sealed = aead().seal(b"super secret value").unwrap();
        let other = Aes256GcmAead::new(&[9u8; 32]);
        assert!(other.open(&sealed).is_err());
    }

    const OLD: [u8; 32] = [7u8; 32];
    const NEW: [u8; 32] = [11u8; 32];

    #[test]
    fn key_ids_are_derived_and_distinct() {
        assert_eq!(key_id(&OLD), key_id(&OLD));
        assert_ne!(key_id(&OLD), key_id(&NEW));
    }

    #[test]
    fn keyring_round_trip_and_marks_its_own_output_current() {
        let ring = KeyRing::new(&NEW, &[]);
        let sealed = ring.seal(b"hunter2").unwrap();
        assert_eq!(ring.open(&sealed).unwrap(), b"hunter2");
        assert!(ring.is_current(&sealed));
        assert_eq!(ring.active_key_id(), key_id(&NEW));
    }

    /// The compatibility case that matters: data written before rotation
    /// existed carries no key id, and must still open.
    #[test]
    fn keyring_reads_pre_rotation_values() {
        let legacy = Aes256GcmAead::new(&OLD).seal(b"written in 0.1").unwrap();
        let ring = KeyRing::new(&OLD, &[]);
        assert_eq!(ring.open(&legacy).unwrap(), b"written in 0.1");
        // …and is reported as stale, so rewrapping upgrades it.
        assert!(!ring.is_current(&legacy));
    }

    /// Mid-rotation: the new key seals, the retired key still opens.
    #[test]
    fn keyring_opens_values_sealed_by_a_retired_key() {
        let before = KeyRing::new(&OLD, &[]);
        let sealed = before.seal(b"sealed under the old key").unwrap();

        let rotating = KeyRing::new(&NEW, &[OLD]);
        assert_eq!(rotating.open(&sealed).unwrap(), b"sealed under the old key");
        assert!(
            !rotating.is_current(&sealed),
            "a value on the retired key must be reported as needing rewrap"
        );
        assert_eq!(rotating.retired_key_count(), 1);
    }

    /// Dropping a key that is still in use must fail loudly, not silently
    /// return garbage.
    #[test]
    fn keyring_refuses_a_value_whose_key_is_gone() {
        let sealed = KeyRing::new(&OLD, &[]).seal(b"orphaned").unwrap();
        assert!(KeyRing::new(&NEW, &[]).open(&sealed).is_err());
    }

    #[test]
    fn keyring_detects_tampering() {
        let ring = KeyRing::new(&NEW, &[]);
        let mut sealed = ring.seal(b"hunter2").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert!(ring.open(&sealed).is_err());
    }

    /// A truncated or empty blob must not panic on the slicing in `open`.
    #[test]
    fn keyring_rejects_short_blobs_without_panicking() {
        let ring = KeyRing::new(&NEW, &[]);
        for len in 0..20 {
            assert!(ring.open(&vec![VERSIONED_MARKER; len]).is_err());
        }
    }
}
