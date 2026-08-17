use aes_gcm::aead::array::Array;
use aes_gcm::aead::{Aead as _, Generate, KeyInit, Nonce};
use aes_gcm::Aes256Gcm;
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
}

/// AES-256-GCM, storing `nonce || ciphertext || tag` as a single blob.
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
}

/// v1 master key source: a hex-encoded 32-byte key from an env var, or (if
/// the env var holds a path instead) read from a file. Swappable later for
/// a KMS-backed provider without touching `Barrier` or its callers.
pub struct StaticMasterKeyProvider {
    key: [u8; 32],
}

impl StaticMasterKeyProvider {
    pub fn from_hex(hex_key: &str) -> Result<Self, CryptoError> {
        let bytes = hex::decode(hex_key.trim()).map_err(|_| CryptoError::Seal)?;
        let key: [u8; 32] = bytes.try_into().map_err(|_| CryptoError::Seal)?;
        Ok(Self { key })
    }

    pub fn from_env(var: &str) -> Result<Self, CryptoError> {
        let value = std::env::var(var).map_err(|_| CryptoError::Seal)?;
        if let Ok(contents) = std::fs::read_to_string(&value) {
            Self::from_hex(&contents)
        } else {
            Self::from_hex(&value)
        }
    }
}

impl MasterKeyProvider for StaticMasterKeyProvider {
    fn current_key(&self) -> [u8; 32] {
        self.key
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
}
