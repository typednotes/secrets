# Symmetric Cryptography

Once a [key derivation function](key-derivation.md) turns a master
password into a key, that key is used with a **symmetric cipher** to
actually encrypt the vault contents — the same key encrypts and
decrypts, unlike the asymmetric (public/private key) schemes used
elsewhere for sharing (see e.g. RSA in
[`tools/bitwarden.md`](tools/bitwarden.md) or OpenPGP in
[`tools/pass.md`](tools/pass.md)). This doc covers the block/stream
ciphers and modes that show up across the tools in
[`docs/alternatives.md`](alternatives.md): AES-256, ChaCha20, their
AEAD (authenticated encryption) constructions, and why "just encrypt
it" is not enough on its own.

## Block ciphers vs. stream ciphers

- A **block cipher** (AES, Twofish) transforms a fixed-size block of
  data (16 bytes for AES) at a time using the key. To encrypt data
  longer than one block, you need a **mode of operation** that chains
  blocks together.
- A **stream cipher** (ChaCha20) generates a pseudorandom keystream
  from the key and a nonce, then XORs it with the plaintext of
  arbitrary length — no block chaining or padding needed.

## AES-256

The **Advanced Encryption Standard** (FIPS 197, 2001) is a block
cipher operating on 128-bit (16-byte) blocks, with AES-256 using a
256-bit key (also seen: AES-128, AES-192 — the number is the key
size, not the block size, which is always 128 bits for AES).

- **Structure:** a substitution-permutation network — 14 rounds (for
  AES-256) of byte substitution, row shifting, column mixing, and
  key-mixing steps.
- **Hardware acceleration:** most modern CPUs (x86 via AES-NI, ARM via
  the Cryptography Extensions) have dedicated instructions for AES,
  making it extremely fast and, critically, **constant-time** —
  avoiding cache-timing side channels that plagued early
  software-only AES implementations.
- **Modes of operation** (how AES is applied across multiple blocks):
  - **CBC (Cipher Block Chaining):** each plaintext block is XORed
    with the previous ciphertext block before encryption, using a
    random **IV (initialization vector)** for the first block.
    CBC provides confidentiality only — it has **no built-in
    integrity check**, so a separate MAC (see below) is required.
    Used by LastPass and (for the legacy/inner encryption layer) by
    Bitwarden.
  - **GCM (Galois/Counter Mode):** a counter-mode cipher combined with
    a Galois-field MAC, producing an **AEAD** construction — a single
    pass that gives you both confidentiality *and* integrity/
    authenticity (see below). Used by HashiCorp Vault's storage
    barrier and increasingly preferred over CBC+HMAC for new designs.
  - **CTR / other counter-style modes:** turn a block cipher into a
    stream cipher by encrypting an incrementing counter and XORing
    the result with plaintext; GCM is built on top of this idea.

## ChaCha20 (and ChaCha20-Poly1305)

Designed by Daniel J. Bernstein as a refinement of his earlier
Salsa20, standardized in RFC 8439 (commonly as the variant
**XChaCha20** for its extended 24-byte nonce, which removes the risk
of nonce reuse in high-volume or randomly-generated-nonce settings).

- **Structure:** a stream cipher built from add-rotate-XOR (ARX)
  operations on a 4x4 matrix of 32-bit words, run for 20 rounds. No
  substitution tables, no lookups — every operation is a simple
  integer op.
- **Why it exists alongside AES:** ChaCha20 is fast and
  **constant-time in pure software**, without needing dedicated CPU
  instructions. This matters on hardware without AES-NI (older or
  low-power mobile/embedded chips), where software AES can be slow
  *and* vulnerable to cache-timing attacks if implemented naively.
  ChaCha20 sidesteps both problems.
- **ChaCha20-Poly1305 / XChaCha20-Poly1305:** pairs the cipher with
  the **Poly1305** MAC to form an AEAD scheme, directly comparable to
  AES-GCM. NordPass uses XChaCha20-Poly1305 as its vault cipher
  (see [`tools/nordpass.md`](tools/nordpass.md)); it's also the AEAD
  used in the widely-adopted NaCl/libsodium `crypto_box` construction
  that KeePassXC's browser-integration protocol relies on (see
  [`tools/keepassxc.md`](tools/keepassxc.md)).
- **TLS relevance:** ChaCha20-Poly1305 is also a standard TLS 1.3
  cipher suite, chosen automatically by many clients/servers on
  hardware lacking AES acceleration.

## AEAD: why authentication has to be part of the design

**Confidentiality** (an attacker can't read the plaintext) is not the
same as **integrity/authenticity** (an attacker can't undetectably
*modify* the ciphertext). A raw block cipher mode like CBC only gives
you the former. Without a check, an attacker with write access to
encrypted storage could flip bits in the ciphertext and produce a
predictable, undetected change in the decrypted plaintext (a
"malleability" attack), or splice/replay old ciphertext blocks.

Two ways to add integrity:

1. **Encrypt-then-MAC:** encrypt with CBC, then compute an HMAC (e.g.
   HMAC-SHA256) over the ciphertext, and store/verify both. This is
   what Bitwarden's item-encryption scheme and KeePassXC's KDBX4
   block-integrity checks do.
2. **AEAD (Authenticated Encryption with Associated Data):** a single
   cipher construction that produces both ciphertext and an
   authentication tag in one pass — AES-GCM and ChaCha20-Poly1305 are
   the two dominant AEAD schemes in modern use. AEAD constructions
   also support "associated data": fields that are authenticated but
   not encrypted (e.g. a record's non-secret metadata), so tampering
   with them is still detected.

Decrypting *before* verifying the tag (or skipping verification) is a
classic implementation bug — always **verify integrity before ever
using or displaying the decrypted plaintext**.

## Nonces and IVs: the part that's easy to get wrong

Every mode discussed above needs a per-message value — an IV (CBC) or
nonce (CTR/GCM/ChaCha20) — that must never repeat under the same key:

- Reusing a **CBC IV** across two messages leaks information about
  whether their plaintexts share a common prefix.
- Reusing a **GCM or ChaCha20-Poly1305 nonce** under the same key is
  far worse: it allows an attacker to recover the authentication key
  and forge ciphertexts, and can leak the XOR of the two plaintexts —
  a full break of both confidentiality and integrity for those
  messages.
- This is precisely why **XChaCha20**'s extended 24-byte nonce is
  attractive for systems that generate nonces randomly rather than
  with a stateful counter: with a 12-byte nonce, random generation
  risks collision at scale (birthday bound); 24 bytes makes that
  practically impossible.

## Twofish and other legacy options

**Twofish** (an AES finalist candidate, still unbroken) appears as an
optional cipher in KeePassXC/KDBX4 for users wanting an alternative to
AES, largely for diversity/preference rather than because AES is
considered weaker. It sees little other adoption today since AES's
hardware acceleration and standardization won out.

## Comparison

| | AES-256 (GCM) | AES-256 (CBC+HMAC) | ChaCha20-Poly1305 |
|---|---|---|---|
| Type | Block cipher, counter-based AEAD | Block cipher, needs separate MAC | Stream cipher, native AEAD |
| Built-in integrity | Yes | No — must add HMAC separately | Yes |
| Best hardware fit | CPUs with AES-NI/ARM crypto ext | CPUs with AES-NI/ARM crypto ext | Any CPU, esp. without AES acceleration |
| Nonce/IV size | 96-bit nonce typical | 128-bit IV | 96-bit (ChaCha20) or 192-bit (XChaCha20) |
| Used by (from this repo's surveys) | HashiCorp Vault | Bitwarden/Vaultwarden (legacy), LastPass | NordPass, KeePassXC-Browser (NaCl box) |

## Practical takeaway

Prefer an AEAD construction (AES-256-GCM or ChaCha20/XChaCha20-Poly1305)
over an unauthenticated mode plus a bolted-on MAC — it's harder to
implement incorrectly and gives integrity "for free." Never reuse a
nonce/IV under the same key, prefer XChaCha20 over ChaCha20 when
nonces are randomly generated rather than counter-based, and remember
that the cipher is only as strong as the key it's given — a strong
AEAD scheme fed a weakly-derived key (see
[`key-derivation.md`](key-derivation.md)) is still broken in practice.
