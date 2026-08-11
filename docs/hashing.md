# Cryptographic Hashing

A **cryptographic hash function** takes an input of any size and
produces a fixed-size output (a "digest") in a way that is
deterministic, one-way, and collision-resistant. Hashing underlies
several other primitives already covered in this docs set — it's the
building block inside [KDFs](key-derivation.md) like PBKDF2/Argon2,
inside the HMAC construction used for integrity in
[symmetric cryptography](symmetric-cryptography.md), and inside
signature schemes in [asymmetric cryptography](asymmetric-cryptography.md).
This doc covers SHA-256 and HMAC specifically, since they're the pair
that shows up most across the tools in
[`docs/alternatives.md`](alternatives.md).

## Properties a cryptographic hash must have

- **Deterministic:** the same input always produces the same digest.
- **One-way (preimage resistance):** given a digest, it should be
  computationally infeasible to find *any* input that produces it.
- **Second-preimage resistance:** given a specific input, it should be
  infeasible to find a *different* input with the same digest.
- **Collision resistance:** it should be infeasible to find *any two*
  distinct inputs that produce the same digest (a strictly harder
  property than second-preimage resistance, and the one broken first
  when a hash function ages — as happened to MD5 and SHA-1).
- **Avalanche effect:** changing a single bit of input should change
  roughly half the output bits, with no discernible pattern relating
  input changes to output changes.

A hash is **not encryption** — there is no key and no way to "decrypt"
a digest back to its input. It's a one-way fingerprint, not a
reversible transformation.

## SHA-256

**SHA-256** ("Secure Hash Algorithm 2," 256-bit variant) is part of the
SHA-2 family (FIPS 180-4), standardized by NIST in 2001 as the
successor to the broken SHA-1 and MD5.

- **Output:** always exactly 256 bits (32 bytes), regardless of input
  size — hashing one byte or one gigabyte produces the same-length
  digest.
- **Structure:** a Merkle–Damgård construction — the input is padded
  and split into 512-bit blocks, each processed through 64 rounds of
  bitwise operations (rotations, XORs, modular additions) that mix in
  a running internal state, block by block, until all input is
  consumed.
- **Current status:** no practical collision or preimage attacks are
  known against full SHA-256; it remains the workhorse general-purpose
  hash across TLS certificates, Bitcoin, code-signing, Git's newer
  object format, and — relevant here — as the underlying hash inside
  PBKDF2-HMAC-SHA256 and inside HMAC-based authentication schemes used
  by several tools in this survey (see
  [`tools/bitwarden.md`](tools/bitwarden.md) and
  [`tools/lastpass.md`](tools/lastpass.md)).
- **Why it's *not* used alone for passwords:** SHA-256 is
  *deliberately fast* — exactly the wrong property for hashing a
  password directly, since an attacker with a stolen hash can compute
  billions of guesses per second on a GPU. This is why
  [key derivation functions](key-derivation.md) exist: PBKDF2 doesn't
  invent a new primitive, it just applies SHA-256 (via HMAC) over and
  over, deliberately amortizing that speed away. Never hash a password
  directly with SHA-256 (or any general-purpose hash) and call it
  secure — the fast-hash property that makes SHA-256 great for
  integrity checks makes it bad for password storage.

## HMAC

**HMAC** (Hash-based Message Authentication Code, RFC 2104) turns a
plain hash function into a **keyed** construction that proves both
integrity (the data wasn't altered) and authenticity (the sender knew
a shared secret key) — something a bare hash cannot do, since anyone
can compute a bare hash of anything with no secret involved.

- **The problem it solves:** if you just send `data` alongside
  `SHA256(data)`, anyone intercepting the message can alter `data` and
  recompute a matching hash — the hash alone proves nothing about who
  produced it. HMAC fixes this by mixing a **secret key** into the
  computation, so only someone holding the key can produce a valid tag.
- **Construction (conceptually):**
  ```
  HMAC(key, message) = H( (key ⊕ opad) || H( (key ⊕ ipad) || message ) )
  ```
  The key is XORed with two different padding constants (`ipad`,
  `opad`) and hashed in twice, with the inner hash's result fed into
  the outer one. This "hash twice, differently padded" structure is
  specifically designed to remain secure even though the underlying
  hash (like SHA-256) doesn't use a formal proof against related-key
  or length-extension attacks on its own — HMAC's construction is
  proven secure as long as the underlying hash is a reasonable
  pseudorandom function, which is why it's preferred over naive
  `H(key || message)` schemes (which *are* vulnerable to
  length-extension attacks with Merkle–Damgård hashes like SHA-256).
- **Naming convention:** "HMAC-SHA256" means HMAC instantiated with
  SHA-256 as the underlying hash — the most common combination in
  practice, producing a 256-bit authentication tag.
- **Where it's used across these tools:**
  - **Inside PBKDF2** — PBKDF2-HMAC-SHA256 uses HMAC as its core
    pseudorandom function, iterated many times (see
    [`key-derivation.md`](key-derivation.md)).
  - **Encrypt-then-MAC integrity** — Bitwarden's item encryption and
    KeePassXC's KDBX4 block-integrity checks compute an HMAC over
    ciphertext to detect tampering, since AES-CBC alone provides no
    authenticity (see [`symmetric-cryptography.md`](symmetric-cryptography.md)).
  - **API request signing / webhook verification** — a common pattern
    (used in various self-hosted and enterprise integrations) where a
    shared secret HMACs a request body so the receiver can verify it
    came from the expected sender and wasn't modified in transit.
  - **TLS (older cipher suites) and various token schemes** — HMAC
    remains one of the most widely reused primitives in applied
    cryptography precisely because it composes cleanly with any
    underlying hash function.

## Hash vs. HMAC vs. KDF — don't confuse the three

These three primitives are often mixed up because they all "take input,
produce fixed-size output," but they solve different problems:

| | Input | Secret involved? | Deliberately slow? | Purpose |
|---|---|---|---|---|
| **Hash** (SHA-256) | Any data | No | No (fast by design) | Fingerprint / integrity check of public or arbitrary data |
| **HMAC** (HMAC-SHA256) | Data + a shared key | Yes | No (fast by design) | Prove a message came from someone holding the key, and wasn't altered |
| **KDF** (PBKDF2/Argon2) | A password + salt | The password is the "secret" being protected | Yes (deliberately slow/expensive) | Turn a guessable password into a hard-to-brute-force key |

A hash with no key proves nothing about *who* produced it. HMAC proves
authenticity but is still fast, so it's wrong for password storage. A
KDF is slow on purpose, so it's wrong for high-throughput integrity
checks where speed matters (e.g. hashing large files or verifying
millions of HMAC tags per second).

## Practical takeaway

Reach for a plain hash (SHA-256) when you need a fast, keyless
fingerprint of data whose integrity you're checking against a
*trusted* reference (e.g. verifying a downloaded file against a
published checksum). Reach for HMAC when you need to prove a message
came from someone holding a shared secret and wasn't tampered with in
transit or storage — always pair an unauthenticated cipher mode like
AES-CBC with HMAC (or switch to an AEAD mode entirely, per
[`symmetric-cryptography.md`](symmetric-cryptography.md)). Never use a
plain hash or even plain HMAC to store or verify a password directly —
that's what [key derivation functions](key-derivation.md) exist to do.
