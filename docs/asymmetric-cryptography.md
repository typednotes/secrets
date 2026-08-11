# Asymmetric Cryptography

Where [symmetric cryptography](symmetric-cryptography.md) uses one
shared key for both encryption and decryption, **asymmetric
(public-key) cryptography** uses a mathematically linked key pair: a
**public key** anyone can know, and a **private key** only its owner
holds. This is what lets the tools in
[`docs/alternatives.md`](alternatives.md) solve problems symmetric
crypto can't on its own — securely sharing a vault with someone you've
never exchanged a secret with, and authenticating a login without ever
transmitting the password itself. This doc covers RSA, ECC, and the
Diffie-Hellman/SRP family, as they appear in
[`tools/bitwarden.md`](tools/bitwarden.md), [`tools/pass.md`](tools/pass.md),
[`tools/proton-pass.md`](tools/proton-pass.md), and others.

## What asymmetric crypto is used for here

Three distinct jobs show up across these tools, and it's easy to
conflate them:

1. **Encryption to a public key** — anyone can encrypt data that only
   the private-key holder can decrypt. Used for sharing a vault/item
   key with another user (Bitwarden organizations, OpenPGP
   multi-recipient files in `pass`) without ever needing a prior
   shared secret.
2. **Digital signatures** — the private-key holder signs data; anyone
   with the public key can verify it came from them and wasn't
   altered. Used for verifying software releases, OpenPGP identity
   trust, and some authentication protocols.
3. **Key agreement / authentication without transmitting a secret** —
   two parties derive a shared secret over an insecure channel without
   ever sending the secret (or a password) itself. This is what
   Diffie-Hellman and SRP are for.

## RSA

**Rivest–Shamir–Adleman** (1977) is the oldest widely-deployed public-key
system, based on the difficulty of factoring the product of two large
prime numbers.

- **Key pair:** a public key `(n, e)` and private key `(n, d)`, where
  `n` is the product of two large secret primes. Common key sizes
  today are 2048 or 4096 bits (much larger than symmetric key sizes,
  because the best known factoring attacks are far more effective
  against RSA's structure than brute force is against AES).
- **Direct encryption use:** RSA can encrypt data directly under a
  public key (in practice, using padding schemes like OAEP to prevent
  structural attacks), but only up to a size roughly related to the
  key length — so in every tool surveyed here, RSA is used to encrypt
  a *symmetric key* (a "key-wrapping" step), never the vault data
  itself. Bitwarden wraps an organization's shared vault key in each
  member's RSA public key so only their private key can unwrap it
  (see [`tools/bitwarden.md`](tools/bitwarden.md)).
- **Signatures:** RSA can also sign data (a related but distinct
  operation from encryption), used in some certificate and update-
  verification schemes.
- **Performance/size tradeoff:** RSA keys and ciphertexts are large
  compared to ECC for equivalent security, and operations are slower
  — one reason newer designs increasingly prefer ECC.

## ECC (Elliptic Curve Cryptography)

ECC achieves the same goals as RSA (encryption, signatures, key
agreement) using the algebraic structure of points on an elliptic
curve over a finite field, based on the difficulty of the **elliptic
curve discrete logarithm problem**.

- **Why it's preferred in new designs:** ECC achieves equivalent
  security to RSA with far smaller keys — a 256-bit ECC key is
  considered roughly comparable in strength to a 3072-bit RSA key —
  which means smaller ciphertexts/signatures and faster operations,
  particularly valuable on mobile devices and for protocols with many
  handshakes.
- **Common curves:** NIST P-256/P-384 (widely standardized, used in
  TLS and WebAuthn), and Curve25519/Ed25519 (designed by Daniel J.
  Bernstein for both high performance and to avoid categories of
  implementation pitfalls that affected some NIST curves — used in
  SSH, Signal, and modern OpenPGP keys).
- **ECDH (Elliptic Curve Diffie-Hellman):** the key-agreement use of
  ECC — see the Diffie-Hellman section below, since the *protocol
  idea* is the same, just instantiated over elliptic curve math
  instead of modular exponentiation.
- **ECDSA / EdDSA:** the signature schemes built on ECC, used for
  passkeys/WebAuthn credentials (see
  [`tools/apple-keychain.md`](tools/apple-keychain.md)) and modern
  OpenPGP signing keys.
- **Where it shows up in these tools:** WebAuthn/passkey credentials
  are built entirely on ECC (or the related Ed25519), and modern
  OpenPGP keys (used by `pass` and Proton Pass) increasingly default
  to Curve25519-based keys over RSA.

## Diffie-Hellman (DH) and key agreement

**Diffie-Hellman key exchange** (1976) solves a different problem than
RSA/ECC encryption: it lets two parties who have never met establish a
**shared secret** over a channel an eavesdropper can fully observe,
without ever transmitting the secret itself.

- **Mechanism (classic, modular-exponentiation form):** both parties
  agree on public parameters (a large prime `p` and generator `g`).
  Each picks a private random value, computes a public value from it
  (`g^a mod p`), and exchanges public values. Each then combines their
  own private value with the other's public value to arrive at the
  *same* shared secret (`g^(ab) mod p`) — which an eavesdropper,
  seeing only the public values, cannot feasibly compute (the
  discrete logarithm problem).
- **ECDH:** the same idea performed with elliptic-curve point
  multiplication instead of modular exponentiation — smaller keys,
  faster, and the form actually used in TLS 1.3 and modern messaging
  protocols today.
- **What DH does *not* provide on its own:** authentication. Plain
  Diffie-Hellman is vulnerable to a **man-in-the-middle attack** — an
  attacker who can intercept both directions can run DH separately
  with each party and relay/re-encrypt everything, undetected. Real
  protocols (TLS, SSH) always combine DH/ECDH with a *separate*
  authentication step (certificates, signatures, or known host keys)
  to bind the exchange to a verified identity.

## SRP (Secure Remote Password)

**SRP** (RFC 2945/5054) is a **Password-Authenticated Key Exchange**
(PAKE) protocol: it lets a client prove knowledge of a password to a
server *without ever sending the password, or anything equivalent to
it, over the network* — and without the server needing to store the
plaintext password either.

- **Why it's more than "just send a password hash over TLS":** even
  with TLS protecting the channel, sending a password hash to the
  server means the server sees an artifact that, if compromised
  (server breach, TLS interception via a compromised CA, buggy proxy),
  is directly useful to an attacker for offline brute-forcing or
  replay. SRP is designed so the server only ever stores a
  **verifier** derived from the password — not the password or a
  simple hash of it — and the network exchange proves password
  knowledge through a challenge built on Diffie-Hellman-style math,
  without transmitting that verifier or the password.
- **Mechanism (conceptually):** at signup, the client derives a
  private key from the password and salt (via a KDF — see
  [`key-derivation.md`](key-derivation.md)), and sends the server a
  **verifier** (`v = g^x mod N`, derived from that private value) —
  structurally similar to how a public key is derived from a private
  key, so the server holds something whose corresponding "private"
  value it can never recover from the verifier alone. At login, client
  and server run a DH-like exchange incorporating the verifier/private
  value on each side; both arrive at a shared session key *only if*
  the client's password was correct, and an eavesdropper or a
  malicious server operator learns nothing usable for offline
  password guessing from the exchange itself.
- **Where it's used:** Proton Pass (and the wider Proton ecosystem)
  uses SRP for login authentication specifically so that Proton's own
  servers never see or store anything equivalent to the plaintext
  password (see [`tools/proton-pass.md`](tools/proton-pass.md)) —
  consistent with their zero-knowledge design even at the
  authentication layer, not just for vault data at rest.
- **Contrast with typical password-manager logins:** Bitwarden-family
  tools instead derive a **master password hash** client-side and send
  *that* hash to the server as the login credential (itself never
  reused as an encryption key) — simpler than SRP, but it does mean
  the server sees and stores a verifiable artifact of the password,
  making SRP a stronger design in this specific respect (see the
  comparison in [`tools/bitwarden.md`](tools/bitwarden.md)).

## How these combine in practice

None of these primitives are used alone — real systems layer them:

- **TLS 1.3** uses ECDH for key agreement (fresh per session, giving
  forward secrecy) plus certificate-based signatures for
  authentication, so the DH exchange can't be silently
  man-in-the-middled.
- **OpenPGP** (`pass`, Proton Pass) combines RSA or ECC public-key
  encryption (to wrap a per-message symmetric key) with RSA/ECDSA/EdDSA
  signatures (to prove authenticity), then uses a symmetric AEAD-style
  cipher for the bulk data itself.
- **WebAuthn/passkeys** use ECC/EdDSA signatures as a
  possession-and-biometric-bound replacement for passwords entirely,
  sidestepping the password-transmission problem SRP solves in a
  different way.

## Comparison

| | RSA | ECC (ECDH/ECDSA) | Diffie-Hellman (classic) | SRP |
|---|---|---|---|---|
| Core hard problem | Integer factorization | Elliptic curve discrete log | Discrete logarithm (mod p) | DH-based, plus password verifier |
| Typical use here | Wrapping shared vault keys | Passkeys, modern OpenPGP keys, TLS key agreement | Underlying idea behind ECDH | Password-based login without transmitting the password |
| Provides authentication alone? | Yes, via signatures | Yes, via signatures | No — needs a separate auth step | Yes — proves password knowledge |
| Relative key/message size | Large | Small | Large (mod p) / small (EC form) | N/A (protocol, not a cipher) |
| Used by (from this repo's surveys) | Bitwarden org key sharing | WebAuthn/passkeys, modern OpenPGP | TLS/SSH (as ECDH) | Proton Pass login |

## Practical takeaway

Asymmetric crypto answers "how do I share a secret with someone I've
never met, or prove I know a password without sending it" — problems
symmetric encryption structurally cannot solve on its own. Prefer ECC
over RSA for new designs (smaller, faster, equivalent security), never
use plain Diffie-Hellman without a separate authentication step, and
recognize SRP as a meaningfully stronger login design than
"hash-then-send" precisely because the server never holds an artifact
useful for offline password guessing.
