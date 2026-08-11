# TLS, and How It Uses Post-Quantum Cryptography

Every cloud-hosted tool in [`docs/alternatives.md`](alternatives.md)
protects its network traffic with **TLS** (Transport Layer Security),
which is really just an orchestration layer that combines the
primitives already covered in this docs set —
[asymmetric key agreement](asymmetric-cryptography.md),
[symmetric AEAD encryption](symmetric-cryptography.md), and
[hashing](hashing.md) — into one handshake-then-transport protocol.
This doc explains how a TLS 1.3 connection is actually built, then
where the [hybrid X25519+ML-KEM](post-quantum-cryptography.md) exchange
plugs into that handshake.

## What TLS is actually doing

TLS has two phases:

1. **Handshake** — client and server agree on a shared symmetric key,
   using asymmetric crypto, while authenticating that they're talking
   to who they think they are.
2. **Record protocol** — once the handshake is done, all further data
   is just [AEAD-encrypted](symmetric-cryptography.md) (AES-256-GCM or
   ChaCha20-Poly1305 in TLS 1.3) using the key the handshake produced.

The handshake is the interesting part for this doc, since it's where
key agreement, authentication, and (now) PQC all interact.

## The TLS 1.3 handshake

TLS 1.3 (RFC 8446) simplified and hardened the handshake compared to
1.2 — fewer round trips, no more legacy weak ciphers, and the property
that (almost) the entire handshake after the first message is itself
encrypted. At a high level, for a fresh connection with no prior
session:

```
Client                                           Server
  ClientHello
    + key_share (client's ephemeral public keys, one per group)
    + supported_groups, signature_algorithms
  ------------------------------------------------------------>
                                            ServerHello
                                              + key_share (server's ephemeral public key, chosen group)
                                            EncryptedExtensions
                                            Certificate
                                            CertificateVerify (signature over the handshake so far)
                                            Finished
  <------------------------------------------------------------
  Finished
  ------------------------------------------------------------>
  [ application data, AEAD-encrypted with the derived key ]
```

Breaking that down against the primitives already covered:

- **`key_share`** is where [key agreement](asymmetric-cryptography.md)
  happens: the client proposes one or more ephemeral public keys (one
  per "group" it supports — e.g. X25519, P-256), the server picks one
  it also supports and responds with its own ephemeral public key for
  that group. Both sides then run ECDH (or, as covered below, a hybrid
  KEM) locally to arrive at the **same shared secret** without ever
  transmitting it.
- **Ephemeral keys, every time:** these key-share keypairs are
  generated fresh for each connection and discarded afterward — this
  is what gives TLS 1.3 **forward secrecy**: even if a server's
  long-term certificate private key is later compromised, past
  session traffic recorded by an eavesdropper still can't be decrypted,
  because the actual encryption key was derived from ephemeral values
  no one retained.
- **`Certificate` + `CertificateVerify`** is the *authentication* half
  that plain Diffie-Hellman/ECDH lacks on its own (see the
  man-in-the-middle discussion in
  [`asymmetric-cryptography.md`](asymmetric-cryptography.md)): the
  server presents a certificate binding its long-term public key to its
  domain name (issued by a CA the client trusts), then signs a
  transcript of the handshake with the corresponding private key,
  proving it actually holds that key — not just relaying messages
  between the client and some other party.
- **Key derivation:** the raw ECDH/KEM shared secret isn't used
  directly as an encryption key. It's run through **HKDF** (a
  [hash](hashing.md)-based key derivation function built on HMAC — the
  same primitive family as
  [PBKDF2's HMAC core](key-derivation.md), but tuned for deriving
  several independent keys from one high-entropy secret, not for
  slowing down a low-entropy password) to produce separate keys for
  each direction of traffic and each handshake phase.
- **Record protocol:** application data is then encrypted with an AEAD
  cipher — [AES-256-GCM or ChaCha20-Poly1305](symmetric-cryptography.md)
  — using the derived key, giving every record both confidentiality
  and integrity.

## Where the post-quantum hybrid exchange fits in

Everything above still applies unchanged with PQC enabled — **only the
`key_share`/`supported_groups` step changes.** This is the detail that
makes hybrid PQC deployment relatively low-friction: it's a drop-in
replacement for one negotiated value, not a redesign of the protocol.

- **A new "group" codepoint, not a new mechanism:** TLS already
  supported negotiating *which* key-agreement group to use (X25519 vs.
  P-256 vs. others) — PQC just adds new codepoints to that same list,
  such as `X25519MLKEM768`, which client and server negotiate exactly
  like any other group via `supported_groups`/`key_share`.
- **What actually travels over the wire for a hybrid group:** the
  client's `key_share` entry for `X25519MLKEM768` concatenates *two*
  independent public values — a normal X25519 ECDH public key, and an
  ML-KEM-768 encapsulation key. The server's response similarly
  contains its X25519 public key plus the ML-KEM ciphertext
  encapsulating a shared secret to that key. Structurally, this is one
  extension carrying two unrelated key-agreement payloads back to
  back, not a new handshake message type.
- **Combining the two secrets:** the client and server each end up
  computing two shared secrets independently — the classical X25519
  ECDH result, and the ML-KEM decapsulated secret — which are
  concatenated and fed into the same HKDF step described above,
  producing a single combined secret that seeds the rest of the
  handshake's key schedule. This is exactly the "as strong as the
  stronger half" hybrid property described in
  [`post-quantum-cryptography.md`](post-quantum-cryptography.md):
  breaking the session requires breaking *both* X25519 and ML-KEM-768,
  not just one.
- **Authentication is still classical (for now):** the `Certificate` /
  `CertificateVerify` signature step is unaffected by this — it still
  uses RSA or ECDSA signatures today. NIST's post-quantum signature
  standard (**ML-DSA**, see
  [`post-quantum-cryptography.md`](post-quantum-cryptography.md)) is
  newer and its certificate-chain/CA ecosystem migration is a separate,
  slower-moving effort than the key-exchange side — so a
  "post-quantum TLS" connection today typically means the *key
  agreement* is hybrid-protected against harvest-now-decrypt-later,
  while the *server authentication* is still only as strong as
  classical ECDSA/RSA against a future quantum adversary. That
  asymmetry is intentional: forward-secrecy-relevant traffic
  confidentiality is the urgent "harvest now" risk, whereas a forged
  certificate has to be exploited in real time during an active
  attack, not stored and cracked years later.
- **Size/performance cost:** ML-KEM-768's public keys and ciphertexts
  add roughly 1–1.5 KB to the `key_share` extension compared to a
  pure-X25519 handshake (a few dozen bytes) — a real but modest
  increase, well within normal handshake sizes, and negligible
  compared to the size of a typical certificate chain.
- **Negotiation and fallback:** because this is just another
  `supported_groups` entry, a client offering `X25519MLKEM768` degrades
  gracefully to plain `X25519` (or any other mutually supported group)
  against a server that doesn't recognize the PQC codepoint — no
  protocol version bump is required, which is why browsers and servers
  have been able to roll this out incrementally rather than needing a
  flag-day cutover.

## Practical takeaway

TLS's handshake was already structured as "negotiate a key-agreement
group, then derive keys via HKDF, then encrypt with AEAD" — hybrid PQC
support is essentially just adding `X25519MLKEM768` (or similar) to the
list of groups a client/server can pick, concatenating its output with
the classical ECDH secret before the existing HKDF step, and leaving
everything else — record encryption, certificate authentication,
forward secrecy via ephemeral keys — unchanged. That's precisely why
Apple's and Google's PQC rollouts referenced in
[`docs/alternatives.md`](alternatives.md#post-quantum-readiness) could
ship as an incremental, backward-compatible upgrade to transport
security, well ahead of any surveyed password manager changing how it
encrypts the vault itself.
