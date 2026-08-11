# Post-Quantum Cryptography (PQC)

Every asymmetric scheme covered in
[`asymmetric-cryptography.md`](asymmetric-cryptography.md) — RSA, ECC,
Diffie-Hellman — relies on a hard *classical* math problem (factoring,
discrete logarithms) that a large enough **quantum computer** could
solve efficiently. **Post-quantum cryptography** is the effort to
replace those primitives with ones believed to resist quantum attacks
too, using entirely different hard problems. This doc explains why
that's necessary, what Kyber/ML-KEM is, and why it's deployed
"hybrid" alongside X25519 rather than alone. See
[`docs/alternatives.md`](alternatives.md#post-quantum-readiness) for
where each surveyed password manager currently stands on this.

## Why classical asymmetric crypto is at risk

Two quantum algorithms matter here, and they affect symmetric and
asymmetric crypto very differently:

- **Shor's algorithm** (1994) can factor large integers and compute
  discrete logarithms in polynomial time on a sufficiently large,
  fault-tolerant quantum computer. That breaks **RSA, Diffie-Hellman,
  and ECC/ECDH/ECDSA outright** — not weakened, but fully solvable in
  practical time. This is the primitive PQC is racing to replace.
- **Grover's algorithm** only gives a quadratic speedup for
  brute-forcing unstructured search problems, which affects
  **symmetric crypto and hashes** far more mildly: it roughly halves
  the effective key length (AES-256 drops to a still-safe ~128-bit
  security level, not "broken"). This is why
  [`symmetric-cryptography.md`](symmetric-cryptography.md) and
  [`hashing.md`](hashing.md) primitives are considered "quantum-safe
  enough already" simply by using sufficiently large key/output sizes
  — no redesign needed, just bigger numbers. **PQC work is almost
  entirely about the asymmetric side.**

No quantum computer today is large or stable enough to run Shor's
algorithm against real-world key sizes. The urgency comes from
**"harvest now, decrypt later"**: an adversary can record encrypted
traffic (or exfiltrated ciphertext) today and decrypt it retroactively
once a capable quantum computer exists years from now. That's a real
threat for anything with long confidentiality requirements — a state
secret, a medical record, or a vault backup that might sit encrypted
for a decade — even though it's not yet a threat for keys and sessions
that are already discarded and re-derived moment to moment.

## Lattice-based cryptography: the new hard problem

Most standardized PQC schemes, including Kyber, are built on
**lattice problems** — most commonly variants of **Learning With
Errors (LWE)**, or its more efficient structured form,
**Module-LWE**. Informally: given a large grid ("lattice") of points
in many-dimensional space and a point that's been nudged slightly off
the grid, finding the nearest real grid point (or recovering the exact
nudge) is believed to be hard for both classical *and* quantum
computers — no known Shor-style quantum algorithm attacks lattice
problems efficiently, which is precisely why they were chosen as a
replacement.

This isn't the only PQC family (code-based, hash-based, and
multivariate schemes exist too, and NIST standardized a
hash-based signature scheme alongside lattice ones), but lattice-based
constructions are the ones behind Kyber/ML-KEM and its companion
signature scheme, and are the most widely deployed PQC family in
production today.

## Kyber / ML-KEM

**Kyber** was the algorithm selected by NIST's multi-year post-quantum
standardization competition for **key encapsulation** (the PQC
analogue of Diffie-Hellman/ECDH key agreement). NIST's finalized
standard version of it is published as **ML-KEM** (Module-Lattice-based
Key-Encapsulation Mechanism, FIPS 203) — "Kyber" and "ML-KEM" refer to
essentially the same underlying design; ML-KEM is the standardized name
you'll increasingly see in specs and library APIs, with "Kyber" as the
name used during development and still common in casual references.

- **What a KEM does, and how it differs from Diffie-Hellman:** in
  classic ECDH, both parties perform symmetric-looking operations to
  arrive at a shared secret. A **KEM (Key Encapsulation Mechanism)**
  is asymmetric in role: one party generates a keypair and publishes
  the public key; the other party uses that public key to
  "encapsulate" a randomly generated shared secret, producing a
  ciphertext; the keypair owner "decapsulates" that ciphertext with
  their private key to recover the same shared secret. The end result
  — both sides end up with a shared secret usable as a symmetric key —
  is the same goal as Diffie-Hellman, just structured differently to
  fit lattice math.
- **Security levels:** ML-KEM is standardized in three parameter sets
  (ML-KEM-512, -768, -1024) trading key/ciphertext size for security
  margin, roughly analogous to choosing AES-128 vs. AES-256.
  ML-KEM-768 is the most commonly deployed default, seen as
  comparable in strength to AES-192-equivalent classical security.
- **What it does *not* cover:** ML-KEM is a key-agreement primitive,
  not a signature scheme. The companion NIST-standardized PQC
  signature algorithm (for the "prove authenticity" role RSA/ECDSA
  play today) is **ML-DSA** (based on the CRYSTALS-Dilithium design,
  FIPS 204), with a hash-based alternative, **SLH-DSA**
  (based on SPHINCS+, FIPS 205), standardized as a more conservative
  fallback built on hash-function security rather than lattice
  assumptions.

## Why hybrid (X25519 + Kyber/ML-KEM), not PQC alone

Nearly every production PQC deployment today — including the TLS and
messaging rollouts referenced in
[`docs/alternatives.md`](alternatives.md#post-quantum-readiness) for
Apple and Google — combines a classical ECDH exchange (typically
**X25519**, the Curve25519-based ECDH function) with ML-KEM/Kyber,
rather than switching to ML-KEM outright. This is deliberate, for two
reasons:

1. **Defense in depth against a *new* primitive being wrong.** ECC
   and RSA have survived decades of public cryptanalysis; lattice-based
   ML-KEM has only been under serious scrutiny since the mid-2010s and
   was only finalized as a standard in 2024. Combining both means an
   attacker must break *both* the classical **and** the post-quantum
   half to recover the shared secret — so even if a subtle flaw is
   later found in ML-KEM's design or a specific implementation, X25519
   still protects the session against classical attackers, and vice
   versa (X25519 alone protects nothing against a quantum attacker,
   which is the whole point of adding ML-KEM).
2. **Regulatory and interoperability caution.** Several PQC candidates
   from earlier rounds of NIST's competition were broken *during* the
   standardization process itself (structural attacks were found
   against some finalists/alternates after years of prior confidence).
   That track record is exactly why hybrid deployment, not
   PQC-only, is the current consensus best practice — it hedges
   against exactly the kind of surprise that has already happened once
   in this specific standardization effort.
- **Mechanism (conceptually):** the two exchanges run independently
  and in parallel — a normal X25519 ECDH exchange, and a separate
  ML-KEM encapsulation/decapsulation — and their two resulting shared
  secrets are combined (concatenated and run through a key-derivation
  step) into the single symmetric key that actually protects the
  session, so the design collapses to "as strong as the stronger of
  the two" rather than needing either alone to be perfect.
- **Where this shows up today:** TLS 1.3 has standardized hybrid key
  exchange codepoints (`X25519MLKEM768` and similar), Apple's iMessage
  PQ3 protocol adds Kyber/ML-KEM to its existing Curve25519-based
  Diffie-Hellman ratchet, and Google has enabled hybrid post-quantum
  key exchange in Chrome's TLS stack — all as *transport-layer*
  protections, not (yet, per the survey in
  [`docs/alternatives.md`](alternatives.md)) as the vault-encryption
  scheme of any password manager covered in this repo.

## What PQC does *not* change

- It's purely about replacing the **asymmetric** layer (key exchange
  and signatures). The symmetric ciphers and hashes in
  [`symmetric-cryptography.md`](symmetric-cryptography.md) and
  [`hashing.md`](hashing.md) — AES-256, ChaCha20, SHA-256, HMAC — don't
  need PQC replacements; they just need adequately large key/output
  sizes, which they already have.
- SRP (see [`asymmetric-cryptography.md`](asymmetric-cryptography.md))
  is also DH-based under the hood and would need a PQC-hybrid
  redesign to remain quantum-resistant for authentication — no
  standardized "post-quantum SRP" is in wide production use today.
- Migrating to PQC/hybrid schemes doesn't retroactively protect data
  that was already encrypted and exfiltrated under classical-only
  schemes before the migration — it only protects *new* traffic and
  keys going forward, which is why "harvest now, decrypt later" risk
  is about acting early, not waiting until a quantum computer actually
  exists.

## Practical takeaway

Treat PQC readiness as "does this system do a **hybrid** exchange
(classical + ML-KEM), not PQC alone" — pure lattice-only deployments
are rare and considered premature given the primitive's relative youth.
For vault-style tools specifically, the real near-term exposure is
narrow: TLS transport (increasingly hybrid-PQC-protected via the
browser/OS layer already, regardless of the vendor) and any
public-key-based sharing/authentication step (RSA key-wrapping, SRP)
that would need a deliberate redesign to become quantum-resistant —
not the AES/ChaCha20-encrypted vault blob itself, which Grover's
algorithm leaves in a comfortable security margin as-is.
