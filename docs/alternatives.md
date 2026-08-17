# Alternatives to 1Password

This page surveys password managers / secret vaults that compete with or
substitute for 1Password. Each entry links to a dedicated chapter with a
detailed breakdown of its architecture, security model, and protocols.

Open-source projects (fully open client and/or server source) are
<u>underlined</u>.

- [Bitwarden](tools/bitwarden.md) — <u>open-source</u> (AGPL-3.0 server,
  GPL-3.0 clients), cloud or self-hosted
- [KeePass / KeePassXC](tools/keepassxc.md) — <u>open-source</u> (GPL-2/3),
  local encrypted file, no built-in sync service
- [pass (the standard Unix password manager)](tools/pass.md) —
  <u>open-source</u> (GPL-2.0), GPG + git based
- [Vaultwarden](tools/vaultwarden.md) — <u>open-source</u> (GPL-3.0),
  unofficial Bitwarden-compatible server implementation in Rust
- [HashiCorp Vault](tools/hashicorp-vault.md) — <u>open-source core</u>
  (MPL-2.0, BUSL for newer releases), infrastructure/secrets-management
  focus rather than end-user vault
- [OpenBao](tools/openbao.md) — <u>open-source</u> (MPL-2.0), Linux
  Foundation-governed fork of HashiCorp Vault created after Vault's
  BUSL relicensing, infrastructure/secrets-management focus
- [Dashlane](tools/dashlane.md) — closed-source, cloud SaaS
- [LastPass](tools/lastpass.md) — closed-source, cloud SaaS
- [NordPass](tools/nordpass.md) — closed-source, cloud SaaS
- [Proton Pass](tools/proton-pass.md) — clients are open-source
  (<u>partially open-source</u>), server-side is closed; part of the
  Proton ecosystem
- [Apple Keychain / iCloud Keychain](tools/apple-keychain.md) —
  closed-source, OS-integrated
- [Google Password Manager](tools/google-password-manager.md) —
  closed-source, browser/OS-integrated

## Quick comparison

| Tool | License model | Sync backend | Open-source | Primary protocol(s) |
|---|---|---|---|---|
| Bitwarden | AGPL-3.0 / GPL-3.0 | Bitwarden Cloud or self-hosted | <u>Yes</u> | HTTPS/REST + JSON, WebSocket/SignalR for push |
| KeePassXC | GPL-2/3 | None built-in (file sync via user's own method) | <u>Yes</u> | Local file format (KDBX), KeePassXC-Browser NaCl protocol |
| pass | GPL-2.0 | git (any transport) | <u>Yes</u> | GPG (OpenPGP), git protocol |
| Vaultwarden | GPL-3.0 | Self-hosted, Bitwarden clients | <u>Yes</u> | Same wire protocol as Bitwarden |
| HashiCorp Vault | MPL-2.0 / BUSL | Self-hosted / HCP | <u>Core: yes</u> | HTTPS/REST, gRPC (Enterprise replication) |
| OpenBao | MPL-2.0 | Self-hosted | <u>Yes</u> | HTTPS/REST (Vault-compatible), gRPC (replication) |
| Dashlane | Proprietary | Dashlane Cloud | No | HTTPS/REST |
| LastPass | Proprietary | LastPass Cloud | No | HTTPS/REST |
| NordPass | Proprietary | NordPass Cloud | No | HTTPS/REST |
| Proton Pass | Proprietary server, open clients | Proton Cloud | Partial | HTTPS/REST, SRP for auth |
| Apple Keychain | Proprietary | iCloud | No | Apple's proprietary sync protocol over iCloud |
| Google Password Manager | Proprietary | Google account sync | No | Google's proprietary sync protocol |

See individual chapters under [`docs/tools/`](tools/) for details.

## Post-quantum readiness

None of the tools above use post-quantum cryptography (PQC) for the
data that actually protects the vault contents at rest. All of them
still rely exclusively on classical primitives — AES-256/ChaCha20 for
symmetric vault encryption, PBKDF2/Argon2/scrypt for key derivation,
and RSA/ECC (including SRP, which is Diffie-Hellman-based) for any
asymmetric operations such as key sharing or authentication. None of
these are believed to be broken by classical computers, but the
asymmetric primitives (RSA, ECC, SRP/DH) would fall to a
sufficiently large quantum computer running Shor's algorithm — a
"harvest now, decrypt later" concern mainly for anything encrypted
*to* another party's public key (sharing/escrow), not for the
symmetric-key vault blob itself, which is comparatively quantum-safe
already (AES-256 loses at most half its effective strength under
Grover's algorithm, leaving it in a still-safe ~128-bit regime).

Nuance by tool:

- **Bitwarden, Vaultwarden** — purely classical (PBKDF2/Argon2id + AES-256-CBC/HMAC; RSA-2048 only for organization key-sharing). No PQC roadmap has shipped in the client protocol as of this writing.
- **KeePassXC, pass** — purely classical (AES/ChaCha20/Twofish; OpenPGP RSA/ECC for `pass`). OpenPGP has draft support for PQC algorithms (e.g. ML-KEM) in newer specs, but mainstream GnuPG/KeePassXC deployments do not use it by default.
- **HashiCorp Vault, OpenBao** — purely classical (AES-256-GCM barrier, Shamir secret sharing which is information-theoretic and *not* threatened by quantum computers at all). No PQC key-wrapping/transit algorithms are in general availability in either project; as a fork sharing Vault's pre-fork cryptographic design, OpenBao's PQC status tracks Vault's exactly.
- **Dashlane, LastPass, NordPass** — purely classical (AES-256/XChaCha20-Poly1305 with vendor-specific KDFs). No vendor has publicly announced production PQC for vault encryption.
- **Proton Pass** — classical today (OpenPGP RSA/ECC + AES). Proton is the one vendor in this list that has publicly announced active post-quantum work (a PQC key-exchange rollout for parts of Proton Mail/VPN), so it is the most likely of these to add PQC to Pass first — but as of this writing that has not been confirmed shipped specifically for Pass's vault/sharing cryptography, so treat it as "watch this space," not "yes."
- **Apple Keychain / iCloud Keychain** — Apple has shipped PQC (a hybrid Kyber/ML-KEM construction) in **iMessage** (PQ3) and is rolling similar hybrid PQC into **iCloud's end-to-end encryption** transport for some data categories, but this has not been confirmed to extend to iCloud Keychain's own sync protocol specifically as of this writing.
- **Google Password Manager** — Google has been an early mover on PQC in **TLS** (hybrid X25519+Kyber for the transport layer) and has piloted PQC in some Google security keys/protocols, but that is transport-layer, not the password vault's own encryption scheme, and no PQC vault encryption has been announced for Google Password Manager specifically.

**Bottom line:** as of this writing, *no* tool surveyed here offers
end-to-end post-quantum protection of vault contents. The realistic
near-term exposure is limited to asymmetric operations (key sharing,
SRP/DH-based auth handshakes, TLS transport) rather than the
AES-encrypted vault blob itself. If PQC readiness is a hard
requirement, the most future-facing signal is transport-layer PQC in
TLS (increasingly common across all cloud-hosted options via
browsers/OS support) plus watching Proton's PQC rollout, rather than
any vendor's current vault-encryption algorithm choice.
