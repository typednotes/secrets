# Bitwarden as a 1Password Alternative

## 1. Overview

Bitwarden is an open-source password manager and secrets platform. Unlike 1Password, whose server-side infrastructure and native clients are closed source, Bitwarden publishes essentially its entire stack — server, mobile/desktop/browser-extension clients, CLI, and the underlying cryptographic library — under open-source licenses (mostly GPLv3 for the server, a mix of GPLv3/AGPLv3/MIT across client repos, with some newer enterprise-only modules under a source-available Bitwarden License that restricts commercial redistribution).

Bitwarden Inc. develops the project, sells hosted subscriptions (bitwarden.com, "Bitwarden Cloud"), and also distributes a self-hostable server. Three deployment models exist in practice:

- **Bitwarden Cloud** — multi-tenant SaaS run by Bitwarden Inc., with US and EU data-residency options.
- **Self-hosted (official images)** — Docker Compose-based deployment of the same server codebase, run by the user/organization on their own infrastructure.
- **Vaultwarden** — a third-party, community-maintained reimplementation of the Bitwarden server API in Rust, API-compatible with official Bitwarden clients but not developed or endorsed by Bitwarden Inc. (mentioned here because it is commonly conflated with "self-hosted Bitwarden"; it has a different codebase, storage engine, and security review history).

For a Rust-based secrets vault project, Bitwarden is a relevant reference point both architecturally (self-hostable, transparent crypto) and as a migration target/source (via its documented, versioned export/import JSON format and CLI).

## 2. Architecture

### Client applications
Browser extensions (Chromium/Firefox/Safari), desktop apps (Electron-based), mobile apps (iOS/Android), a web vault (SPA), and a CLI (`bw`), plus a directory-sync connector and a separate secrets-manager CLI/SDK for machine-to-machine secrets. All clients embed or link a shared cryptography core; newer clients increasingly consume a common Rust SDK (`sdk-internal`) compiled to native libraries or WASM, replacing per-platform reimplementations of the crypto and API logic.

### Server components
The self-hosted server ("Bitwarden Unified Server" in newer releases; historically a set of separate microservices) is composed of:

- **API** — the core REST service: accounts, ciphers (vault items), collections, organizations, folders, sends, events.
- **Identity** — a dedicated IdentityServer4/Duende-based OAuth2 token service handling login, refresh tokens, and two-factor challenges, kept separate from API for isolation of credential handling.
- **Notifications** — push-notification hub built on SignalR (ASP.NET's WebSocket/long-polling abstraction), telling other logged-in clients "the vault changed, re-sync."
- **Icons** — fetches and caches website favicons for autofill UI, deliberately isolated so the one component making outbound requests to arbitrary domains cannot touch vault data.
- **Admin** — internal portal for server administration (self-hosted license management, support tools).
- **Events/Scim** — audit logging and enterprise SCIM provisioning, in cloud and enterprise self-host tiers.
- **Storage backend** — a relational database (Microsoft SQL Server historically the reference target; MySQL, PostgreSQL, and SQLite supported for self-hosting via Entity Framework Core providers) plus a blob store (Azure Blob Storage/S3-compatible or local filesystem) for attachments and Sends.

Self-hosted deployments run the above (or a merged "unified server" image) via Docker Compose behind a reverse proxy. bitwarden.com runs the same logical components at cloud scale, with additional internal services for billing, multi-region data residency, and enterprise SSO/SCIM not part of the open-source distribution. The API surface presented to clients is otherwise the same, which is what makes self-hosting a genuine alternative rather than a crippled one.

## 3. Cryptography & security model

Bitwarden follows a **zero-knowledge** (more precisely, "zero-knowledge encryption") design: the server stores and transports only encrypted blobs and values that are cryptographically derived such that the plaintext master password never leaves the client and cannot be reconstructed by the server.

### Key derivation chain

```
Master Password + Email (as salt)
        │  KDF: PBKDF2-HMAC-SHA256 (default ≥600,000 iterations)
        │        or Argon2id (memory/parallelism/iterations configurable)
        ▼
   Master Key (256-bit)
        │  HKDF-Expand (client-side "master password hash" derivation)
        ├────────────────────────────────────────────┐
        ▼                                             ▼
Master Password Hash                         Stretched Master Key
(PBKDF2/HKDF over Master Key + password,     (HKDF-expand of Master Key into
 sent to server for authentication only)      a 512-bit encryption+MAC key pair)
                                                        │
                                                        ▼
                                     Used to decrypt the "Protected Symmetric Key"
                                     record (a.k.a. User Key), which is itself a
                                     randomly generated 512-bit key (256-bit AES key
                                     + 256-bit HMAC key) that is stored, ENCRYPTED,
                                     on the server.
                                                        │
                                                        ▼
                              User Key decrypts individual item keys / the
                              organization keys, which in turn decrypt each
                              vault item's fields (name, username, password,
                              notes, custom fields, attachments).
```

Key points:

- **The master password is never transmitted.** Only the "master password hash" — derived one more round from the master key, further salted — is sent to the server, for authentication only; it cannot be used to derive decryption keys, though it remains subject to offline brute-force if KDF settings are weak (hence iteration/Argon2id parameters being user-configurable).
- **Two derived secrets, two purposes**: the *master key* (stays local, encryption-adjacent) and the *master password hash* (server-facing, auth-only) are distinct outputs of the same KDF chain, so a leak of one does not compromise the other.
- **Envelope encryption**: items are not encrypted directly with a password-derived key. Each account has a random **User Key** that actually protects data; it is wrapped by the stretched master key and stored server-side only in encrypted form, so changing the master password just re-wraps the User Key instead of re-encrypting the whole vault.
- **Per-item encryption**: individual ciphers (and, for organizations, each collection) use their own symmetric keys, wrapped by the User Key or organization key, enabling fine-grained rotation and selective sharing.
- **Symmetric primitives**: AES-256-CBC with HMAC-SHA256 (encrypt-then-MAC) is the historical default; the ciphertext format is versioned to allow algorithm evolution (e.g., movement toward XChaCha20-Poly1305 in newer SDK work) without breaking old data.
- **Organizations / shared vaults**: an organization has its own random key, individually wrapped for each member with that member's RSA public key (every account holds an RSA keypair, itself protected by the User Key) — so the server distributes per-member encrypted copies without ever seeing the plaintext key or needing an out-of-band exchange.
- **Emergency access**: a trusted contact gets a time-delayed, revocable grant, implemented by re-encrypting the grantor's User Key for the contact's public key once the wait elapses or is approved — no weakening of the base scheme.
- **Biometric unlock** (Windows Hello, Touch/Face ID, OS keychains) caches the decrypted vault key in an OS-protected secure enclave local to the device — a convenience layer on top of, not a replacement for, the master-password-derived scheme.
- **Server-side blindness**: the database holds only ciphertext, KDF parameters, wrapped keys, and the authentication hash — an attacker with database access cannot decrypt vault contents without the master password (subject to KDF strength).

## 4. Protocols

- **REST/JSON API**: the API service exposes resource-oriented endpoints (`/api/accounts`, `/api/ciphers`, `/api/folders`, `/api/organizations`, `/api/sync`, `/api/collections`, etc.), consumed by all first-party clients and the public `bw` CLI. Encrypted fields are opaque versioned strings inside otherwise plaintext-structured JSON — cipher names/notes are ciphertext, but the JSON envelope, IDs, timestamps, and metadata are visible to the server.
- **Authentication**: OAuth2-flavored token issuance from the separate Identity service, historically the Resource Owner Password Credentials grant (client posts the derived master-password hash, not the password, plus a device identifier) to obtain a bearer access token and refresh token; newer flows add SSO (OIDC) delegation to third-party IdPs at the organization level.
- **Two-factor authentication**: TOTP (RFC 6238), WebAuthn/FIDO2 security keys, email codes, Duo, and YubiKey OTP are handled as an additional challenge step during the Identity token exchange (a two-factor-required error response, followed by a resubmitted token request including the second-factor proof).
- **Sync protocol**: clients call `/api/sync` to pull a full snapshot of ciphers/folders/organizations/settings; incremental updates are message-driven — clients receive a lightweight push notification and then re-fetch. There is no CRDT/OT merge; conflict resolution is largely last-write-wins at the cipher level, guarded by revision-date checks.
- **Push notifications**: the Notifications service uses SignalR, negotiating WebSocket (falling back to Server-Sent Events or long polling) to tell a user's other active sessions that a sync is needed, that they were logged out, or that a Send/cipher changed — the push message itself carries no vault data, only an event type and target ID.
- **Browser extension native messaging**: the desktop app can act as a biometric-unlock/autofill helper for the browser extension via the OS-level Native Messaging protocol (a length-prefixed JSON-over-stdio channel brokered by the browser), so the extension can request an OS-biometric unlock without touching biometric APIs itself.

## 5. Threat model & known limitations

- **What a compromised server can do**: read/tamper with ciphertext and metadata (cipher names may be encrypted, but item counts, folder structure, timestamps, IP/login metadata, and organizational relationships are visible); serve a malicious client update or malicious web-vault JavaScript (see below); deny service; silently downgrade a user's KDF settings if not client-pinned, weakening offline attack resistance; observe traffic timing/size patterns.
- **What it cannot do**, assuming correct client behavior and a reasonably strong master password: derive the master key or User Key, decrypt vault items, or forge master-password-hash verification, since the KDF and hash derivation happen client-side and only irreversible outputs are transmitted.
- **Web vault / client-side JavaScript risk**: the most frequently cited structural weakness of any browser-delivered zero-knowledge vault, Bitwarden included — a user authenticating through the web vault is trusting whatever JavaScript the server (or a CDN/MITM position) served *that session* to correctly implement the crypto and not exfiltrate the master key once it's derived in memory. This does not apply to native desktop/mobile/CLI clients, which run fixed, independently distributed and auditable code. Self-hosting does not eliminate this risk unless the operator also audits and controls the exact JS served.
- **Self-hosting attack surface**: operators take on responsibility for TLS termination, database hardening, backup encryption, and timely image updates; a misconfigured instance (missing reverse-proxy TLS, exposed admin portal, stale image with a fixed vulnerability) is a materially larger risk than the maintained cloud service. The Identity/API separation and Icons-service isolation exist specifically to limit blast radius of a single compromised component.
- **KDF configuration matters directly**: the server cannot enforce master-password strength or KDF work factor beyond what's stored in (attacker-visible) account settings, so accounts with low iteration counts or weak passwords are meaningfully more exposed to offline cracking after a database dump, even though the scheme is sound at high work factors.
- **Known incidents**: Bitwarden periodically commissions and publishes third-party security audits and advisories; no specific CVE numbers or incident details are cited here since they weren't independently verified for this document — consult Bitwarden's published advisories/audit reports for specifics on any given release. Vaultwarden, being a separate unofficial reimplementation, has its own independent history and should not be assumed to inherit Bitwarden Inc.'s audit coverage.

## 6. Sources / references

This chapter is based on Bitwarden's publicly published Security Whitepaper, its open-source server, client, and SDK repositories (bitwarden/server, bitwarden/clients, bitwarden/sdk-internal), and public help-center documentation describing the API, sync, and two-factor flows. No specific version numbers, CVE identifiers, or audit citations are asserted; consult Bitwarden's current whitepaper and repositories for authoritative details (e.g., current default KDF iteration counts) before relying on any specific parameter.
