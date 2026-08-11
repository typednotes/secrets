# Dashlane

> Closed-source, cloud-hosted password manager. Everything below about
> internal cryptography, key-derivation parameters, and protocol internals
> is **as publicly documented by Dashlane** (help-center articles and its
> published security whitepaper) — none of it is independently verifiable
> from source, since Dashlane's server and client code are not open.

## 1. Overview

Dashlane is a proprietary Software-as-a-Service (SaaS) password manager
from Dashlane Inc., sold under a commercial subscription model (Free,
Premium/Advanced, Business, and enterprise tiers). The vault is
cloud-hosted by design; a legacy fully-local mode existed in older
versions, but the current product is built around cloud sync as the
default.

Supported platforms, per the vendor: desktop apps for Windows and macOS,
mobile apps for iOS and Android, browser extensions for Chrome, Firefox,
Edge, Safari and other Chromium-based browsers, a web vault, and a
separate CLI/secrets-injection tool aimed at developers. No component of
the client, extension, or server stack is published as open source, so all
security claims rest on Dashlane's own representations rather than
inspectable code.

## 2. Architecture

**Cloud-hosted vault.** Encrypted credentials, notes, payment data, and
sharing metadata are stored on Dashlane's servers, hosted on major cloud
providers with US and EU data centers; EU residency is offered as a
compliance option for business customers.

**Clients and extensions.** Native apps and browser extensions decrypt
data locally; the encryption key is derived on-device from the master
password and, per Dashlane's documentation, is never sent to or stored by
the servers. Extensions communicate either with a companion desktop app or
directly with the cloud API, depending on platform.

**Sync.** Each client keeps a local encrypted cache. Changes are encrypted
client-side, pushed to Dashlane's servers, and redistributed as encrypted
blobs to the user's other authorized devices — the server is described as
an encrypted-blob relay/store, not a party able to read vault contents.
The sync protocol itself (conflict resolution, incremental updates) is
proprietary and not publicly specified in detail.

**Admin/business console.** Business and Team plans get a web admin
console for provisioning (including SCIM and directory sync with Azure
AD/Entra ID, Okta), policy enforcement (master password strength, 2FA
requirement, sharing restrictions), metadata-level activity logs, and
management of shared groups/vaults. Because the vault is end-to-end
encrypted, Dashlane states admins cannot see plaintext credentials through
the console except via deliberately-enabled recovery features for managed
accounts.

## 3. Cryptography & security model

Dashlane advertises a **zero-knowledge architecture**: the claim is that
its servers never receive the master password or plaintext encryption key
and cannot decrypt vault contents. As documented in its security
whitepaper and support articles:

- The **master password** is the root secret and is never transmitted to
  Dashlane's servers.
- A local key-derivation step turns the master password into a
  cryptographic key. Dashlane's published material describes a move to
  **Argon2d** as the KDF for the master encryption key, replacing an older
  PBKDF2-based scheme on legacy accounts. Exact parameters (memory cost,
  iterations, parallelism) are only described at a high level and are not
  independently auditable without source access.
- The derived key encrypts/decrypts vault content with **AES-256**
  (documentation cites CBC mode historically, with per-item random IV and
  HMAC for integrity).
- **Device enrollment/authorization.** New devices historically could not
  obtain an unencrypted vault copy without an out-of-band authorization
  step — typically an emailed confirmation link or code, sometimes paired
  with a code shown on an already-trusted device. This mitigates an
  attacker who has only the master password but not the user's email or an
  existing trusted device.
- **Biometric unlock** (Touch ID, Face ID, Windows Hello, Android
  biometrics) is a convenience layer built on OS secure-enclave/keystore
  APIs; the master password (or a locally wrapped equivalent) remains what
  is actually protected behind the biometric gate.
- **Confidential SSO**, offered for enterprise customers, is designed so
  that SSO gates access to the Dashlane application via the company's
  identity provider (SAML/OIDC) while vault key material is still derived
  from a user secret unknown to the IdP and to Dashlane — the stated goal
  is that compromising SSO alone should not suffice to decrypt vaults. How
  this reconciles with a strict zero-knowledge design is not disclosed at
  implementation level.
- **Secure password sharing** wraps a per-item symmetric key with each
  recipient's public key (asymmetric key-wrapping, described as RSA-based
  in the whitepaper), letting shared items be re-encrypted per authorized
  recipient without the server learning plaintext.

## 4. Protocols

- Client-server communication is documented as **HTTPS** with a
  **REST-style JSON API** for sync, authentication, and admin operations;
  no public specification exists for the vault sync protocol itself.
- **Device authorization flow**: a new device login triggers an
  out-of-band step — commonly a 6-digit **email code** or confirmation
  click, sometimes combined with entering a code shown on an already
  trusted device — layered on top of master-password authentication.
- **2FA**: TOTP (authenticator apps) and hardware-backed **U2F/WebAuthn**
  (e.g., YubiKey), available on Premium and higher/Business tiers.
- Enterprise SSO uses standard federation protocols (**SAML 2.0**,
  **OIDC**) at the identity-provider boundary, combined with Dashlane's
  proprietary confidential-SSO key-handling layer.

## 5. Threat model & known limitations

- **Closed-source verifiability gap.** All claims above originate from
  Dashlane's own publications. With neither server nor client/extension
  source public, independent researchers cannot confirm the shipped
  implementation matches the documented design, that KDF parameters are as
  strong as claimed, or that no server code path could access plaintext.
  This is a structural limitation of any closed-source vault, not a
  specific allegation.
- **Third-party audits.** Dashlane states it commissions third-party
  security assessments and publishes whitepapers summarizing its
  architecture. As with most closed-source vendors, scope and full
  findings of such audits are typically not released; public artifacts are
  vendor-selected summaries rather than reproducible, independently
  published reports.
- **Cloud availability dependency.** Since the vault is cloud-hosted by
  design (unlike a purely local KeePass file), new-device access and
  sharing require reaching Dashlane's infrastructure, though clients cache
  data locally for offline use.
- **Browser-extension attack surface.** Like all browser-integrated
  password managers, the extension operates in a high-risk environment
  (DOM injection, autofill phishing, malicious scripts); Dashlane's
  specific mitigations are not independently auditable.
- **Vendor lock-in and export.** Data lives in Dashlane's proprietary
  cloud format. CSV/JSON export is provided for migration, but exported
  CSV is unencrypted at rest on the destination — a general risk when
  migrating off any vault of this kind. There is no self-hosted deployment
  option, unlike Vaultwarden or HashiCorp Vault; organizations with strict
  data-sovereignty requirements should evaluate Dashlane's EU-hosting
  option and contract terms instead of assuming self-hosting is possible.

## 6. Sources / references

This chapter is based on Dashlane's publicly available security
documentation, including its published security whitepaper and
help-center articles on master-password handling, key derivation (the
Argon2d transition), AES-256 encryption, device authorization/2FA, and
sharing design, plus general vendor material describing Confidential SSO
and admin console capabilities.

No claim here should be treated as independently verified against source
code or a reproducible, public third-party audit report — Dashlane's
client and server implementations are closed-source, and the accuracy of
the above rests entirely on the vendor's own disclosures.
