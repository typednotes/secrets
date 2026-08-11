# Proton Pass

## 1. Overview

Proton Pass is the password manager from Proton AG, the Swiss company behind
Proton Mail, Proton Drive, Proton Calendar, and Proton VPN. It launched well
after those products (Mail: 2014, VPN: 2017, Calendar: 2020, Drive: 2022),
and was designed from the outset to plug into Proton's existing account and
encryption infrastructure rather than build a standalone stack.

Proton is headquartered in Geneva, Switzerland, and hosts data primarily in
Switzerland and the EU, marketing Swiss privacy law as a differentiator from
US-based competitors such as 1Password (Canada) or Bitwarden (US).

Licensing follows the pattern used across Proton's apps: mobile, desktop,
web, and browser-extension clients are open source under GPL-family licenses
(published on Proton's GitHub organization), while backend/server components
are closed source. This "open client, closed server" split means
auditability applies to on-device cryptographic operations, not to server
behavior — an asymmetry discussed further in Section 5.

## 2. Architecture

Proton Pass is a cloud-synced vault built on top of Proton's pre-existing
account system, not a standalone product with its own identity stack.

- **Shared Proton account.** A Proton Pass user is a Proton account — the
  same one used for Mail, Drive, and Calendar. Login reuses the same
  authentication flow and account keys as the rest of the suite; there is no
  Pass-specific master identity.
- **Vaults.** Items (logins, notes, cards, identities) are organized into
  vaults, each stored server-side as encrypted blobs. Users can maintain
  multiple vaults and share individual vaults with other Proton Pass users.
- **Clients.** Official apps exist for web, desktop, Android, iOS, and as
  browser extensions, all published as open-source repositories sharing a
  common Rust-based cryptographic/business-logic core with platform-specific
  UI layers on top.
- **Aliasing via SimpleLogin.** Pass integrates SimpleLogin, the
  email-aliasing service Proton acquired in 2022, to provide "hide my email"
  functionality: creating an alias for a login provisions a SimpleLogin
  forwarding address that relays mail to the user's real inbox while
  exposing only a disposable address to the site being registered. This
  composes two previously separate Proton products rather than building
  alias-masking natively into the vault protocol.
- **Sync.** Vault data is stored encrypted server-side and synced across
  devices through the same API infrastructure as other Proton products,
  with all encryption/decryption performed client-side.

## 3. Cryptography & security model

Proton Pass's cryptography is not a purpose-built design; it reuses the
OpenPGP-based end-to-end encryption architecture built for Proton Mail and
later extended to Drive and Calendar. This produces a key hierarchy that
differs sharply from most other password managers.

- **Account keys as root of trust.** Every Proton account has one or more
  OpenPGP key pairs (originally for mail encryption). Pass vaults are
  encrypted with symmetric content keys, but those keys are wrapped to the
  user's OpenPGP public key; only the corresponding private key — itself
  protected by the account password — can unwrap them. Pass therefore layers
  a **PGP-keypair-per-user** model on top of vault content, rather than
  deriving one symmetric master key per vault directly via a password-based
  KDF.
- **Contrast with Bitwarden.** Bitwarden derives a symmetric master key from
  the master password via a KDF (PBKDF2 or Argon2), which directly (or via a
  stretched key) encrypts a symmetric vault key — no public-key cryptography
  in the core unlock path. Proton instead puts an asymmetric keypair at the
  center: the password-derived secret protects the account private key,
  which in turn decrypts symmetric content keys for individual vaults/items.
  This enables Proton's sharing model to mirror mail/file sharing elsewhere
  in the ecosystem, at the cost of a more complex key hierarchy than
  Bitwarden's flatter symmetric design.
- **SRP-based authentication.** The account password itself is never sent to
  Proton's servers, even hashed, during login. Proton uses the Secure Remote
  Password (SRP) protocol so client and server can mutually verify password
  knowledge without transmitting it. A separately derived value unlocks the
  user's private key material once authentication succeeds.
- **Vault sharing.** Sharing a vault encrypts its symmetric content key to
  the recipient's OpenPGP public key (fetched from Proton's key directory),
  rather than transmitting a shared secret out of band — a direct reuse of
  Proton Mail's address-to-address encryption mechanics for vault objects.
- **Zero-knowledge design.** Proton's servers store only encrypted vault
  contents and encrypted key material, and are not intended to be able to
  decrypt vault contents even under compulsion, since decryption keys are
  reconstructed only client-side from the user's password.

## 4. Protocols

- **HTTPS/REST/JSON.** Clients talk to Proton's backend over a conventional
  HTTPS REST API exchanging JSON, the same API family used across Proton
  products. Vault/item payloads are opaque ciphertext from the server's
  perspective.
- **SRP (Secure Remote Password).** Used for the login handshake, letting
  the server verify password knowledge without ever receiving the password
  or a directly-derived hash — the same account-wide SRP implementation used
  by other Proton apps.
- **OpenPGP (RFC 4880).** Key wrapping, sharing-related content encryption,
  and key-management plumbing are implemented with OpenPGP primitives
  (public-key encryption, symmetric session keys, signatures for integrity),
  consistent with Proton Mail's long-standing OpenPGP.js-derived libraries
  and, on native/mobile clients, Proton's Go/Rust cryptography libraries
  (GopenPGP and related bindings).

## 5. Threat model & known limitations

- **Closed server despite open clients.** Open client source allows
  independent review of the cryptographic operations the apps claim to
  perform, but the server is closed. Users cannot verify from source what
  the server does with ciphertext, metadata, or key material — only what the
  published client source claims to do. The end-to-end guarantee is
  therefore only as strong as (a) the correctness of the open client code
  and (b) assurance that the binary a user actually runs was built from that
  published source rather than a tampered variant (the "reproducible
  builds" problem). Proton has taken partial steps toward reproducible
  builds for some clients, but this remains an ongoing mitigation, not a
  guarantee, and says nothing about server behavior.
- **Centralized account as a single point of trust.** Because Pass reuses
  the same account and key infrastructure as Mail, Drive, and Calendar, a
  compromise of a user's Proton account (password compromise, or a flaw in
  the shared account/key system) has blast radius across every enabled
  Proton product, not just the password vault — unlike a purpose-built
  manager whose account system is scoped to credentials alone.
- **Metadata exposure.** As with most cloud-synced vaults, item contents are
  encrypted, but some metadata (account existence, vault counts, sync
  timestamps, login IPs, use of SimpleLogin aliasing) is necessarily visible
  to server infrastructure even under a zero-knowledge design for content.
- **Jurisdiction.** Switzerland offers strong statutory privacy protections
  and sits outside both EU and US legal frameworks, though Swiss-EU
  data-protection arrangements and mutual legal assistance treaties still
  apply. Proton has publicly disclosed complying with legally binding Swiss
  orders in the past (e.g., IP-logging in criminal cases), showing that
  Swiss jurisdiction reduces but does not eliminate exposure to lawful-access
  requests. It does not undermine the zero-knowledge design's core claim,
  though: that Proton cannot hand over decrypted vault contents it never
  possesses, regardless of legal pressure.

## 6. Sources / references

This chapter draws on Proton's publicly published account-security and
encryption architecture documentation (security pages and cryptographic
architecture write-ups for Proton Mail/Drive, which Pass reuses), on
Proton Pass's open-source client repositories (Android, iOS, browser
extension, shared Rust core, published under Proton's GitHub organization),
and on Proton's general public statements about its account model,
SRP-based authentication, and zero-access architecture. No specific version
numbers, release dates, or CVE identifiers are asserted; readers evaluating
Proton Pass for a specific deployment should consult Proton's current
published security documentation and client source directly, as
implementation details evolve over time.
