# Vaultwarden

## 1. Overview

Vaultwarden (formerly `bitwarden_rs`, renamed in 2020 after Bitwarden Inc.
requested the project stop using the "Bitwarden" trademark in its name) is
an **unofficial, community-run, lightweight reimplementation of the
Bitwarden server API**, written in Rust. It is licensed under **GPL-3.0**
and is not affiliated with, endorsed by, or supported by Bitwarden Inc.

The project's motivation is squarely operational: the official Bitwarden
server is distributed as a set of .NET-based microservices intended to run
under Docker Compose (or Kubernetes for larger deployments), with a
resource footprint — memory, disk, and number of containers — that is
awkward for a single-user or small-family self-hosted deployment on
constrained hardware such as a Raspberry Pi, a small VPS, or a home NAS.
Vaultwarden collapses the entire server-side surface into a single compiled
binary (or a correspondingly small Docker image), making self-hosting
practical on hardware an order of magnitude less powerful than what the
official server expects.

Crucially, Vaultwarden does not modify or fork the Bitwarden **clients**.
Users install the official Bitwarden browser extensions, desktop apps,
mobile apps, and CLI unmodified, and simply point them at a custom server
URL (a setting exposed in every official client for exactly this purpose:
self-hosted deployments). This is the central design decision that shapes
everything else in this chapter: Vaultwarden's job is to speak the same
protocol as the real Bitwarden server closely enough that the official
clients cannot tell the difference.

## 2. Architecture

**Single binary vs. microservices.** The official Bitwarden self-hosted
stack decomposes into multiple services (API, Identity/auth server,
Notifications hub, Icons/favicon service, Admin portal, a SQL Server
database, etc.), each typically its own container. Vaultwarden folds all
of this into one Rust process. It reimplements, in-process, the pieces a
single-user or small-team deployment actually needs:

- `/api` — the core vault CRUD API (ciphers, folders, collections,
  organizations, attachments, sends).
- `/identity` — the OAuth2-style token endpoint used for login, two-factor
  authentication, and API-key/device authentication flows.
- `/notifications/hub` — a WebSocket endpoint used to push live-sync
  events to connected clients (e.g., "a cipher was updated elsewhere,
  refresh your local copy").
- An **admin panel** (a Vaultwarden-specific addition with no equivalent
  in the official self-hosted product at this scope) for server
  configuration, user management, and diagnostics, gated by a separate
  admin token.
- A bundled copy of the **Bitwarden web vault** front-end (the open-source
  `bitwarden/clients` web app), served directly by the binary, so browsing
  to the server's root URL gives a full web vault UI without a separate
  container.

**Web framework and storage.** Vaultwarden is built on **Rocket**, a Rust
web framework, for HTTP routing, and uses **Diesel** as its ORM/query
builder. It supports **SQLite** (the default, and a key reason it runs
well on minimal hardware — no separate database server process is
required), **MySQL/MariaDB**, and **PostgreSQL** as backends, selected at
build/config time — a deliberate divergence from official Bitwarden,
which targets Microsoft SQL Server.

**API surface reimplementation.** Because the official Bitwarden server is
closed-source (only clients and the SDK are open), Vaultwarden's API
compatibility is derived from the publicly documented Bitwarden API, the
open-source client code (which reveals exactly what requests/responses
clients expect), community reverse engineering, and ongoing reactive
fixes whenever official clients update and break something. There is no
formal, versioned API specification to implement against — compatibility
is empirical and continuously maintained.

## 3. Cryptography & security model

Because Vaultwarden serves unmodified official Bitwarden clients, the
**client-side cryptography is identical to Bitwarden's**: all encryption,
decryption, and key derivation happen in the client. The server model is
zero-knowledge in the same sense as official Bitwarden — the server never
receives the master password (only a derived, and further stretched,
authentication hash), and never sees plaintext vault data. Concretely,
the same primitives apply:

- A master password is run through **PBKDF2-SHA256** (or, in newer client
  versions, optionally **Argon2id**) with a per-account iteration count to
  derive a master key.
- The master key encrypts (wraps) a randomly generated **symmetric vault
  key**, which is what actually encrypts individual vault items using
  **AES-256-CBC with HMAC** (encrypt-then-MAC).
- Only the wrapped/encrypted vault key and the encrypted item blobs are
  transmitted to and stored on the server, alongside a separate
  password-derived **authentication hash** used for login verification.

Vaultwarden's server-side responsibility mirrors Bitwarden's: store these
opaque, already-encrypted blobs and enforce authentication/authorization
around who can fetch or write them, without needing to understand their
contents.

**The risk this reimplementation introduces.** Vaultwarden's
trustworthiness rests on a different foundation than Bitwarden's. It is a
from-scratch reimplementation, by a much smaller volunteer maintainer
group, of a security-critical API surface — authentication, session/token
issuance, two-factor enforcement, organization/collection access control,
and safe storage of encrypted blobs. Any subtle divergence from the
official server's behavior here (e.g. how two-factor auth is enforced, how
KDF iteration counts are validated, how organizational permission checks
are applied) is a Vaultwarden-only bug invisible to Bitwarden Inc.'s own
security audits, which do not cover Vaultwarden's code. Users are
implicitly trusting the project's community review process in lieu of a
commercial security team and paid third-party penetration testing — a
qualitatively different trust posture than using the vendor's own server,
even though Vaultwarden has a long operational track record.

## 4. Protocols

Since the client binaries are the genuine, unmodified Bitwarden apps,
Vaultwarden must speak the **same wire protocol** the real server speaks:
HTTPS/REST with JSON payloads for the `/api` and `/identity` endpoints,
and the same request/response schemas the clients expect for login,
sync, cipher CRUD, organization management, and Sends.

**Push notifications are the one area with real behavioral divergence.**
Official Bitwarden Cloud uses a hosted push-notification relay (backed by
Azure/Firebase-style mobile push infrastructure) to wake mobile clients
and trigger live sync. Vaultwarden, as a self-hosted server with no
access to Bitwarden Inc.'s push infrastructure, instead relies on:

- Its own **self-hosted WebSocket notifications** (`/notifications/hub`),
  which work well for desktop/browser clients that keep a live connection
  open, but
- For mobile clients, which need OS-level push to wake up an app that has
  been backgrounded, Vaultwarden supports registering with **Bitwarden's
  official push relay** as an opt-in feature (using an installation
  id/key issued by Bitwarden for self-hosted servers), so that mobile
  push notifications work despite the vault data itself never touching
  Bitwarden's infrastructure. Without this configured, mobile clients
  typically fall back to polling/manual sync rather than instant push.

Aside from this push-delivery mechanism, the protocol — token formats,
sync endpoints, cipher object shapes, WebSocket message framing — tracks
the official server as closely as the maintainers can determine and
implement.

## 5. Threat model & known limitations

Adopting Vaultwarden means accepting several distinct sources of risk
beyond those inherent to Bitwarden's design itself:

- **Reimplementation risk.** You are trusting a community
  reimplementation of an authentication and access-control surface
  rather than the vendor's reference implementation. Bugs here tend to
  fall in the "server-side logic" category (authorization, session
  handling, rate limiting) rather than cryptography, since the crypto is
  entirely client-side and unchanged.
- **Smaller maintainer and audit surface.** Vaultwarden has far fewer
  maintainers/contributors than Bitwarden Inc. and has not undergone the
  same scale of funded, professional security audits as Bitwarden's
  server and clients. Community code review is real but not equivalent
  to a commercial audit program.
- **Self-hosting operational burden falls entirely on the operator:**
  TLS termination and certificate renewal (Vaultwarden expects a reverse
  proxy such as Caddy or nginx in front of it — it does not terminate
  TLS itself), regular tested backups of the database and attachments,
  timely patching of the host OS and the Vaultwarden binary/image, and
  deciding how much of the service to expose to the public internet.
  Misconfiguration here is a self-inflicted vulnerability a managed
  cloud service would otherwise absorb.
- **Admin panel exposure.** The built-in admin panel is a powerful,
  Vaultwarden-specific attack surface with no equivalent in official
  Bitwarden. It is protected by a single shared admin token (not
  per-user accounts with 2FA), so if left enabled and exposed to the
  internet without extra protection (IP allow-listing, a reverse-proxy
  auth layer, or disabling it post-setup), it is a high-value target
  whose compromise can expose or manipulate every user record on the
  instance.
- **Upstream protocol drift.** Because Vaultwarden tracks an
  externally-controlled, closed-source, undocumented API surface, it is
  structurally dependent on staying in sync with whatever Bitwarden Inc.
  changes in its client apps. A client update that alters request
  formats or authentication flows can break compatibility until
  maintainers reverse-engineer and ship a fix — creating windows where
  certain client versions misbehave against Vaultwarden, or operators
  must pin versions.
- **Feature and scaling gaps.** Some official Bitwarden enterprise
  features (certain SSO integrations, advanced policies, large-org
  scaling characteristics) are partially supported or behave differently
  under Vaultwarden, since small self-hosted deployments — not
  enterprise scale — were the primary design target.

## 6. Sources / references

This chapter is based on Vaultwarden's publicly available documentation
(the project wiki and README in its GitHub repository,
`dani-garcia/vaultwarden`) and its open-source code, which is the
authoritative record of its implemented behavior since no separate formal
specification exists. Details on the underlying Bitwarden cryptographic
design (PBKDF2/Argon2id KDF, AES-256-CBC+HMAC item encryption, the
wrapped-vault-key model) reflect Bitwarden's own published security
whitepaper and client source, which Vaultwarden clients rely on unchanged.
No specific CVE identifiers or version numbers are cited here; readers
evaluating a deployment should consult the project's current release
notes and security advisories directly.
