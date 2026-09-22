# secrets

[![CI](https://github.com/typednotes/secrets/actions/workflows/ci.yml/badge.svg)](https://github.com/typednotes/secrets/actions/workflows/ci.yml)
[![Docker image](https://img.shields.io/badge/ghcr.io-secrets--server-blue?logo=docker)](https://github.com/typednotes/secrets/pkgs/container/secrets-server)
[![crates.io](https://img.shields.io/crates/v/secrets-core.svg)](https://crates.io/crates/secrets-core)
[![docs.rs](https://img.shields.io/docsrs/secrets-core)](https://docs.rs/secrets-core)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

A small, modular secrets-management server in Rust — a much simpler
reimplementation of the core ideas in [HashiCorp Vault](https://www.vaultproject.io/)
and [OpenBao](https://github.com/openbao/openbao): encrypted secret storage
gated by auth and policy, plus on-demand dynamic PostgreSQL credentials.

## Table of contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick start](#quick-start)
- [HTTP API](#http-api)
- [Testing](#testing)
- [Project status and scope](#project-status-and-scope)
- [Further reading](#further-reading)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Storage**: PostgreSQL only, behind a `StorageBackend` trait so another
  backend could be added later without touching anything above it.
- **Encryption**: a master key from an env var (or a file path held in it) —
  no Shamir seal/unseal. A `Barrier` decorator transparently
  AES-256-GCM-encrypts every value before it reaches storage; paths stay
  plaintext so leases/tokens can be expiry-scanned without decrypting.
  **Rotatable**: each value records which key sealed it, so a new key can be
  introduced alongside the old one and the store rewrapped in place — see
  [Rotating the master key](#rotating-the-master-key).
- **Secrets engines**:
  - `secret/` — a versioned, soft-deleting static KV store (kv-v2 style).
  - `database/` — dynamic PostgreSQL credentials: configure a target
    database and a role's `CREATE`/`DROP` SQL templates, then mint a
    short-lived, uniquely-named credential on demand.
  - **third-party delegation** — `github/`, `gitlab/`, `aws/`, `gcp/`,
    `gworkspace/`, `dropbox/`, `m365/`: mint scoped, short-lived credentials
    for a consuming microservice so it never holds a long-lived provider
    secret. See [`docs/delegation/`](docs/delegation/README.md).
  - `federation/` — the shape where nothing is stored at all: publishes the
    OIDC token-exchange instructions a consumer needs to authenticate to AWS,
    Google Cloud or Entra ID with its own workload identity.
- **Self-documenting**: every engine answers `GET /v1/{mount}/help` with its
  mechanism, TTL envelope, scoping, the root credential it needs and its
  caveats — and every minted credential carries a `_doc` block saying what it
  was scoped to and, crucially, whether revoking its lease actually destroys
  it. Three of the seven providers cannot revoke an issued token, and the API
  says so rather than implying a guarantee it cannot keep.
- **Auth methods**:
  - `userpass` — Argon2id-hashed username/password.
  - `oidc` — both interactive human login (authorization-code + PKCE) and
    machine-to-machine login (hand us a JWT, we verify it against the IdP's
    JWKS). Both share one discovery/JWKS cache and one claims-to-policies
    mapping.
- **Tokens**: opaque bearer strings (`s.<hex>`), looked up by
  `sha256(token)` — never the raw token — so every request round-trips to
  storage and can be revoked immediately, unlike a self-contained JWT.
- **Policies**: path-prefix + capability (`read/create/update/delete/list/sudo`)
  documents, longest-prefix-match, deny-by-default.
- **Leases**: every dynamic credential is tracked as a lease with an
  expiry; a background reaper revokes expired ones, and revoking a token
  cascades to revoke every lease it owns.
- **Horizontally scalable.** Requests hold no in-process state — tokens are
  looked up by `sha256` in storage on every call, and policies, leases and
  OIDC PKCE state all live there too — so replicas sit behind a load balancer
  with no session affinity. The lease reaper is the one singleton, elected by
  a Postgres advisory lock. See [Running multiple
  replicas](#running-multiple-replicas).
- No namespaces and no audit-log backend beyond structured `tracing` output.

## Architecture

```
HTTP (axum)
  -> auth/policy/token/router core   (secrets-core)
       -> SecretsEngine impls        (secrets-engine-kv, secrets-engine-postgres)
       -> AuthMethod impls           (secrets-auth-userpass, secrets-auth-oidc)
            -> StorageBackend        (Barrier<PgStorage> — AEAD wraps plain Postgres)
```

Everything above the barrier works with plaintext logical values through
the same `StorageBackend` trait; only the barrier touches encryption. This
is a Cargo workspace specifically so that boundary is compiler-enforced:
`secrets-core` depends on nothing project-specific, every engine/auth crate
depends only on `secrets-core` plus what it individually needs, and
`crates/secrets-server/src/wiring.rs` is the single place mounts and auth
methods get registered. Adding a new engine or auth method means
implementing a trait and adding one line there — not touching routing,
tokens, or policy evaluation.

| Crate | Responsibility | docs.rs |
|---|---|---|
| `secrets-core` | Traits (`StorageBackend`, `SecretsEngine`, `AuthMethod`), token/policy/lease model, AEAD barrier, router, background reaper | [![docs.rs](https://img.shields.io/docsrs/secrets-core)](https://docs.rs/secrets-core) |
| `secrets-storage-postgres` | `StorageBackend` impl backed by a single `kv_store` table | [![docs.rs](https://img.shields.io/docsrs/secrets-storage-postgres)](https://docs.rs/secrets-storage-postgres) |
| `secrets-engine-kv` | Versioned, soft-deleting static secrets | [![docs.rs](https://img.shields.io/docsrs/secrets-engine-kv)](https://docs.rs/secrets-engine-kv) |
| `secrets-engine-postgres` | Dynamic PostgreSQL credential generation/revocation | [![docs.rs](https://img.shields.io/docsrs/secrets-engine-postgres)](https://docs.rs/secrets-engine-postgres) |
| `secrets-engine-github` | GitHub App installation tokens — repo-scoped, revocable | [![docs.rs](https://img.shields.io/docsrs/secrets-engine-github)](https://docs.rs/secrets-engine-github) |
| `secrets-engine-gitlab` | GitLab project/group access tokens | [![docs.rs](https://img.shields.io/docsrs/secrets-engine-gitlab)](https://docs.rs/secrets-engine-gitlab) |
| `secrets-engine-aws` | STS assumed-role sessions and per-lease IAM users | [![docs.rs](https://img.shields.io/docsrs/secrets-engine-aws)](https://docs.rs/secrets-engine-aws) |
| `secrets-engine-gcp` | Service-account impersonation, downscoped tokens, HMAC keys | [![docs.rs](https://img.shields.io/docsrs/secrets-engine-gcp)](https://docs.rs/secrets-engine-gcp) |
| `secrets-engine-gworkspace` | Brokered Google OAuth access tokens, domain-wide delegation | [![docs.rs](https://img.shields.io/docsrs/secrets-engine-gworkspace)](https://docs.rs/secrets-engine-gworkspace) |
| `secrets-engine-dropbox` | Brokered Dropbox OAuth access tokens | [![docs.rs](https://img.shields.io/docsrs/secrets-engine-dropbox)](https://docs.rs/secrets-engine-dropbox) |
| `secrets-engine-m365` | Microsoft Graph client-credentials and federated identity | [![docs.rs](https://img.shields.io/docsrs/secrets-engine-m365)](https://docs.rs/secrets-engine-m365) |
| `secrets-engine-federation` | Publishes provider trust config — stores no credential | [![docs.rs](https://img.shields.io/docsrs/secrets-engine-federation)](https://docs.rs/secrets-engine-federation) |
| `secrets-auth-userpass` | Argon2id username/password login | [![docs.rs](https://img.shields.io/docsrs/secrets-auth-userpass)](https://docs.rs/secrets-auth-userpass) |
| `secrets-auth-oidc` | Interactive + JWT-bearer OIDC login | [![docs.rs](https://img.shields.io/docsrs/secrets-auth-oidc)](https://docs.rs/secrets-auth-oidc) |
| `secrets-server` | axum binary: HTTP routes + `wiring.rs` composition root | *(not published — see the [Docker image](#docker))* |

Every library crate above is published to [crates.io](https://crates.io/search?q=secrets-core), with docs auto-built on [docs.rs](https://docs.rs/secrets-core) on every release — see [`.github/workflows/crates-publish.yml`](.github/workflows/crates-publish.yml). The publish list is derived from the workspace, so a new crate is released as soon as it exists; `secrets-server` opts out with `publish = false` and ships as a container image instead.

## Quick start

The server needs its own Postgres database (the "storage DB") to hold
encrypted state — this is separate from any database(s) the PostgreSQL
engine later manages credentials on.

### Docker

A public image is published to GitHub Container Registry on every push to
`main` (tag `edge`) and on version tags (tags `X.Y.Z`, `X.Y`, `latest`) —
see [`.github/workflows/docker-publish.yml`](.github/workflows/docker-publish.yml).

```bash
docker run --rm -p 8200:8200 \
  -e SECRETS_SERVER_STORAGE_DATABASE_URL=postgres://user:pass@host.docker.internal/secrets \
  -e SECRETS_MASTER_KEY=$(openssl rand -hex 32) \
  -e SECRETS_SERVER_BOOTSTRAP_USERNAME=admin \
  -e SECRETS_SERVER_BOOTSTRAP_PASSWORD=change-me \
  ghcr.io/typednotes/secrets-server:edge
```

The storage Postgres must be reachable from inside the container — use
`host.docker.internal` to reach a Postgres running on your host, or run
both containers on the same Docker network/compose project.

### From source

```bash
export SECRETS_SERVER_STORAGE_DATABASE_URL=postgres://user:pass@localhost/secrets
export SECRETS_MASTER_KEY=$(openssl rand -hex 32)   # 32 random bytes, hex-encoded

# optional: seed an initial admin user + full-access "root" policy
export SECRETS_SERVER_BOOTSTRAP_USERNAME=admin
export SECRETS_SERVER_BOOTSTRAP_PASSWORD=change-me

cargo run -p secrets-server
```

Config can also come from `secrets-server.toml` in the working directory;
environment variables (prefixed `SECRETS_SERVER_`) take precedence. See
`crates/secrets-server/src/config.rs` for every field and its default —
config is validated at startup, so a typo'd `listen_addr` or a
non-Postgres `storage_database_url` fails fast instead of surfacing later.

## Running multiple replicas

Run as many instances as you like behind a load balancer, pointed at the same
storage database. No configuration change is needed.

Two details make it work:

- **The reaper is elected, not duplicated.** Every instance competes for the
  `secrets/lease-reaper` advisory lock and only the winner revokes expired
  leases; the rest log once and stand by. The lock lives on a held Postgres
  connection, so a crashed leader releases it the moment its connection drops
  and the next tick elsewhere picks the work up — no heartbeat, no lease
  timeout to tune. Backends that do not implement `try_acquire_lock` grant it
  unconditionally, so single-node deployments are unaffected.
- **`/v1/sys/health` is a real probe.** It runs `SELECT 1` and answers `503`
  when storage is unreachable, so a load balancer takes a broken node out of
  rotation.

What you still have to provide:

- **An HA Postgres.** That is where durability, consensus and failover
  actually live.
- **The master key on every node.** `SECRETS_MASTER_KEY` must be identical
  across replicas, since they share one encrypted store. A KMS-backed unseal
  would be the upgrade if distributing the key that widely is a concern.

## Rotating the master key

Each stored value records the id of the key that sealed it — derived from the
key's own SHA-256, so there are no labels to keep in sync and a key cannot be
mislabelled. That makes rotation an online, resumable operation rather than a
dump-and-restore.

```mermaid
flowchart LR
    A["1. generate a new key<br/>openssl rand -hex 32"] --> B["2. restart with the new key<br/>active and the old one retired"]
    B --> C["3. POST /v1/sys/rewrap<br/>re-seals every value"]
    C --> D["4. drop the retired key<br/>and restart"]
```

```bash
# 2. both keys present: the new one seals, the old one still opens
export SECRETS_MASTER_KEY=$NEW_KEY
export SECRETS_MASTER_KEY_RETIRED=$OLD_KEY   # comma-separated if several

# 3. re-encrypt everything under the active key
curl -s -X POST "$ADDR/v1/sys/rewrap" -H "Authorization: Bearer $TOKEN" | jq
# => {"scanned": 412, "rewrapped": 412, "unchanged": 0, "contended": 0,
#     "failed": 0, "active_key_id": "9f2c1ab4",
#     "next_step": "every value is on the active key — ..."}

# 4. only once failed == 0
unset SECRETS_MASTER_KEY_RETIRED
```

Notes that matter:

- **Do not skip step 2.** Removing the old key before rewrapping makes every
  value written under it unreadable, and there is no recovery.
- `failed > 0` means a key still in use is missing from the ring. Restore it
  and re-run *before* removing anything; the pass keeps going rather than
  aborting, so the count tells you the scale of the problem.
- Safe to re-run and safe to run while serving. Rewrapping is conditional on
  the ciphertext it read, so a concurrent write is never clobbered by a
  re-encryption of the value it replaced — those show up as `contended`, which
  is benign because that write used the active key anyway.
- Values written before 1.0 carry no key id. They are read on a fallback path
  and reported as needing rewrap, so upgrading and rewrapping once brings the
  whole store onto the versioned format.
- `GET /v1/sys/rewrap` reports the active key id. Every replica must agree; if
  they disagree, one is running with stale configuration.

## HTTP API

```
GET   /v1/sys/health

POST  /v1/auth/userpass/login
POST  /v1/auth/oidc/config              # Sudo — register the IdP
GET   /v1/auth/oidc/authorize_url       # start interactive login
GET   /v1/auth/oidc/callback            # IdP redirects back here
POST  /v1/auth/oidc/login               # machine-to-machine: {"jwt": "..."}

GET   /v1/auth/token/lookup-self
POST  /v1/auth/token/renew-self
POST  /v1/auth/token/revoke-self

GET/POST/DELETE /v1/secret/data/{path}  # KV engine
GET   /v1/secret/metadata/{path}

GET/POST /v1/sys/rewrap                 # active master key / re-encrypt (Sudo)
GET   /v1/sys/help                      # every mounted engine and its shape
GET   /v1/{mount}/help                  # one engine's own documentation

GET/POST/DELETE /v1/{mount}/config/{target}   # provider + root credential (Sudo)
GET/POST/DELETE /v1/{mount}/roles/{role}      # what a role may mint, and its TTL
GET   /v1/{mount}/creds/{role}          # mint a credential + open a lease
POST  /v1/sys/leases/revoke/{lease_id}

GET/POST/DELETE /v1/sys/policy/{name}
```

Every request other than `sys/health` and login is authenticated via
`Authorization: Bearer <token>` and checked against the caller's policies
before it reaches an engine. The `help` endpoints are the one exception to
capability checks: any authenticated caller may read them, so that a consumer
holding only `read` on a single `creds` path can still discover what its
credential is worth.

`{mount}` is any engine — `database`, `github`, `gitlab`, `aws`, `gcp`,
`gworkspace`, `dropbox`, `m365`, `federation` — so adding a provider adds no
routes. `{mount}/config/{target}` is write-only: a `GET` reports whether it is
configured but never returns the document, because it holds the root
credential.

### Example: dynamic PostgreSQL credentials

```bash
TOKEN=$(curl -s -X POST localhost:8200/v1/auth/userpass/login \
  -d '{"username":"admin","password":"change-me"}' | jq -r .auth.client_token)

curl -s -X POST localhost:8200/v1/database/config/app-db \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"connection_url":"postgres://admin:adminpw@localhost/appdb"}'

curl -s -X POST localhost:8200/v1/database/roles/readonly \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "db_name": "app-db",
    "creation_statements": [
      "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '\''{{password}}'\'' VALID UNTIL '\''infinity'\'';",
      "GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"
    ],
    "revocation_statements": ["DROP ROLE IF EXISTS \"{{name}}\";"],
    "default_ttl_seconds": 3600
  }'

curl -s localhost:8200/v1/database/creds/readonly -H "Authorization: Bearer $TOKEN"
# => {"lease_id": "...", "data": {"username": "v_readonly_...", "password": "..."}, "lease_duration": 3600}
```

Generated usernames are restricted to `[a-z0-9_]` and passwords are pure
hex, so template substitution is plain string replacement — neither value
can contain a character that breaks out of the quotes in the SQL template
above.

## Testing

```bash
cargo test --workspace --lib --bins
```

Unit tests cover crypto round-trip/tamper-detection, policy evaluation,
KV versioning/soft-delete, the lease reaper (including cascade-revoke on
token revocation), SQL-template substitution and username/password
character-set safety, and OIDC claims-to-policy mapping / PKCE challenge
generation — all against in-memory fakes, no live Postgres or IdP needed.

Each delegation engine additionally tests its own credential-shaping logic
offline: GitHub App JWT claim bounds, GitLab's date-rollover and
lease-beats-provider-expiry rule, AWS IAM user-name generation and the
per-credential shape override, GCP access-boundary construction, the
Microsoft client-assertion variants, and the federation instruction builder.

The server's own tests assert the **self-documentation contract**: that the
route table has no conflicts, that every mounted engine describes itself, and
that no engine claims more revocability than its shape allows — so a `_doc`
block cannot quietly start lying.

Key rotation is covered end to end against an in-memory barrier: that
pre-1.0 unversioned values still open, that a retired key opens what it
sealed, that dropping a key still in use fails loudly instead of returning
garbage, that rewrapping is idempotent, and that a concurrent write is never
overwritten by a re-encryption of stale plaintext.

`cargo clippy --workspace --all-targets -- -D warnings` is clean.

### Integration tests against a running server

`crates/secrets-server/tests/integration.rs` drives the HTTP API of an
already-running server — local or deployed — over the network. The target
is given by environment variable:

```bash
SECRETS_TEST_URL=http://localhost:8200 \
SECRETS_TEST_USERNAME=admin \
SECRETS_TEST_PASSWORD=change-me \
  cargo test -p secrets-server --test integration
```

Every test *skips* (rather than fails) when `SECRETS_TEST_URL` is unset, so
plain `cargo test --workspace` stays offline; tests needing a token skip
again without `SECRETS_TEST_USERNAME`/`SECRETS_TEST_PASSWORD`. Coverage:
health, the unauthenticated surface (401/403 shapes, malformed bodies,
unknown routes), token lifecycle (login/lookup/renew/revoke), the KV engine
(round-trip, versioning, listing, unicode, concurrent writes), policy CRUD,
and the database-engine/lease error paths.

They are safe to point at a live deployment: each test namespaces its
secrets under `secret/data/itest/<uuid>/` and its policies under
`itest-<uuid>`, cleans up afterwards, and never touches the token it was
not issued. The suite also goes easy on the server — `userpass` login is
deliberately expensive (Argon2id), so one login is shared across tests and
in-flight requests are capped at 4 (`SECRETS_TEST_CONCURRENCY`); without
that, Cargo's default test parallelism is enough to starve a small
single-instance deployment into timeouts.

Integration tests against real Postgres (`testcontainers`-backed) are not
yet written — `secrets-storage-postgres` and `secrets-engine-postgres`
already carry `testcontainers`/`testcontainers-modules` dev-dependencies
for that purpose.

CI runs both `cargo test --workspace --lib --bins` and
`cargo clippy --workspace --all-targets -- -D warnings` on every pull
request — see [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## Project status and scope

This is an early-stage, single-maintainer project — treat it as a
learning/reference implementation, not production-hardened software yet.
Explicitly out of scope for v1: namespaces, an audit-log backend beyond
structured logs, a web UI, other secrets engines (PKI, transit, ...), other
storage backends, and Shamir seal/unseal.

Availability is delegated to Postgres rather than reimplemented: unlike Vault
and OpenBao, which own their own Raft consensus precisely so they need no
database, this depends on one already. That removes the need for an
active/standby model, request forwarding, peer membership and snapshotting —
and means your HA story is your Postgres HA story.

## Further reading

Design rationale and comparisons to existing secret managers live in
[`docs/`](docs/):

- [Alternatives compared](docs/alternatives.md)
- [**Delegating third-party access**](docs/delegation/README.md) — how a
  microservice gets GitHub, GitLab, AWS, GCS, Google Workspace, Dropbox or
  Microsoft 365 access without holding a long-lived credential, with a guide
  per provider, plus [**federation**](docs/delegation/federation.md) (the shape
  that stores nothing) and [**setup runbooks**](docs/delegation/setup/README.md)
  for every engine
- [Symmetric cryptography](docs/symmetric-cryptography.md), [asymmetric cryptography](docs/asymmetric-cryptography.md), [post-quantum cryptography](docs/post-quantum-cryptography.md)
- [Hashing](docs/hashing.md), [key derivation](docs/key-derivation.md), [TLS](docs/tls.md)
- [`docs/tools/`](docs/tools/) — notes on HashiCorp Vault, OpenBao, Bitwarden, 1Password-style tools, and others

## Contributing

Issues and PRs are welcome. Before opening a PR, run:

```bash
cargo test --workspace --lib --bins
cargo clippy --workspace --all-targets -- -D warnings
```

CI re-checks both on every pull request.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
