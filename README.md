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
- **Encryption**: a single master key (env var, or a file path held in that
  env var) — no Shamir seal/unseal. A `Barrier` decorator transparently
  AES-256-GCM-encrypts every value before it reaches storage; paths stay
  plaintext so leases/tokens can be expiry-scanned without decrypting.
- **Secrets engines**:
  - `secret/` — a versioned, soft-deleting static KV store (kv-v2 style).
  - `database/` — dynamic PostgreSQL credentials: configure a target
    database and a role's `CREATE`/`DROP` SQL templates, then mint a
    short-lived, uniquely-named credential on demand.
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
- **Single node.** No HA, no clustering, no namespaces, no audit-log
  backend beyond structured `tracing` output.

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
| `secrets-auth-userpass` | Argon2id username/password login | [![docs.rs](https://img.shields.io/docsrs/secrets-auth-userpass)](https://docs.rs/secrets-auth-userpass) |
| `secrets-auth-oidc` | Interactive + JWT-bearer OIDC login | [![docs.rs](https://img.shields.io/docsrs/secrets-auth-oidc)](https://docs.rs/secrets-auth-oidc) |
| `secrets-server` | axum binary: HTTP routes + `wiring.rs` composition root | *(not published — see the [Docker image](#docker))* |

The library crates above are published to [crates.io](https://crates.io/search?q=secrets-core), with docs auto-built on [docs.rs](https://docs.rs/secrets-core) on every release — see [`.github/workflows/crates-publish.yml`](.github/workflows/crates-publish.yml).

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

POST  /v1/database/config/{name}        # target DB connection (Sudo)
POST  /v1/database/roles/{role}         # create/revoke SQL templates + TTL
GET   /v1/database/creds/{role}         # generates a lease on demand
POST  /v1/sys/leases/revoke/{lease_id}

GET/POST/DELETE /v1/sys/policy/{name}
```

Every request other than `sys/health` and login is authenticated via
`Authorization: Bearer <token>` and checked against the caller's policies
before it reaches an engine.

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
cargo test --workspace --lib
```

Unit tests cover crypto round-trip/tamper-detection, policy evaluation,
KV versioning/soft-delete, the lease reaper (including cascade-revoke on
token revocation), SQL-template substitution and username/password
character-set safety, and OIDC claims-to-policy mapping / PKCE challenge
generation — all against in-memory fakes, no live Postgres or IdP needed.
`cargo clippy --workspace --all-targets` is clean.

Integration tests against real Postgres (`testcontainers`-backed) are not
yet written — `secrets-storage-postgres` and `secrets-engine-postgres`
already carry `testcontainers`/`testcontainers-modules` dev-dependencies
for that purpose.

CI runs both `cargo test --workspace --lib` and
`cargo clippy --workspace --all-targets -- -D warnings` on every pull
request — see [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## Project status and scope

This is an early-stage, single-maintainer project — treat it as a
learning/reference implementation, not production-hardened software yet.
Explicitly out of scope for v1: namespaces, HA/replication (the lease
reaper takes no distributed lock — a Postgres advisory lock is where that
would go), an audit-log backend beyond structured logs, a web UI, other
secrets engines (PKI, transit, ...), other storage backends, and Shamir
seal/unseal.

## Further reading

Design rationale and comparisons to existing secret managers live in
[`docs/`](docs/):

- [Alternatives compared](docs/alternatives.md)
- [Symmetric cryptography](docs/symmetric-cryptography.md), [asymmetric cryptography](docs/asymmetric-cryptography.md), [post-quantum cryptography](docs/post-quantum-cryptography.md)
- [Hashing](docs/hashing.md), [key derivation](docs/key-derivation.md), [TLS](docs/tls.md)
- [`docs/tools/`](docs/tools/) — notes on HashiCorp Vault, OpenBao, Bitwarden, 1Password-style tools, and others

## Contributing

Issues and PRs are welcome. Before opening a PR, run:

```bash
cargo test --workspace --lib
cargo clippy --workspace --all-targets -- -D warnings
```

CI re-checks both on every pull request.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
