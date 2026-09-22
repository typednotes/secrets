# GitHub

Delegating repository access — clone, push, open PRs, publish packages — to a
consuming microservice.

GitHub is the **best case** in this whole set. Its App installation tokens are
short-lived by construction, narrowable to specific repositories *and* a
subset of permissions, and genuinely revocable on demand. That combination is
rare enough that GitHub is the one provider here where a lease means exactly
what it says, and the engine is a near-direct translation of
`secrets-engine-postgres`.

- [Mechanisms at a glance](#mechanisms-at-a-glance)
- [One-time setup](#one-time-setup)
- [How a credential is minted](#how-a-credential-is-minted)
- [Engine sketch](#engine-sketch)
- [Revocation](#revocation)
- [Deploy keys](#deploy-keys)
- [What does not work](#what-does-not-work)
- [Gotchas](#gotchas)

## Mechanisms at a glance

| Mechanism | Shape | TTL | Scoping | Revocable early? |
|---|---|---|---|---|
| App installation token | **A** | **1 h, fixed** | chosen repos (≤ 500) + permission subset | **yes** |
| Deploy key | **A** | none — until deleted | one repo, read or read-write | **yes** |
| Fine-grained / classic PAT | **D** | up to 1 year | repos + permissions | via org bulk-revoke only |
| Actions OIDC token | — | minutes | proves workflow identity *outward* | n/a |

Only the first two can be minted by an API, so only those can back an engine.

## One-time setup

The server authenticates as a **GitHub App** — not as a user, and not with a
PAT. This matters: an App's identity is independent of any employee, its
private key is the only durable secret, and its reach is exactly the set of
repositories the App is installed on.

```mermaid
flowchart LR
    A["1. Create a GitHub App<br/>in the org"] --> B["2. Grant it the <i>maximum</i><br/>permission set any consumer<br/>will ever need"]
    B --> C["3. Generate a private key<br/>PEM — the only secret<br/>the server stores"]
    C --> D["4. Install the App on the<br/>target repos, note the<br/>installation id"]
    D --> E["5. POST the PEM + App id to<br/>github/config/{target}"]
```

Step 2 is the one to think about: an installation token can only ever be a
*subset* of what the App was granted, so the App's permissions are the ceiling
and each role's `permissions` block is the actual grant. Set the ceiling once,
narrowly, and do least-privilege per role.

## How a credential is minted

Two hops: a short-lived JWT proves the server *is* the App, then the
installation token is requested for a specific installation, narrowed on the
way out.

```mermaid
sequenceDiagram
    participant C as consumer
    participant V as secrets-server
    participant GH as GitHub API
    participant R as repo

    C->>V: 1. GET /v1/github/creds/report-service<br/>Bearer $TOKEN
    V->>V: 2. policy check: read on github/creds/report-service
    V->>V: 3. load github/roles/report-service<br/>(installation id, repos, permissions)
    V->>V: 4. build JWT — RS256, iss = App client id,<br/>iat = now-60s, exp = iat+600s
    Note over V,GH: the JWT proves "I am this App".<br/>It is NOT a repo credential.
    V->>GH: 5. POST /app/installations/{id}/access_tokens<br/>Authorization: Bearer $APP_JWT<br/>{repositories, permissions}
    GH-->>V: 6. {token: "ghs_…", expires_at: +1h,<br/>permissions, repositories}
    V->>V: 7. store_lease(expires_at from response,<br/>internal_data = {token})
    V-->>C: 8. {lease_id, data: {token}, lease_duration}
    C->>R: 9. git clone https://x-access-token:ghs_…@github.com/org/repo
    Note over R: token dies after 1 h,<br/>or when the lease is revoked
```

The JWT's `exp` may be at most **10 minutes** out, and backdating `iat` by ~60
seconds is the conventional guard against clock skew. Sign with **RS256**; the
`iss` claim is the App's client ID (the numeric App ID is accepted as a
legacy fallback).

Use the `expires_at` GitHub returns as the lease expiry rather than computing
`now + 1h` locally — same discipline as everywhere else, so the lease can
never outlive the credential.

## Engine sketch

```
github/config/{target}   # App id + private key PEM              (Sudo)
github/roles/{role}      # installation, repos, permissions, TTL  (Sudo)
github/creds/{role}      # GET → installation token + lease       (Read)
```

`github/config/acme`:

```json
{
  "app_id": "1234567",
  "private_key_pem": "-----BEGIN RSA PRIVATE KEY-----\n…",
  "base_url": "https://api.github.com"
}
```

`base_url` is what makes GitHub Enterprise Server work — its endpoint is
`https://ghe.example.com/api/v3`, otherwise identical.

`github/roles/report-service`:

```json
{
  "target": "acme",
  "installation_id": 98765432,
  "repositories": ["reports", "report-templates"],
  "permissions": { "contents": "read", "pull_requests": "write" }
}
```

There is no `default_ttl_seconds`: the 1-hour lifetime is fixed and not
configurable, so the role has nothing to say about it.

`generate()` returns `{"token": "ghs_…"}` and stores that same token in
`Lease.internal_data`, because the revocation call authenticates *with the
token being revoked*.

## Revocation

```mermaid
sequenceDiagram
    participant R as reaper
    participant E as github engine
    participant GH as GitHub API

    Note over R: lease expired, explicitly revoked,<br/>or owning token revoked
    R->>E: 1. revoke(storage, lease)
    E->>GH: 2. DELETE /installation/token<br/>Authorization: Bearer $LEASED_TOKEN
    GH-->>E: 3. 204 No Content
    Note over E,GH: the token stops working immediately
```

Note the asymmetry with minting: creation authenticates with the **App JWT**,
revocation authenticates with the **installation token itself**. That is why
the token has to be kept in `internal_data` — an engine that discarded it
after handing it to the consumer could not revoke it.

This is real revocation, not the advisory kind AWS and GCP force on us. It is
worth stating in the engine docs that GitHub leases honour their contract,
precisely because most others do not.

## Deploy keys

If a consumer only needs git transport to one repository and nothing from the
API, a deploy key is narrower than any token: `POST /repos/{owner}/{repo}/keys`
creates it, `DELETE /repos/{owner}/{repo}/keys/{key_id}` destroys it. The
engine generates a keypair, registers the public half, leases the private half,
and deletes the key on expiry — structurally identical to the Postgres engine.

Two warnings. Deploy keys have **no expiry field at all**, so a missed
revocation leaves permanent access — the lease is the only clock. And the API's
`read_only` parameter **defaults to `false`**, i.e. write access, the opposite
of the web UI's default. Always set it explicitly.

## What does not work

- **Personal access tokens**, fine-grained or classic, **cannot be created by
  any API** — web UI only. Organisations can bulk-*revoke* them
  (`POST /orgs/{org}/personal-access-tokens`), but never mint them. A PAT is
  therefore shape D: store it in KV, rotate it by hand, and treat that as a
  stopgap rather than a design.
- **Actions OIDC tokens** authenticate a workflow *to third parties* such as
  AWS. There is no endpoint that exchanges one for a GitHub API token, so
  GitHub cannot be reached by the federation shape the way AWS or Microsoft
  can. Federation here points outward, not inward.

## Gotchas

- **Token creation is rate-limited to roughly 2,000 per hour, App-wide** —
  not per installation. GitHub's own guidance is to cache and reuse a token
  for most of its hour rather than mint one per request. An engine that mints
  per request will hit this under load; consider caching a live token per
  role and handing out the remaining lifetime, at the cost of several
  consumers sharing one token's fate on revocation.
- Requests *using* a minted token draw on the installation's own budget
  (5,000–12,500/hour, more on Enterprise Cloud), which is separate from the
  minting limit.
- A token may name at most **500 repositories**, and a large permission set
  crossed with a large repository set can be rejected outright for
  "complexity". Narrow scope is the fix, which is the right instinct anyway.
- GitHub began rolling out a **stateless JWT-format installation token**
  (`ghs_<appid>.<jwt>`, recognisable by having two dots where the opaque form
  has none) on Enterprise Cloud and Data Residency during 2026. Treat the
  token as an opaque string and never parse it. If you need the legacy format
  for a specific call there is a per-request override header; verify the
  current state of this rollout before relying on either form.
