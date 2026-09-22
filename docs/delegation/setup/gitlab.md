# Setting up GitLab

Mount `gitlab/` · shape A, with day-granularity provider expiry · [mechanism](../gitlab.md)

## 1. Provider side

Create the credential the server will mint with. Prefer the narrower option:

- **Group Owner PAT** — Group → Settings → Access tokens, role Owner, scope
  `api`. Can only mint access within that group.
- **Instance admin PAT** — only if you need per-user or impersonation tokens.
  It can act as any user on the instance.

Note the numeric project or group id (shown on the project's overview page).

## 2. Register it

```bash
curl -X POST "$ADDR/v1/gitlab/config/acme" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "base_url": "https://gitlab.com/api/v4",
    "private_token": "glpat-..."
  }'
```

`base_url` defaults to `https://gitlab.com/api/v4`; for self-managed use
`https://gitlab.example.com/api/v4`.

## 3. Define the role

```bash
curl -X POST "$ADDR/v1/gitlab/roles/report-service" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "target": "acme",
    "resource": "project",
    "resource_id": "42",
    "scopes": ["read_repository"],
    "access_level": 20,
    "default_ttl_seconds": 900
  }'
```

- `resource` is `"project"` (default) or `"group"`.
- `resource_id` is a **string**, so URL-encoded paths work as well as numbers.
- `access_level`: 10 Guest, 20 Reporter (our default), 30 Developer,
  40 Maintainer (GitLab's own default), 50 Owner. `scopes` chooses which APIs,
  `access_level` how much authority within them.
- `default_ttl_seconds` governs **our** lease, which is what actually makes the
  credential short-lived — see below.

## 4. Grant the consumer

```bash
curl -X POST "$ADDR/v1/sys/policy/report-service" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"rules":[{"prefix":"gitlab/creds/report-service","capabilities":["read"]}]}'
```

## The two clocks

GitLab's `expires_at` accepts a **date**, not a timestamp, so the soonest
expiry it will accept is tomorrow at midnight UTC. The engine therefore runs
two clocks:

```mermaid
flowchart LR
    A["GitLab's expires_at<br/>= tomorrow<br/><i>backstop only</i>"] --> C["credential"]
    B["our Lease.expires_at<br/>= now + default_ttl_seconds<br/><i>the real deadline</i>"] --> C
    C --> D["reaper DELETEs the token<br/>at our deadline"]
```

Set `default_ttl_seconds` to what you actually want. GitLab's date only matters
if the reaper never runs at all.

## Verify

```bash
curl -s "$ADDR/v1/gitlab/creds/report-service" \
  -H "Authorization: Bearer $CONSUMER_TOKEN" | jq '.data, ._doc.revocable'

git clone https://oauth2:${GL_TOKEN}@gitlab.com/acme/reports.git
```

## Troubleshooting

| Symptom | Cause |
|---|---|
| `401 Unauthorized` | The `private_token` lacks `api` scope, or has expired — PATs now always expire. |
| `403 Forbidden` on create | The root PAT's role is below Owner on that group/project. |
| `400` about `expires_at` | The instance enforces a shorter maximum lifetime than the date sent. |
| Token works but API calls 403 | `access_level` is too low even though `scopes` is right. |

Never retry a **rotation** blindly: rotating an already-revoked token makes
GitLab revoke the whole token family as reuse detection.
