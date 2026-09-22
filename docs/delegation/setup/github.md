# Setting up GitHub

Mount `github/` · shape A — genuinely revocable · [mechanism](../github.md)

## 1. Provider side

1. **Create a GitHub App** in the organisation: Settings → Developer settings →
   GitHub Apps → New GitHub App. Disable Webhook (nothing here needs it).
2. **Grant it the maximum permission set** any consumer will need — this is the
   ceiling, and each role narrows *down* from it. Start with
   `Contents: Read-only` and add only what a consumer actually asks for.
3. **Generate a private key** at the bottom of the App's settings page. The
   downloaded `.pem` is the only durable secret this engine needs.
4. **Install the App** on the specific repositories, not "All repositories".
5. **Note the installation id** — it is in the URL after installing
   (`/settings/installations/<id>`), or list them with an App JWT.

## 2. Register the App

```bash
curl -X POST "$ADDR/v1/github/config/acme" \
  -H "Authorization: Bearer $TOKEN" \
  -d "$(jq -n --arg pem "$(cat acme-app.private-key.pem)" '{
        app_id: "Iv1.0123456789abcdef",
        private_key_pem: $pem,
        base_url: "https://api.github.com"
      }')"
```

- `app_id` is the App's **client ID**; the numeric App ID also works.
- `base_url` defaults to `https://api.github.com`. For GitHub Enterprise Server
  use `https://ghe.example.com/api/v3`.

## 3. Define the role

```bash
curl -X POST "$ADDR/v1/github/roles/report-service" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "target": "acme",
    "installation_id": 98765432,
    "repositories": ["reports", "report-templates"],
    "permissions": { "contents": "read", "pull_requests": "write" }
  }'
```

Leaving `repositories` or `permissions` empty means "everything the
installation has". The engine reports that back as `repos:ALL` in `scoped_to`
so it cannot pass unnoticed, but set both.

There is no TTL setting: GitHub fixes installation tokens at one hour.

## 4. Grant the consumer

```bash
curl -X POST "$ADDR/v1/sys/policy/report-service" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"rules":[{"prefix":"github/creds/report-service","capabilities":["read"]}]}'
```

## Verify

```bash
curl -s "$ADDR/v1/github/creds/report-service" \
  -H "Authorization: Bearer $CONSUMER_TOKEN" | jq '.data.token, ._doc.scoped_to'
```

Then use it:

```bash
git clone https://x-access-token:${GH_TOKEN}@github.com/acme/reports.git
```

## Troubleshooting

| Symptom | Cause |
|---|---|
| `401 'A JWT could not be decoded'` | `private_key_pem` is not the App key, or not RSA. The engine rejects a malformed PEM up front with a clear message. |
| `401` with a valid key | Clock skew. The engine already backdates `iat` by 60s; check the host clock if it persists. |
| `404` on the token request | The App is not installed on that installation id, or the id belongs to another App. |
| `422` mentioning complexity | Too many repositories crossed with too many permissions. Narrow the role. |
| `403` with secondary-rate-limit wording | You are minting too fast. GitHub allows ~2,000 token creations per hour App-wide; cache a token for most of its hour. |

## What revocation really does

GitHub is the exception in this project: revoking the lease calls
`DELETE /installation/token` and the credential stops working immediately.

```bash
curl -X POST "$ADDR/v1/sys/leases/revoke/$LEASE_ID" -H "Authorization: Bearer $TOKEN"
```
