# Setting up Google Workspace and Drive

Mount `gworkspace/` · shape C — refresh broker · [mechanism](../google-workspace.md)

The server custodies the refresh token and hands out only ~1-hour access
tokens. That custody is the entire security benefit, so the consumer must never
be given the refresh token itself.

## 1. Provider side

1. In Google Cloud console, **create an OAuth 2.0 Client ID** (type: Web
   application) and add a redirect URI you can receive once.
2. **Publish the consent screen.** While it is in "Testing", refresh tokens
   expire after **seven days** — this catches almost everyone once.
3. Enable the Drive (or Gmail/Calendar) API on the project.

## 2. Obtain a refresh token, once

This step is interactive by nature — a human consents.

```bash
# 1. open this, approve, and copy the ?code= parameter from the redirect
echo "https://accounts.google.com/o/oauth2/v2/auth\
?client_id=$CLIENT_ID\
&redirect_uri=$REDIRECT\
&response_type=code\
&access_type=offline\
&prompt=consent\
&scope=https://www.googleapis.com/auth/drive.readonly"

# 2. exchange it
curl -s https://oauth2.googleapis.com/token \
  -d client_id="$CLIENT_ID" -d client_secret="$CLIENT_SECRET" \
  -d redirect_uri="$REDIRECT" -d grant_type=authorization_code \
  -d code="$CODE" | jq -r .refresh_token
```

`access_type=offline` plus `prompt=consent` is what makes a refresh token
appear.

## 3. Register the account

```bash
curl -X POST "$ADDR/v1/gworkspace/config/reporting" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "client_id": "....apps.googleusercontent.com",
    "client_secret": "...",
    "refresh_token": "1//..."
  }'
```

Config is write-only, so the refresh token can never be read back out — which
is the reason to put it here rather than in KV.

## 4. Define the role and grant the consumer

```bash
curl -X POST "$ADDR/v1/gworkspace/roles/report-service" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "target": "reporting",
    "mode": "refresh_token",
    "scopes": ["https://www.googleapis.com/auth/drive.readonly"]
  }'

curl -X POST "$ADDR/v1/sys/policy/report-service" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"rules":[{"prefix":"gworkspace/creds/report-service","capabilities":["read"]}]}'
```

## Alternative: domain-wide delegation

Impersonates any user in the domain without per-user consent. Read
[the blast radius](../google-workspace.md#alternative--domain-wide-delegation-shape-b)
before choosing it — Google's own guidance is now to avoid it for new
integrations.

```bash
curl -X POST "$ADDR/v1/gworkspace/config/dwd" \
  -H "Authorization: Bearer $TOKEN" \
  -d "$(jq -n --arg key "$(cat sa-key.json)" '{
        service_account_key_json: $key
      }')"

curl -X POST "$ADDR/v1/gworkspace/roles/mail-archiver" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "target": "dwd",
    "mode": "domain_wide_delegation",
    "subject": "user@acme.com",
    "scopes": ["https://www.googleapis.com/auth/gmail.readonly"]
  }'
```

`subject` is required in this mode and the engine refuses without it. A
super-admin must also authorise the service account's client ID and scope list
under Admin console → Security → Access and data control → API controls →
Domain-wide Delegation.

## Verify

```bash
AT=$(curl -s "$ADDR/v1/gworkspace/creds/report-service" \
  -H "Authorization: Bearer $CONSUMER_TOKEN" | jq -r .data.access_token)

curl -s -H "Authorization: Bearer $AT" \
  "https://www.googleapis.com/drive/v3/files?pageSize=5" | jq .
```

## Troubleshooting

| Symptom | Cause |
|---|---|
| `invalid_grant` | **Terminal, not transient.** The authorisation is gone: consent screen still in Testing (7-day expiry), six months idle, password change, or the user revoked it. A human must re-consent. The engine surfaces this explicitly so you do not retry forever. |
| `unauthorized_client` on DWD | The scope list in the Admin console does not exactly match the scopes requested. |
| `403 insufficientPermissions` | The scope is too narrow for the call, or the identity is not a member of the shared drive. |
| Files invisible in a shared drive | Drive ACLs are a separate axis from scopes — add the identity to the drive. |

## What revocation really does

**Nothing at the provider, deliberately.** An individual access token cannot be
invalidated, and calling Google's `/revoke` on lease expiry would destroy the
whole authorisation and require a human to re-consent. Real revocation is an
operator action:

```bash
curl -X DELETE "$ADDR/v1/gworkspace/config/reporting" -H "Authorization: Bearer $TOKEN"
curl -s https://oauth2.googleapis.com/revoke -d token="$REFRESH_TOKEN"
```
