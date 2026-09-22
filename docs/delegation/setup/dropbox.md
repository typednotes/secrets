# Setting up Dropbox

Mount `dropbox/` · shape C — refresh broker · [mechanism](../dropbox.md)

Dropbox has no API that mints a sub-credential, so **the unit of isolation is
one OAuth authorisation per consumer**. Share one authorisation across
consumers and you lose per-consumer revocability entirely.

## 1. Provider side

1. Create an app at <https://www.dropbox.com/developers/apps>.
2. Choose the access type carefully: **App folder** sandboxes it to
   `/Apps/<name>`; **Full Dropbox** sees everything. This is **immutable** —
   changing it later means a new app and re-linking every consumer. Choose App
   folder unless you are certain.
3. Under Permissions, enable only the scopes needed (e.g.
   `files.content.read`, `files.metadata.read`) and submit.

## 2. Obtain a refresh token, once per consumer

```bash
# 1. open, approve, copy the ?code= value
echo "https://www.dropbox.com/oauth2/authorize\
?client_id=$APP_KEY\
&response_type=code\
&token_access_type=offline\
&scope=files.content.read%20files.metadata.read"

# 2. exchange it
curl -s https://api.dropbox.com/oauth2/token \
  -u "$APP_KEY:$APP_SECRET" \
  -d grant_type=authorization_code -d code="$CODE" | jq -r .refresh_token
```

`token_access_type=offline` is what produces a refresh token; without it you
get a single four-hour token and no way to renew.

## 3. Register it and define the role

```bash
curl -X POST "$ADDR/v1/dropbox/config/report-service" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "app_key": "...",
    "app_secret": "...",
    "refresh_token": "..."
  }'

curl -X POST "$ADDR/v1/dropbox/roles/report-service" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "target": "report-service",
    "scopes": ["files.content.read"]
  }'

curl -X POST "$ADDR/v1/sys/policy/report-service" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"rules":[{"prefix":"dropbox/creds/report-service","capabilities":["read"]}]}'
```

One config document per consumer authorisation — that is what makes them
independently revocable.

## Team accounts

`select_user` / `select_admin` on the role record which
`Dropbox-API-Select-User` / `-Select-Admin` header the consumer should send:

```bash
curl -X POST "$ADDR/v1/dropbox/roles/team-archiver" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{ "target": "team", "select_user": "dbmid:AAB..." }'
```

Understand what this is before using it: the header **selects a target, it does
not reduce what the token can reach**. A team credential can act as any member,
so it belongs in the server's own custody for administrative jobs — not leased
to ordinary consumers. The engine states this in `scoped_to` so it appears in
the consumer's own response.

## Verify

```bash
AT=$(curl -s "$ADDR/v1/dropbox/creds/report-service" \
  -H "Authorization: Bearer $CONSUMER_TOKEN" | jq -r .data.access_token)

curl -s -X POST https://api.dropboxapi.com/2/files/list_folder \
  -H "Authorization: Bearer $AT" -H "Content-Type: application/json" \
  -d '{"path":""}' | jq .
```

## Troubleshooting

| Symptom | Cause |
|---|---|
| `invalid_grant` | The refresh token was revoked — note that revoking *any* token from an authorisation kills the whole set. Re-link. |
| `missing_scope` | The scope was not enabled on the app, or not requested during authorisation. |
| Paths look wrong | An App-folder app is rooted at `/Apps/<name>`; paths are relative to that, not the account root. |
| Wanted a shorter token | Not possible. Four hours is fixed, including for testing. |

## What revocation really does

**Nothing on lease expiry, deliberately** — and this is the subtle one.
Dropbox's `/2/auth/token/revoke` invalidates the **refresh token** along with
the access token, so a reaper calling it would destroy the authorisation and
break the consumer's next request.

The engine does not even keep the access token in the lease, so that
authorisation-destroying call is out of the reaper's reach by construction.
Real revocation is a deliberate operator action requiring human re-consent
afterwards:

```bash
curl -X DELETE "$ADDR/v1/dropbox/config/report-service" -H "Authorization: Bearer $TOKEN"
curl -X POST https://api.dropboxapi.com/2/auth/token/revoke -H "Authorization: Bearer $AT"
```
