# Setting up Microsoft 365

Mount `m365/` · shape B · [mechanism](../microsoft-365.md)

Microsoft offers the only **completely keyless** brokered path in this project:
a federated identity credential means no client secret exists anywhere. Use it.

## 1. Provider side

1. **Register an app**: Entra admin center → App registrations → New.
2. **Add Graph application permissions** and click **Grant admin consent**.
   Without that last step every call fails with an authorisation error that
   does not mention consent.
3. **Add a federated credential** (preferred): Certificates & secrets →
   Federated credentials → add your issuer, the exact subject, and audience
   `api://AzureADTokenExchange`. Create **no** client secret.
4. **Narrow the permissions.** App-only Graph permissions are tenant-wide by
   default, so this is not optional:

| Resource | Mechanism |
|---|---|
| Mail | `New-ApplicationAccessPolicy` binding the app to a mail-enabled security group (propagation can exceed an hour) |
| SharePoint / OneDrive | `Sites.Selected`, then `POST /sites/{siteId}/permissions` per site |
| Teams | resource-specific consent for named teams and chats |

## 2. Register the tenant

```bash
# Preferred: no stored secret at all
curl -X POST "$ADDR/v1/m365/config/acme" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "tenant_id": "00000000-0000-0000-0000-000000000000",
    "client_id": "11111111-1111-1111-1111-111111111111",
    "credential": {
      "type": "federated",
      "token_file": "/var/run/secrets/azure/tokens/azure-identity-token"
    }
  }'
```

The token file is re-read on every mint, because the platform rotates it.

```bash
# Certificate: the key never crosses the wire
curl -X POST "$ADDR/v1/m365/config/acme" \
  -H "Authorization: Bearer $TOKEN" \
  -d "$(jq -n --arg pem "$(cat app.key.pem)" '{
        tenant_id: "...", client_id: "...",
        credential: { type: "certificate", private_key_pem: $pem, x5t_s256: "BASE64URL_SHA256_THUMBPRINT" }
      }')"
```

```bash
# Client secret: simplest, weakest
curl -X POST "$ADDR/v1/m365/config/acme" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{ "tenant_id": "...", "client_id": "...",
        "credential": { "type": "secret", "client_secret": "..." } }'
```

Add `"authority"` only for sovereign clouds; it defaults to the public one.

## 3. Define the role and grant the consumer

```bash
curl -X POST "$ADDR/v1/m365/roles/report-service" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "target": "acme",
    "scope": "https://graph.microsoft.com/.default",
    "resource_hint": "Sites.Selected on acme.sharepoint.com/sites/reports"
  }'

curl -X POST "$ADDR/v1/sys/policy/report-service" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"rules":[{"prefix":"m365/creds/report-service","capabilities":["read"]}]}'
```

`.default` is the only usable scope for client credentials: the token carries
every permission the app has been granted, so **the app registration is the
scope boundary**. You cannot ask for less at request time.

`resource_hint` is documentation, not enforcement — Entra never reports the
narrowing back, so the engine surfaces `resource-narrowing:NONE RECORDED` in
`scoped_to` when it is unset rather than letting silence read as "scoped".

## Verify

```bash
AT=$(curl -s "$ADDR/v1/m365/creds/report-service" \
  -H "Authorization: Bearer $CONSUMER_TOKEN" | jq -r .data.access_token)

curl -s -H "Authorization: Bearer $AT" \
  "https://graph.microsoft.com/v1.0/sites?search=reports" | jq .
```

## Troubleshooting

| Symptom | Cause |
|---|---|
| `AADSTS700016` | Wrong `client_id` or tenant. |
| `AADSTS7000215` | Bad client secret. |
| `AADSTS700211` / `AADSTS70021` | No federated credential matches the token's issuer/subject. Compare them exactly — the subject must match character for character. |
| `Authorization_RequestDenied` from Graph | Admin consent was never granted, or the narrowing (`Sites.Selected`) grants no access to that site yet. |
| Token works everywhere despite `Sites.Selected` | The Graph **Search** API queries a tenant-wide index and bypasses `Sites.Selected`. |
| Token lives far longer than 90 minutes | A CAE-eligible token can last 24–28 hours. Read `expires_in`, never assume. |

## What revocation really does

**Nothing.** No API revokes a Graph access token.
`revokeSignInSessions` only invalidates refresh tokens and future issuance, and
Continuous Access Evaluation is the only near-real-time path — it needs both
resource and client to be CAE-capable and still takes up to ~15 minutes.

The real control is a Configurable Token Lifetime policy, whose minimum is
**10 minutes**. Given revocation is unavailable, that is worth configuring.
