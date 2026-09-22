# Setting up Google Cloud Storage

Mount `gcp/` · shape B, A with `hmac` · [mechanism](../gcp-storage.md)

Prefer [federation](../federation.md#setting-it-up--google-cloud) if the
consumer has its own OIDC identity.

## 1. Provider side

1. **Create the target service account**, e.g.
   `reports-reader@acme.iam.gserviceaccount.com`, and grant it only what the
   consumer needs on the bucket (`roles/storage.objectViewer`).
2. **Let the server impersonate it**: grant the server's own identity
   `roles/iam.serviceAccountTokenCreator` **on that service account**.
3. **Enable uniform bucket-level access** on the bucket — Credential Access
   Boundary conditions need it.
4. Only if the server does not run on GCP: create a service account JSON key.
   Google's guidance treats this as a last resort, and so should you.

## 2. Register the project

```bash
# Preferred: no stored key, uses the attached service account via the metadata server
curl -X POST "$ADDR/v1/gcp/config/production" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{ "project_id": "acme-prod", "auth": "metadata" }'
```

```bash
# Fallback off-GCP
curl -X POST "$ADDR/v1/gcp/config/production" \
  -H "Authorization: Bearer $TOKEN" \
  -d "$(jq -n --arg key "$(cat sa-key.json)" '{
        project_id: "acme-prod",
        auth: "service_account_key",
        service_account_key_json: $key
      }')"
```

## 3. Define the role

```bash
curl -X POST "$ADDR/v1/gcp/roles/report-service" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "target": "production",
    "credential_type": "downscoped",
    "service_account": "reports-reader@acme.iam.gserviceaccount.com",
    "scopes": ["https://www.googleapis.com/auth/devstorage.read_only"],
    "bucket": "reports",
    "prefix": "report-service/",
    "iam_role": "roles/storage.objectViewer",
    "default_ttl_seconds": 900
  }'
```

`credential_type` options:

| Value | What the consumer gets | Revocable |
|---|---|---|
| `downscoped` (default) | a token restricted to one bucket and prefix | no |
| `impersonated` | a token with **all** of the service account's permissions | no |
| `hmac` | an HMAC key pair for the S3-compatible XML API | **yes** |

Use `downscoped`. Plain `impersonated` hands the consumer the whole service
account for the token's lifetime.

## 4. Grant the consumer

```bash
curl -X POST "$ADDR/v1/sys/policy/report-service" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"rules":[{"prefix":"gcp/creds/report-service","capabilities":["read"]}]}'
```

## Verify

```bash
TOKEN_OUT=$(curl -s "$ADDR/v1/gcp/creds/report-service" \
  -H "Authorization: Bearer $CONSUMER_TOKEN" | jq -r .data.access_token)

curl -s -H "Authorization: Bearer $TOKEN_OUT" \
  "https://storage.googleapis.com/storage/v1/b/reports/o?prefix=report-service/" | jq .
```

## Troubleshooting

| Symptom | Cause |
|---|---|
| `403 iam.serviceAccounts.getAccessToken denied` | The server's identity lacks Token Creator **on the target service account** (project-level is not enough). |
| Reads work, `list` returns nothing | The classic prefix gotcha. The engine OR's in an `objectListPrefix` condition for this reason — check the `prefix` ends with `/`. |
| `400` from the STS exchange | The bucket lacks uniform bucket-level access, or `iam_role` is not a storage role. |
| Token minted but every call 403 | The service account itself lacks the permission; a boundary can only subtract. |
| Asked for 12h, got 1h | Needs the `constraints/iam.allowServiceAccountCredentialLifetimeExtension` org policy — and is the wrong direction for an un-revocable credential. |

## What revocation really does

For `downscoped` and `impersonated`: **nothing.** Google has no endpoint that
invalidates an issued access token. The lease record is dropped and the token
works until `expireTime`, which is why the default TTL here is 15 minutes. The
only blunt alternatives are disabling the service account (kills every
consumer's tokens) or removing its IAM binding.

`hmac` keys are the exception — `revoke()` sets the key `INACTIVE` then deletes
it, and those credentials report `"shape": "mint-and-revoke"`.
