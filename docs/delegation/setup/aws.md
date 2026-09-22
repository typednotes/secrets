# Setting up AWS

Mount `aws/` · shape B by default, A with `iam_user` · [mechanism](../aws.md)

Prefer [federation](../federation.md#setting-it-up--aws) if the consumer has its
own OIDC identity — then no credential is brokered at all.

## 1. Provider side

**If the server runs on AWS** (EC2, ECS or EKS), give its instance profile,
task role or IRSA role permission to assume the target roles. No secret is
stored — this is the preferred setup.

**Otherwise** create an IAM user with `sts:AssumeRole` on the target roles and
keep its access key for step 2.

Then create the role the consumer's session will assume, with a trust policy
naming the server's principal and a least-privilege permission policy.

## 2. Register the account

```bash
# Preferred: no stored secret, credentials come from the provider chain
curl -X POST "$ADDR/v1/aws/config/production" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{ "region": "eu-west-3", "auth": "default" }'
```

```bash
# Fallback when the server has no AWS identity of its own
curl -X POST "$ADDR/v1/aws/config/production" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "region": "eu-west-3",
    "auth": "static",
    "access_key_id": "AKIA...",
    "secret_access_key": "..."
  }'
```

`auth: "default"` uses the standard AWS provider chain, so instance profile,
IRSA, ECS task role and environment variables all work without change.

## 3. Define the role

### Assumed role — short-lived, not revocable

```bash
curl -X POST "$ADDR/v1/aws/roles/report-service" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "target": "production",
    "credential_type": "assumed_role",
    "role_arn": "arn:aws:iam::123456789012:role/reports-writer",
    "default_ttl_seconds": 900,
    "session_policy": {
      "Version": "2012-10-17",
      "Statement": [
        { "Effect": "Allow",
          "Action": ["s3:GetObject","s3:PutObject"],
          "Resource": "arn:aws:s3:::reports-bucket/report-service/*" },
        { "Effect": "Allow",
          "Action": "s3:ListBucket",
          "Resource": "arn:aws:s3:::reports-bucket",
          "Condition": { "StringLike": { "s3:prefix": "report-service/*" } } }
      ]
    }
  }'
```

The session policy **intersects** with the role's own policy — it can only
narrow. Add `external_id` when assuming a role in an account you do not own,
and `session_policy_arns` for up to 10 managed policies.

`default_ttl_seconds` must be within 900–43200 and within the role's
`MaxSessionDuration`; the engine validates locally rather than sending a call
that AWS will reject. Ask for the shortest you can live with, because this
credential cannot be revoked.

### IAM user — revocable, but long-lived until revoked

```bash
curl -X POST "$ADDR/v1/aws/roles/backup-job" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "target": "production",
    "credential_type": "iam_user",
    "default_ttl_seconds": 3600,
    "user_policy": {
      "Version": "2012-10-17",
      "Statement": [{ "Effect": "Allow", "Action": "s3:PutObject",
                      "Resource": "arn:aws:s3:::backups/*" }]
    }
  }'
```

This mirrors the Postgres engine: a user and access key are created per lease
and deleted on expiry. The server's identity needs `iam:CreateUser`,
`iam:PutUserPolicy`, `iam:CreateAccessKey` and the matching deletes.

Credentials from this role report `"shape": "mint-and-revoke"` in their `_doc`,
overriding the engine's headline shape — because for *this* credential, lease
revocation genuinely works.

## 4. Grant the consumer

```bash
curl -X POST "$ADDR/v1/sys/policy/report-service" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"rules":[{"prefix":"aws/creds/report-service","capabilities":["read"]}]}'
```

## Verify

```bash
curl -s "$ADDR/v1/aws/creds/report-service" \
  -H "Authorization: Bearer $CONSUMER_TOKEN" | jq '._doc'
```

Check `_doc.shape` and `_doc.revoke_effect`: for `assumed_role` it will tell
you the session cannot be recalled.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `AccessDenied` on AssumeRole | The target role's trust policy does not name the server's principal. |
| `ValidationError` on duration | Requested TTL exceeds the role's `MaxSessionDuration`. Raise it on the role or lower the TTL. |
| Session has no permissions | The session policy and role policy do not intersect — a session policy can never add. |
| New `iam_user` key fails briefly | IAM is eventually consistent. Retry for a few seconds rather than failing. |
| `LimitExceeded` creating a key | Two access keys per user is a hard limit; this is why a user is created per lease. |

## What revocation really does

For `assumed_role`: **nothing at the provider.** The lease record is removed
and the STS session keeps working until `Expiration`. AWS offers no per-session
revocation — the console's "revoke active sessions" attaches a role-wide deny
on `aws:TokenIssueTime` that also kills innocent sibling sessions. If you need
per-consumer revocation, give each consumer its own role, or use `iam_user`.
