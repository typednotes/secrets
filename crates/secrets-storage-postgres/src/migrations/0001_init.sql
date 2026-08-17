CREATE TABLE kv_store (
    path        TEXT PRIMARY KEY,
    value       BYTEA NOT NULL,
    expires_at  TIMESTAMPTZ,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX kv_store_expires_at_idx ON kv_store (expires_at) WHERE expires_at IS NOT NULL;
