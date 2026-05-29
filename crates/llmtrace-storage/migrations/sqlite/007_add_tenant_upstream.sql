-- 007_add_tenant_upstream.sql: per-tenant upstream routing overrides.
--
-- Adds two nullable columns to the tenants table:
--   * upstream_url                  — optional per-tenant upstream base URL.
--   * upstream_api_key_ciphertext   — AEAD-encrypted per-tenant provider key,
--                                     base64-encoded `nonce || ciphertext`.
--                                     NULL means "inherit the global key".
-- Both default to NULL so existing tenants transparently fall back to the
-- global upstream_url / env-based provider credential.

ALTER TABLE tenants ADD COLUMN upstream_url TEXT;
ALTER TABLE tenants ADD COLUMN upstream_api_key_ciphertext TEXT;
