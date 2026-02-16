# Auth & Multi-Tenancy Guide

LLMTrace supports API key authentication, role-based access control (RBAC), and tenant isolation. When auth is disabled (the default), the proxy operates in open mode with optional header-based tenant tagging.

## Enabling Authentication

```yaml
auth:
  enabled: true
  admin_key: "your-bootstrap-admin-secret"
```

When `auth.enabled` is `true`:

- Every request (except `/health` and `/swagger-ui`) must carry a valid API key
- The `admin_key` is a bootstrap key for initial setup -- use it to create tenants and generate API keys
- Keys are validated via `Authorization: Bearer <key>` header

When `auth.enabled` is `false` (default):

- All requests are allowed without authentication
- Tenant isolation is based on the `X-LLMTrace-Tenant-ID` header (optional)
- All users implicitly have admin-level access

## RBAC Roles

Three roles, hierarchical:

| Role | Permissions |
|------|------------|
| `admin` | Full access: manage tenants, API keys, configuration, all data |
| `operator` | Send proxy traffic, view traces/findings/costs for own tenant |
| `viewer` | Read-only access to traces, findings, and costs for own tenant |

Roles are hierarchical: `admin` inherits `operator` permissions, `operator` inherits `viewer` permissions.

## Tenant Setup Walkthrough

### 1. Create a tenant

Using the bootstrap admin key:

```bash
curl -X POST http://localhost:8080/api/v1/tenants \
  -H "Authorization: Bearer your-bootstrap-admin-secret" \
  -H "Content-Type: application/json" \
  -d '{"name": "Acme Corp"}'
```

Response includes the tenant ID (UUID).

### 2. Create API keys for the tenant

```bash
curl -X POST http://localhost:8080/api/v1/auth/keys \
  -H "Authorization: Bearer your-bootstrap-admin-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "<tenant-uuid>",
    "name": "production-key",
    "role": "operator"
  }'
```

Response:

```json
{
  "id": "key-uuid",
  "key": "llmt_abc123...",
  "key_prefix": "llmt_abc123d...",
  "tenant_id": "<tenant-uuid>",
  "role": "operator",
  "created_at": "2026-01-15T10:30:00Z"
}
```

The plaintext key (`llmt_abc123...`) is shown **only once**. Store it securely.

### 3. Use the API key for proxy traffic

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer llmt_abc123..." \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"Hello"}]}'
```

The proxy resolves the tenant from the API key automatically. All traces, findings, and costs are scoped to that tenant.

### 4. List and revoke keys

```bash
# List keys for a tenant
curl http://localhost:8080/api/v1/auth/keys \
  -H "Authorization: Bearer your-bootstrap-admin-secret" \
  -H "X-LLMTrace-Tenant-ID: <tenant-uuid>"

# Revoke a key
curl -X DELETE http://localhost:8080/api/v1/auth/keys/<key-uuid> \
  -H "Authorization: Bearer your-bootstrap-admin-secret"
```

Revoked keys are immediately rejected on subsequent requests.

## Tenant Isolation

Each API key is bound to exactly one tenant. The tenant determines:

- Which traces, findings, and costs are visible
- Rate limiting quotas (if per-tenant overrides are configured)
- Cost caps (if per-agent budgets are configured)

A viewer or operator key for Tenant A cannot see data from Tenant B.

### Header-Based Tenant Tagging (Auth Disabled)

When auth is disabled, you can still tag requests with a tenant ID for data separation:

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "X-LLMTrace-Tenant-ID: <tenant-uuid>" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  ...
```

This provides logical separation but no authentication. Any client can claim any tenant ID.

## Agent Identification

Tag requests with an agent ID for per-agent cost tracking and budgets:

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "X-LLMTrace-Agent-ID: chatbot-v2" \
  -H "Authorization: Bearer llmt_abc123..." \
  ...
```

Agent IDs are arbitrary strings. They appear in cost breakdowns and can have per-agent daily budgets configured.

## Tenant Token Authentication

In addition to API keys, tenants can authenticate proxy traffic using their tenant token via the `X-LLMTrace-Token` header:

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "X-LLMTrace-Token: <tenant-api-token>" \
  -H "Content-Type: application/json" \
  ...
```

Tenant tokens grant `operator` level access and are useful for simpler setups where full API key management is not needed.

### Retrieving and Resetting Tokens

```bash
# Get current tenant's token
curl http://localhost:8080/api/v1/tenants/current/token \
  -H "Authorization: Bearer your-admin-key"

# Get a specific tenant's token (admin only)
curl http://localhost:8080/api/v1/tenants/<tenant-uuid>/token \
  -H "Authorization: Bearer your-admin-key"

# Reset a tenant's token
curl -X POST http://localhost:8080/api/v1/tenants/<tenant-uuid>/token/reset \
  -H "Authorization: Bearer your-admin-key"
```

## Tenant Management API

| Endpoint | Method | Role | Description |
|----------|--------|------|-------------|
| `/api/v1/tenants` | POST | admin | Create tenant |
| `/api/v1/tenants` | GET | admin | List tenants |
| `/api/v1/tenants/:id` | GET | admin | Get tenant details |
| `/api/v1/tenants/:id` | PUT | admin | Update tenant |
| `/api/v1/tenants/:id` | DELETE | admin | Delete tenant |
| `/api/v1/tenants/:id/token/reset` | POST | admin | Reset tenant token |
| `/api/v1/auth/keys` | POST | admin | Create API key |
| `/api/v1/auth/keys` | GET | admin | List API keys |
| `/api/v1/auth/keys/:id` | DELETE | admin | Revoke API key |

## Security Notes

- API keys are stored as SHA-256 hashes. The plaintext is never persisted.
- The bootstrap `admin_key` should be rotated after initial setup by creating a proper admin API key and removing `admin_key` from config.
- Key prefixes (first 12 characters) are stored for identification in logs and the dashboard.
- The `/health` and `/swagger-ui` endpoints are always accessible without authentication.
