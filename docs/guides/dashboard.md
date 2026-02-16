# Dashboard Usage Guide

LLMTrace includes a built-in Next.js dashboard for visualizing traces, security findings, costs, and tenant management.

## Starting the Dashboard

### With Docker Compose

```bash
docker compose up -d
# Dashboard available at http://localhost:3000
```

### Manual Start (Development)

```bash
cd dashboard
npm install
npm run dev
# Dashboard available at http://localhost:3000
```

### Remote Access

To expose the dashboard remotely (e.g., for team access), use ngrok or a similar tunnel:

```bash
ngrok http 3000
```

## Proxy URL Configuration

The dashboard needs to know where the LLMTrace proxy is running. Configure the proxy URL in the **Settings** page, or set the environment variable before starting:

```bash
NEXT_PUBLIC_PROXY_URL=http://localhost:8080 npm run dev
```

## Dashboard Pages

### Traces

The main traces view shows recent LLM interactions:

- Request and response content
- Model, token count, latency
- Tenant and agent identifiers
- Links to associated security findings

Use filters to narrow by model, tenant, time range, or trace ID.

### Security Findings

Lists all security findings across tenants:

- Finding type (prompt injection, jailbreak, PII, etc.)
- Severity and confidence score
- Voting result (majority vs. single detector)
- Associated trace ID

Filter by severity, finding type, or time range to focus on specific threat categories.

### Costs

Cost tracking and breakdown:

- Total spend by time period
- Per-model cost breakdown
- Per-agent cost breakdown
- Per-tenant cost isolation

### Tenants

Tenant management (requires admin access):

- List all tenants
- Create new tenants
- View tenant details and configuration
- Manage API keys per tenant

### Compliance

Generate and view compliance reports:

- OWASP LLM Top 10 coverage reports
- Audit trail of security events
- Exportable reports for compliance review

### Settings

Dashboard configuration:

- Proxy URL setting
- **Swagger UI** access -- the Settings page provides a link to the interactive API documentation served by the proxy at `/swagger-ui`

## Multi-Tenant Filtering

When authenticated as an admin, the dashboard shows data across all tenants. Use the tenant filter to scope views to a specific tenant.

When authenticated with a tenant-scoped key (operator or viewer), the dashboard automatically restricts all views to that tenant's data.
