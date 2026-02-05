# API Guide

This guide combines the REST query API and the proxy integration examples. It is audited against the current `llmtrace-proxy` routes and response shapes.

## Base URL

```
http://localhost:8080
```

REST endpoints are under `/api/v1`. Proxy traffic is forwarded to the upstream model provider at the same paths you would normally call.

## Authentication

If auth is enabled, pass an API key in the `Authorization` header:

```bash
curl -H "Authorization: Bearer llmt_..." http://localhost:8080/api/v1/traces
```

Roles:
- `viewer`: read-only access to traces, spans, stats, security findings, costs, and reports.
- `operator`: can also report agent actions and generate compliance reports.
- `admin`: can manage API keys and tenants.

If auth is disabled, all endpoints are accessible without a key.

## Request Headers

Optional headers recognized by the proxy:
- `X-LLMTrace-Tenant-ID`: UUID for tenant isolation. If missing or invalid, tenant ID is derived from the API key (or defaults when auth is disabled).
- `X-LLMTrace-Agent-ID`: Agent identifier used for cost caps and spend snapshots.
- `X-LLMTrace-Provider`: Force provider detection (`openai`, `anthropic`, `ollama`, `bedrock`, etc.).

## Health & Metrics

### GET /health

Health probe. Returns `503` while starting, `200` when healthy or degraded.

```bash
curl http://localhost:8080/health
```

### GET /metrics

Prometheus/OpenMetrics endpoint.

```bash
curl http://localhost:8080/metrics
```

## Proxy Integration (LLM Requests)

LLMTrace is a transparent proxy. Any path not handled by the REST API is forwarded upstream. Common OpenAI-compatible paths:
- `/v1/chat/completions`
- `/v1/completions`
- `/v1/embeddings`

Anthropic-style path detection:
- `/v1/messages`

Ollama-style path detection:
- `/api/generate`, `/api/chat`, `/api/tags`, `/api/embeddings`

### Chat Completions (non-streaming)

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {"role": "system", "content": "You are a helpful assistant."},
      {"role": "user", "content": "What is the capital of France?"}
    ],
    "temperature": 0.7,
    "max_tokens": 100
  }'
```

### Chat Completions (streaming)

```bash
curl -N http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {"role": "user", "content": "Write a short story about a robot."}
    ],
    "stream": true,
    "max_tokens": 200
  }'
```

### Embeddings

```bash
curl http://localhost:8080/v1/embeddings \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{
    "model": "text-embedding-ada-002",
    "input": ["Your text", "Another text"]
  }'
```

## REST Query API

### GET /api/v1/traces

List traces with optional filters (paginated).

Query parameters:
- `start_time` (RFC3339)
- `end_time` (RFC3339)
- `provider`
- `model`
- `limit` (default 50, max 1000)
- `offset` (default 0)

```bash
curl "http://localhost:8080/api/v1/traces?limit=10&offset=0"
```

### GET /api/v1/traces/:trace_id

Get a single trace with all spans.

```bash
curl http://localhost:8080/api/v1/traces/7aa2c9b2-1fb1-4d64-9a4f-0c19c7f0a2b1
```

### GET /api/v1/spans

List spans with optional filters (paginated).

Query parameters:
- `security_score_min` (0-100)
- `security_score_max` (0-100)
- `operation_name`
- `model`
- `limit` (default 50, max 1000)
- `offset` (default 0)

```bash
curl "http://localhost:8080/api/v1/spans?security_score_min=1"
```

### GET /api/v1/spans/:span_id

Get a single span.

### GET /api/v1/security/findings

Returns spans with `security_score > 0` (paginated). Security findings are embedded in each span as `security_findings`.

Query parameters:
- `limit` (default 50, max 1000)
- `offset` (default 0)

### GET /api/v1/stats

Storage statistics for the tenant.

### GET /api/v1/costs/current

Current spend snapshot across configured budget windows. Returns `404` if cost caps are disabled.

Query parameters:
- `agent_id` (optional)

### POST /api/v1/traces/:trace_id/actions

Report a client-side agent action (operator role required).

```bash
curl -X POST http://localhost:8080/api/v1/traces/7aa2c9b2-1fb1-4d64-9a4f-0c19c7f0a2b1/actions \
  -H "Content-Type: application/json" \
  -d '{
    "action_type": "tool_call",
    "name": "search",
    "arguments": "{\"q\":\"test\"}",
    "success": true
  }'
```

### GET /api/v1/actions/summary

Aggregate summary of agent actions (viewer role required). Accepts the same filters as `GET /api/v1/spans` (`model`, `operation_name`).

### Tenant Management (admin)

- `POST /api/v1/tenants`
- `GET /api/v1/tenants`
- `GET /api/v1/tenants/:id`
- `PUT /api/v1/tenants/:id`
- `DELETE /api/v1/tenants/:id`

### API Keys (admin)

- `POST /api/v1/auth/keys`
- `GET /api/v1/auth/keys`
- `DELETE /api/v1/auth/keys/:id`

### Compliance Reports

- `POST /api/v1/reports/generate` (operator)
- `GET /api/v1/reports` (viewer)
- `GET /api/v1/reports/:id` (viewer)

## OTLP/HTTP Ingest

### POST /v1/traces

OpenTelemetry OTLP/HTTP trace ingestion endpoint.

## Error Handling

Errors use:

```json
{
  "error": {
    "message": "Human-readable message",
    "type": "api_error"
  }
}
```

Rate limiting and cost caps use specific `type` values:
- `rate_limit_exceeded`
- `cost_cap_exceeded`

## Notes

- Proxy responses are passed through from the upstream provider. LLMTrace does not wrap those responses.
- `trace_id` and `span_id` are UUIDs. Invalid UUIDs return `404` or `400` depending on the handler.
- For streaming responses, LLMTrace can inject an early-stop SSE chunk when critical output findings are detected (requires `streaming_analysis.output_enabled` and `output_safety.enabled`). This appears as `finish_reason: "content_filter"` with a warning message.
- Security findings are stored on spans. Use `GET /api/v1/security/findings` or inspect `security_findings` in spans and traces.
- Tenant ID defaults to a deterministic UUID v5 derived from the API key when `X-LLMTrace-Tenant-ID` is not provided; if no API key is present, a default tenant is used.

## Next Steps

- **[gRPC API Documentation](grpc-api.md)**
- **[OpenAI SDK Integration](integration-openai.md)**
- **[Custom Policies](custom-policies.md)**
