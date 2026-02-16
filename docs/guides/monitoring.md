# Monitoring & Observability Guide

LLMTrace exposes Prometheus metrics, a health endpoint, and structured logging for production monitoring.

## Health Endpoint

```bash
curl http://localhost:8080/health | jq
```

The `/health` endpoint returns:

- **status**: `healthy` or `degraded`
- **storage**: storage backend connectivity status
- **circuit_breaker**: current circuit breaker state (`closed`, `open`, `half_open`)
- **ml_models**: ML model loading status
- **uptime**: proxy uptime in seconds

Use this for Kubernetes liveness/readiness probes:

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 15

readinessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
```

## Prometheus Metrics

```bash
curl http://localhost:8080/metrics
```

The `/metrics` endpoint returns metrics in Prometheus exposition format.

### Key Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `llmtrace_requests_total` | Counter | Total proxy requests by status code |
| `llmtrace_request_duration_seconds` | Histogram | Request latency distribution |
| `llmtrace_tokens_total` | Counter | Total tokens processed (prompt + completion) |
| `llmtrace_security_findings_total` | Counter | Security findings by type and severity |
| `llmtrace_circuit_breaker_state` | Gauge | Circuit breaker state (0=closed, 1=half-open, 2=open) |
| `llmtrace_active_connections` | Gauge | Current active connections |
| `llmtrace_upstream_errors_total` | Counter | Upstream provider errors |

### Prometheus Scrape Config

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'llmtrace'
    scrape_interval: 15s
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: /metrics
```

## Grafana Dashboard Setup

### Common Panels

**Request Rate**:
```promql
rate(llmtrace_requests_total[5m])
```

**P95 Latency**:
```promql
histogram_quantile(0.95, rate(llmtrace_request_duration_seconds_bucket[5m]))
```

**Error Rate**:
```promql
rate(llmtrace_requests_total{status=~"5.."}[5m]) / rate(llmtrace_requests_total[5m])
```

**Security Findings Rate**:
```promql
rate(llmtrace_security_findings_total[5m])
```

**Circuit Breaker State**:
```promql
llmtrace_circuit_breaker_state
```

### Alerting Thresholds

Suggested Grafana alert rules:

| Alert | Condition | Severity |
|-------|-----------|----------|
| High error rate | Error rate > 5% for 5 minutes | Critical |
| High latency | P95 > 5s for 5 minutes | Warning |
| Circuit breaker open | State = 2 for > 30s | Critical |
| Security spike | Finding rate > 10/min for 5 minutes | Warning |

## Logging

### Log Levels

Set via environment variable or config:

```bash
RUST_LOG=info ./target/release/llmtrace-proxy --config config.yaml
```

```yaml
logging:
  level: "info"    # error | warn | info | debug | trace
  format: "text"   # text | json
```

- **error**: only critical failures
- **warn**: degraded operations (circuit breaker trips, timeouts)
- **info**: request summaries, security findings, startup/shutdown
- **debug**: detailed request/response logging, threshold filtering decisions
- **trace**: full request bodies, ML inference details (high volume)

### Structured JSON Logs

For production log aggregation (ELK, Datadog, etc.), use JSON format:

```yaml
logging:
  level: "info"
  format: "json"
```

Output:
```json
{"timestamp":"2026-01-15T10:30:00Z","level":"INFO","target":"llmtrace_proxy","message":"request completed","trace_id":"abc123","status":200,"latency_ms":142}
```

## Alerting Integration

LLMTrace integrates with external alerting via the [custom policies](custom-policies.md) system. Configure webhook endpoints for Slack, PagerDuty, or generic HTTP:

```yaml
alerts:
  slack:
    webhook_url: "https://hooks.slack.com/services/..."
  pagerduty:
    routing_key: "your-pagerduty-key"
  webhook:
    url: "https://your-endpoint.com/alerts"
```

See [Custom Security Policies](custom-policies.md) for full alerting configuration.

## Circuit Breaker

The proxy includes a circuit breaker that degrades to pure pass-through on repeated failures:

```yaml
circuit_breaker:
  enabled: true
  failure_threshold: 10       # failures before opening
  recovery_timeout_ms: 30000  # time in open state before half-open
  half_open_max_calls: 3      # test calls in half-open state
```

States:
- **Closed**: normal operation, all features active
- **Open**: storage/security failures exceeded threshold; proxy passes traffic through without analysis
- **Half-Open**: testing recovery with limited calls

Monitor via the `/health` endpoint or the `llmtrace_circuit_breaker_state` Prometheus metric.
