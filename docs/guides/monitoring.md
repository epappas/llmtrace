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

### Core Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `llmtrace_requests_total` | Counter | `provider`, `model`, `status_code` | Total proxied LLM requests |
| `llmtrace_request_duration_seconds` | Histogram | `provider`, `model` | Request latency distribution |
| `llmtrace_tokens_total` | Counter | `direction`, `provider`, `model` | Total tokens (direction = `prompt` or `completion`) |
| `llmtrace_security_findings_total` | Counter | `severity`, `finding_type` | Security findings detected |
| `llmtrace_security_detector_latency_seconds` | Histogram | `detector` | Per-detector analysis latency |
| `llmtrace_circuit_breaker_state` | Gauge | `subsystem`, `state` | Circuit breaker state (1.0 = active state) |
| `llmtrace_storage_operations_total` | Counter | `operation`, `status` | Storage operations (status = `success` or `error`) |
| `llmtrace_cost_usd_total` | Counter | `tenant`, `model` | Estimated cost in micro-USD (divide by 1,000,000) |
| `llmtrace_anomalies_total` | Counter | `anomaly_type` | Anomalies detected |
| `llmtrace_active_connections` | Gauge | (none) | Current active connections |

### Boundary Defense Metrics

These metrics track the boundary token injection defense. They are emitted when `boundary_defense.enabled: true` in config, including in shadow mode.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `llmtrace_boundary_defense_applied_total` | Counter | `provider`, `mode` | Requests where defense was applied (`mode` = `active` or `shadow`) |
| `llmtrace_boundary_defense_messages_wrapped` | Histogram | `provider` | Number of tool messages wrapped per request |
| `llmtrace_boundary_defense_reminder_injected_total` | Counter | `provider` | Requests where system prompt reminder was injected |
| `llmtrace_boundary_defense_overhead_bytes` | Histogram | `provider` | Byte delta per request from boundary wrapping |
| `llmtrace_boundary_defense_errors_total` | Counter | `error_type` | Errors in boundary pipeline (`parse_failed`, `serialize_failed`) |
| `llmtrace_boundary_defense_skipped_total` | Counter | `reason` | Requests skipped (`disabled`, `no_tool_messages`, `unsupported_provider`) |
| `llmtrace_boundary_defense_shadow_mode` | Gauge | (none) | 1 when shadow mode is active, 0 otherwise |

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
llmtrace_circuit_breaker_state{state="open"}
```

**Boundary Defense -- Messages Wrapped / hour**:
```promql
sum(rate(llmtrace_boundary_defense_applied_total[5m])) by (provider, mode)
```

**Boundary Defense -- Error Rate**:
```promql
rate(llmtrace_boundary_defense_errors_total[5m])
```

### Alerting Thresholds

Suggested Grafana alert rules:

| Alert | Condition | Severity |
|-------|-----------|----------|
| High error rate | Error rate > 5% for 5 minutes | Critical |
| High latency | P95 > 5s for 5 minutes | Warning |
| Circuit breaker open | `llmtrace_circuit_breaker_state{state="open"} == 1` for > 30s | Critical |
| Security spike | Finding rate > 10/min for 5 minutes | Warning |
| Boundary defense errors | `rate(llmtrace_boundary_defense_errors_total[5m]) > 0` for 5 minutes | Warning |

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

LLMTrace integrates with external alerting via the [custom policies](custom-policies.md) system. Configure alert channels for Slack, PagerDuty, or generic webhooks:

```yaml
alerts:
  enabled: true
  channels:
    - type: slack
      url: "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
      min_severity: "Medium"
      min_security_score: 50
    - type: pagerduty
      routing_key: "your-pagerduty-key"
      min_severity: "Critical"
      min_security_score: 90
    - type: webhook
      url: "https://your-endpoint.com/alerts"
      min_severity: "High"
      min_security_score: 70
  cooldown_seconds: 300
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
