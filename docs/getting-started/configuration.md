# Configuration Guide

This document describes the actual configuration surface for `llmtrace-proxy` as implemented in this repository. The canonical reference is `config.example.yaml`.

## Configuration Sources and Precedence

1. **CLI flags**
   - `--config` (path to config file; can also be set via `LLMTRACE_CONFIG`)
   - `--log-level` (overrides `logging.level`)
   - `--log-format` (overrides `logging.format`)
2. **Environment variables**
   - `LLMTRACE_LISTEN_ADDR`
   - `LLMTRACE_UPSTREAM_URL`
   - `LLMTRACE_STORAGE_PROFILE`
   - `LLMTRACE_STORAGE_DATABASE_PATH`
   - `LLMTRACE_CLICKHOUSE_URL`
   - `LLMTRACE_CLICKHOUSE_DATABASE`
   - `LLMTRACE_POSTGRES_URL`
   - `LLMTRACE_REDIS_URL`
   - `LLMTRACE_LOG_LEVEL`
   - `LLMTRACE_LOG_FORMAT`
3. **Config file values**
4. **Built-in defaults** (only for fields with `#[serde(default)]` or `Default` in the schema)

## Minimal Config (Valid)

This matches the minimal structure accepted by the current config loader:

```yaml
listen_addr: "0.0.0.0:8080"
upstream_url: "https://api.openai.com"
timeout_ms: 30000
connection_timeout_ms: 5000
max_connections: 1000
enable_tls: false
enable_security_analysis: true
enable_trace_storage: true
enable_streaming: true
max_request_size_bytes: 52428800
security_analysis_timeout_ms: 5000
trace_storage_timeout_ms: 10000
rate_limiting:
  enabled: true
  requests_per_second: 100
  burst_size: 200
  window_seconds: 60
circuit_breaker:
  enabled: true
  failure_threshold: 10
  recovery_timeout_ms: 30000
  half_open_max_calls: 3
health_check:
  enabled: true
  path: "/health"
  interval_seconds: 10
  timeout_ms: 5000
  retries: 3
```

If you want a full example with all optional sections, copy `config.example.yaml`.

## Storage Profiles

```yaml
storage:
  profile: "lite" # or "memory" or "production"
  database_path: "llmtrace.db"
  # production-only fields:
  # clickhouse_url: "http://localhost:8123"
  # clickhouse_database: "llmtrace"
  # postgres_url: "postgres://llmtrace:llmtrace@localhost:5432/llmtrace"
  # redis_url: "redis://127.0.0.1:6379"
  auto_migrate: true
```

## Security Analysis and Streaming

```yaml
enable_security_analysis: true

streaming_analysis:
  enabled: false
  token_interval: 50
  output_enabled: false
  early_stop_on_critical: false
```

## Output Safety

```yaml
output_safety:
  enabled: false
  toxicity_enabled: false
  toxicity_threshold: 0.7
  block_on_critical: false
  hallucination_enabled: false
  hallucination_model: "vectara/hallucination_evaluation_model"
  hallucination_threshold: 0.5
  hallucination_min_response_length: 50
```

## ML-Based Prompt Injection Detection (Optional)

Only available when the proxy is compiled with the `ml` feature.

```yaml
security_analysis:
  ml_enabled: false
  ml_model: "protectai/deberta-v3-base-prompt-injection-v2"
  ml_threshold: 0.8
  ml_cache_dir: "~/.cache/llmtrace/models"
  ml_preload: true
  ml_download_timeout_seconds: 300
  ner_enabled: false
  ner_model: "dslim/bert-base-NER"
  jailbreak_enabled: true
  jailbreak_threshold: 0.7
```

## Alerts

```yaml
alerts:
  enabled: false
  # legacy single-webhook mode (only if channels is empty)
  # webhook_url: "https://hooks.slack.com/services/..."
  # min_severity: "High"
  # min_security_score: 70

  channels: []
  # - type: slack
  #   url: "https://hooks.slack.com/services/..."
  #   min_severity: "Medium"
  #   min_security_score: 50
  # - type: pagerduty
  #   routing_key: "your-routing-key"
  #   min_severity: "Critical"
  #   min_security_score: 90

  cooldown_seconds: 300
  # escalation:
  #   enabled: false
  #   escalate_after_seconds: 600
```

Note: `email` channels are recognized in config but are not implemented yet.

## Cost Estimation and Cost Caps

```yaml
cost_estimation:
  enabled: true
  # pricing_file: "config/pricing.yaml"
  # custom_models:
  #   my-model:
  #     input_per_million: 5.0
  #     output_per_million: 10.0

cost_caps:
  enabled: false
  default_budget_caps:
    - window: hourly
      hard_limit_usd: 10.0
      soft_limit_usd: 8.0
  # default_token_cap:
  #   max_prompt_tokens: 8192
  #   max_completion_tokens: 4096
```

## Auth (API Keys)

```yaml
auth:
  enabled: false
  # admin_key: "llmt_bootstrap_secret"
```

## OTLP/HTTP and gRPC Ingest

```yaml
otel_ingest:
  enabled: true

grpc:
  enabled: false
  listen_addr: "0.0.0.0:50051"
```

## Health Checks and Shutdown

```yaml
health_check:
  enabled: true
  path: "/health"
  interval_seconds: 10
  timeout_ms: 5000
  retries: 3

shutdown:
  timeout_seconds: 30
```

## Validate Your Config

```bash
llmtrace-proxy validate --config config.yaml
```

If validation fails, the error message lists all missing or invalid fields.
