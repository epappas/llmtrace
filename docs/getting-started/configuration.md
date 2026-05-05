# Configuration Guide

This document describes the actual configuration surface for `llmtrace-proxy` as implemented in this repository. The canonical reference is `config.example.yaml`.

## Configuration Sources and Precedence

**CLI flags**: `--config` (path to config file; can also be set via `LLMTRACE_CONFIG`)

   - `--log-level` (overrides `logging.level`)
   - `--log-format` (overrides `logging.format`)

**Environment variables**: `LLMTRACE_LISTEN_ADDR`

   - `LLMTRACE_UPSTREAM_URL`
   - `LLMTRACE_STORAGE_PROFILE`
   - `LLMTRACE_STORAGE_DATABASE_PATH`
   - `LLMTRACE_CLICKHOUSE_URL`
   - `LLMTRACE_CLICKHOUSE_DATABASE`
   - `LLMTRACE_POSTGRES_URL`
   - `LLMTRACE_REDIS_URL`
   - `LLMTRACE_LOG_LEVEL`
   - `LLMTRACE_LOG_FORMAT`

**Config file values**: **Built-in defaults** (only for fields with `#[serde(default)]` or `Default` in the schema)


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

## LLM Judge (Optional)

Adds an LLM-as-a-Judge detector alongside regex + DeBERTa. Requires
the `judge` feature (enabled by default). Disabled out of the box;
flip on at runtime via the admin feature-flag API
(`llm_judge_enabled`). Fail-open: a misbehaving judge never changes
request outcomes.

Full walkthrough (minimal configs, shadow rollout, metrics,
troubleshooting): see [LLM Judge Setup Guide](../guides/llm-judge.md).

```yaml
judge:
  enabled: false
  backend: cascade                # "cascade" | "deberta" | "openai" | "anthropic" | "vllm"

  # Cascade composes a fast tier (DeBERTa) with an optional slow tier
  # (any LLM-based backend). Set slow_backend: null to ship the fast
  # tier alone today; flip it on when you have a reasoned slow-judge.
  cascade:
    fast_backend: deberta
    slow_backend: null            # or "vllm" | "openai" | "anthropic"
    ambiguous_low: 0.3
    ambiguous_high: 0.7

  deberta:
    model_id: "protectai/deberta-v3-base-prompt-injection-v2"
    threshold: 0.5
    # cache_dir: "~/.cache/llmtrace/models"

  openai:
    base_url: "https://api.openai.com"  # any OpenAI-compatible gateway
    model: "gpt-4o-mini"
    max_tokens: 512
    temperature: 0.1
  anthropic:
    model: "claude-3-5-haiku-20241022"
    max_tokens: 512
    temperature: 0.1
  vllm:
    base_url: "http://localhost:8000"
    model: "security-judge-v1"
    max_tokens: 512
    temperature: 0.1
    allow_plaintext: false        # true only for loopback hosts

  worker:
    channel_buffer: 1000
    max_concurrency: 4
    timeout_ms: 30000
    max_analysis_text_bytes: 65536
    total_deadline_ms: 45000
  retry:
    max_retries: 2
    backoff_base_ms: 1000
  promotion:
    min_confidence: 0.7           # pre-calibration placeholder
    min_security_score: 60
    require_ensemble_support: true
    shadow: false                 # set true during initial rollout

  system_prompt: ""               # "" uses built-in hardened default
  min_score_threshold: 30         # only judge prompts with score >= 30
  persist_verdicts: true
```

API keys are read from environment variables at startup, never from
config files:

- `LLMTRACE_JUDGE_OPENAI_API_KEY` for `backend: openai`
- `LLMTRACE_JUDGE_ANTHROPIC_API_KEY` for `backend: anthropic`
- vLLM does not require a key

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

## Boundary Token Defense

Structural prevention for indirect prompt injection. Wraps untrusted tool message content with delimiter tags before forwarding to the upstream LLM. Reduces attack success rate by ~10x (BIPIA benchmark).

```yaml
boundary_defense:
  enabled: false          # opt-in (default: disabled)
  shadow_mode: false      # compute metrics but forward original bytes
  wrap_roles: ["tool"]    # message roles to wrap
  delimiter: "llmtrace-boundary"
  randomize_nonce: false  # random per-request nonce in tag name
  inject_system_reminder: true
  # system_reminder_text: "" # custom text (empty = built-in default)
```

When enabled, tool messages are transformed before forwarding:

```
Before: {"role": "tool", "content": "Paris is the capital of France."}
After:  {"role": "tool", "content": "<llmtrace-boundary>\nParis is the capital of France.\n</llmtrace-boundary>"}
```

A system prompt reminder is also injected telling the model to treat delimited content as untrusted data.

**Rollout recommendation:** Enable with `shadow_mode: true` first, monitor metrics for 24+ hours, then set `shadow_mode: false` to activate.

See [Boundary Token Defense Architecture](../architecture/BOUNDARY_TOKEN_DEFENSE.md) for full design details.

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
