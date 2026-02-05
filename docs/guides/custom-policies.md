# Custom Policy Setup Guide

This guide covers how to configure LLMTrace's security policies, rate limiting, cost controls, alerting, and other operational features. Every option shown here corresponds to a real configuration field — copy the snippets directly into your `config.yaml`.

> **Quick links:** [Minimal config](../../examples/config-minimal.yaml) · [Production config](../../examples/config-production.yaml) · [High-security config](../../examples/config-high-security.yaml) · [Cost-control config](../../examples/config-cost-control.yaml)

---

## Table of Contents

1. [Configuration Basics](#configuration-basics)
2. [Security Analysis Policies](#security-analysis-policies)
3. [Rate Limiting](#rate-limiting)
4. [Cost Caps & Budgets](#cost-caps--budgets)
5. [Alert Channels](#alert-channels)
6. [Circuit Breaker](#circuit-breaker)
7. [Anomaly Detection](#anomaly-detection)
8. [Streaming Security Analysis](#streaming-security-analysis)
9. [PII Detection & Redaction](#pii-detection--redaction)
10. [Compliance Reporting](#compliance-reporting)
11. [OWASP LLM Top 10 Coverage](#owasp-llm-top-10-coverage)
12. [Putting It All Together](#putting-it-all-together)

---

## Configuration Basics

LLMTrace loads configuration from a YAML file. Settings can be overridden via environment variables or CLI flags.

**Precedence** (highest wins): CLI flags → environment variables → config file → defaults.

```bash
# Start with the example config
cp config.example.yaml config.yaml

# Validate before running
./target/release/llmtrace-proxy validate --config config.yaml

# Run the proxy
./target/release/llmtrace-proxy --config config.yaml
```

### Storage Profiles

Choose one of three storage profiles depending on your environment:

| Profile | Backend | Use Case |
|---------|---------|----------|
| `memory` | In-memory (lost on restart) | Testing, CI/CD |
| `lite` | SQLite | Development, single-node production |
| `production` | ClickHouse + PostgreSQL + Redis | Multi-node, high-throughput production |

```yaml
storage:
  profile: "lite"                # "memory", "lite", or "production"
  database_path: "llmtrace.db"  # Used by "lite" profile

  # Production profile requires all three:
  # clickhouse_url: "http://localhost:8123"
  # clickhouse_database: "llmtrace"
  # postgres_url: "postgres://llmtrace:llmtrace@localhost:5432/llmtrace"
  # redis_url: "redis://127.0.0.1:6379"
```

---

## Security Analysis Policies

LLMTrace provides regex-based security analysis by default. When the binary is built with the `ml` feature and ML is enabled in config, the proxy uses an ensemble analyzer that combines regex findings with ML classifiers.

### Regex-Based Detection (Default)

Regex analysis is enabled by a single toggle and requires no additional infrastructure:

```yaml
# Master toggle — enables the regex-based security engine
enable_security_analysis: true

# How long to wait for security analysis before falling back
# Set lower for latency-sensitive workloads, higher for thoroughness
security_analysis_timeout_ms: 5000
```

The regex engine detects a mix of prompt injection, role injection, jailbreak, and leakage patterns. Examples include:

| Category | Examples | Severity |
|----------|----------|----------|
| **Prompt injection** | "ignore previous instructions", "forget everything" | High |
| **Role injection** | `system:`, `assistant:` appearing in user messages | High/Medium |
| **Jailbreaks** | DAN-style patterns with "no restrictions" | Critical |
| **Encoding attacks** | Base64-encoded malicious instructions | High |
| **Delimiter injection** | `---system:`, `===instructions:` | High |
| **PII patterns** | Email, phone, SSN, credit card, IBAN, UK NIN | Medium |
| **Data leakage** | System prompt leaks, credential exposure | High/Critical |
| **Agent actions** | Dangerous commands, suspicious URLs, sensitive files | Critical/High |

No configuration is needed beyond `enable_security_analysis: true` — all patterns are compiled at startup.

### ML-Based Detection (Optional)

For higher accuracy and fewer false positives, enable ML-based detection. When `ml_preload: true`, the proxy loads HuggingFace models at startup and runs local inference alongside regex analysis. If `ml_preload` is set to `false`, the proxy currently stays in regex-only mode (ML models are not loaded lazily).

```yaml
security_analysis:
  # Enable ML prompt injection detection
  # Requires: binary built with `cargo build --features ml`
  ml_enabled: true

  # HuggingFace model for prompt injection classification
  # This DeBERTa v3 model is specifically trained for prompt injection
  ml_model: "protectai/deberta-v3-base-prompt-injection-v2"

  # Confidence threshold (0.0–1.0)
  # Lower = more sensitive (more detections, more false positives)
  # Higher = more specific (fewer detections, fewer false positives)
  # 0.8 is a good starting point; tune based on your false-positive tolerance
  ml_threshold: 0.8

  # Where to cache downloaded models (avoids re-downloading on restart)
  ml_cache_dir: "~/.cache/llmtrace/models"

  # Pre-load models at startup (recommended for production)
  # If false, first request incurs model download latency
  ml_preload: true

  # Timeout for model download at startup (seconds)
  # Large models (DeBERTa) can be ~500MB — give enough time on slow connections
  ml_download_timeout_seconds: 300

  # Enable NER-based PII detection for person names, organizations, locations
  # Catches PII that regex patterns miss (e.g., "John Smith lives in London")
  ner_enabled: true

  # HuggingFace model for Named Entity Recognition
  ner_model: "dslim/bert-base-NER"

  # Optional jailbreak classifier (runs alongside prompt injection)
  jailbreak_enabled: true
  jailbreak_threshold: 0.7

  # Optional feature-level fusion classifier (ADR-013)
  fusion_enabled: false
  fusion_model_path: null
```

**When to use ML detection:**
- You need to catch adversarial prompt injections that evade regex patterns
- You handle untrusted user input at scale
- You want NER-based PII detection for names and organizations (regex can only catch structured formats like emails/SSNs)

**When regex-only is sufficient:**
- Internal tools where inputs are semi-trusted
- You want zero external dependencies and minimal latency overhead
- Your primary concern is PII in structured formats

### Ensemble Behavior

When ML is enabled, LLMTrace uses the ensemble analyzer:
- Regex findings are always included.
- ML findings are added when the model is loaded successfully.
- Findings are merged and deduplicated; overlapping items include metadata such as `ensemble_agreement`.

---

## Rate Limiting

Rate limiting protects your LLM provider from excessive requests and prevents runaway agents from consuming your entire quota.

### Default Configuration

```yaml
rate_limiting:
  enabled: true

  # Sustained requests per second (across all tenants unless overridden)
  # 100 RPS is a safe starting point for most OpenAI plans
  requests_per_second: 100

  # Burst size — how many requests can fire in a quick burst
  # Set to 2x your RPS for bursty agent workloads
  # Set equal to RPS for smooth, predictable traffic
  burst_size: 200

  # Sliding window for rate calculation (seconds)
  window_seconds: 60
```

### Per-Tenant Overrides

Different tenants (teams, applications, environments) often need different limits:

```yaml
rate_limiting:
  enabled: true
  requests_per_second: 100   # Default for all tenants
  burst_size: 200
  window_seconds: 60

  # Override specific tenants by UUID
  tenant_overrides:
    # Production AI assistant — needs higher throughput
    "550e8400-e29b-41d4-a716-446655440001":
      requests_per_second: 500
      burst_size: 1000

    # Development/testing tenant — keep it low
    "550e8400-e29b-41d4-a716-446655440002":
      requests_per_second: 20
      burst_size: 40

    # Batch processing tenant — moderate steady, low burst
    "550e8400-e29b-41d4-a716-446655440003":
      requests_per_second: 200
      burst_size: 250
```

**How it works:**
- Requests exceeding the limit receive HTTP `429 Too Many Requests`
- The proxy includes `Retry-After` headers so well-behaved clients back off
- Tenant is identified via the `X-LLMTrace-Tenant-ID` header or API key derivation

### Choosing Values

| Scenario | RPS | Burst | Why |
|----------|-----|-------|-----|
| Single chatbot | 10–50 | 2× RPS | Human typing speed limits natural request rate |
| Agent swarm (10 agents) | 100–500 | 2× RPS | Agents fire requests concurrently |
| Batch embedding pipeline | 200–1000 | 1× RPS | Steady throughput, no burst needed |
| Rate-limited LLM plan | Match plan limit | +20% headroom | Prevent provider-side 429s |

---

## Cost Caps & Budgets

Cost caps prevent billing surprises by enforcing per-agent and per-tenant spending limits. When a budget is exceeded, requests are rejected **before** they reach the LLM provider.

### Basic Budget Setup

```yaml
cost_caps:
  enabled: true

  # Default budgets applied to all tenants/agents
  default_budget_caps:
    # Hourly cap: catch runaway loops quickly
    - window: hourly
      hard_limit_usd: 10.0    # Reject requests above this
      soft_limit_usd: 8.0     # Alert (but allow) above this

    # Daily cap: overall spending control
    - window: daily
      hard_limit_usd: 100.0
      soft_limit_usd: 80.0
```

### Soft vs Hard Limits

| Limit Type | Behavior | Use Case |
|------------|----------|----------|
| **Soft limit** | Triggers an alert but allows the request | Early warning — "you're spending fast" |
| **Hard limit** | Rejects the request with HTTP 429 | Hard stop — "no more spending this period" |

Set soft limits at ~80% of hard limits to give teams time to react before hitting the wall.

### Per-Request Token Caps

Prevent individual requests from consuming excessive tokens (useful for catching infinite loops or excessively long prompts):

```yaml
cost_caps:
  enabled: true

  default_token_cap:
    max_prompt_tokens: 8192       # Reject prompts longer than this
    max_completion_tokens: 4096   # Limit response length
    max_total_tokens: 16384       # Combined cap
```

### Per-Agent Overrides

Different agents have different cost profiles. Override budgets per agent using the `X-LLMTrace-Agent-ID` header:

```yaml
cost_caps:
  enabled: true

  default_budget_caps:
    - window: daily
      hard_limit_usd: 50.0

  agents:
    # Heavy research agent — needs a bigger budget
    - agent_id: "research-agent"
      budget_caps:
        - window: daily
          hard_limit_usd: 500.0
          soft_limit_usd: 400.0
        - window: hourly
          hard_limit_usd: 100.0
      token_cap:
        max_prompt_tokens: 16384
        max_completion_tokens: 8192

    # Simple Q&A bot — keep it tight
    - agent_id: "faq-bot"
      budget_caps:
        - window: daily
          hard_limit_usd: 10.0
          soft_limit_usd: 8.0
      token_cap:
        max_prompt_tokens: 2048
        max_completion_tokens: 1024
        max_total_tokens: 4096

    # Batch processing — weekly budget, no hourly limit
    - agent_id: "batch-embedder"
      budget_caps:
        - window: weekly
          hard_limit_usd: 1000.0
          soft_limit_usd: 800.0
```

### Budget Windows

| Window | Duration | Good For |
|--------|----------|----------|
| `hourly` | 1 hour rolling | Catching runaway loops quickly |
| `daily` | 24 hours rolling | Day-to-day budget control |
| `weekly` | 7 days rolling | Batch workloads with variable daily usage |
| `monthly` | 30 days rolling | Long-term budget planning |

### Custom Model Pricing

If you use fine-tuned or self-hosted models, add custom pricing so cost estimation is accurate:

```yaml
cost_estimation:
  enabled: true

  # Load pricing from an external file (hot-reloaded on SIGHUP)
  # pricing_file: "config/pricing.yaml"

  # Inline pricing overrides (per 1M tokens, in USD)
  custom_models:
    my-fine-tuned-gpt4:
      input_per_million: 5.0
      output_per_million: 10.0
    local-llama-70b:
      input_per_million: 0.0    # Self-hosted = no API cost
      output_per_million: 0.0
```

---

## Alert Channels

Alerts notify your team when security findings exceed configured thresholds. LLMTrace supports multiple simultaneous channels with independent severity filters.

### Single Channel (Legacy Mode)

The simplest setup — one webhook URL:

```yaml
alerts:
  enabled: true
  webhook_url: "https://hooks.slack.com/services/T00/B00/xxx"
  min_severity: "High"        # Only alert on High and Critical
  min_security_score: 70       # Minimum confidence score (0–100)
  cooldown_seconds: 300        # 5 minutes between duplicate alerts
```

### Multi-Channel Setup

For production, send different severity levels to different channels:

```yaml
alerts:
  enabled: true
  cooldown_seconds: 300    # Global deduplication window

  channels:
    # Slack: Medium and above — for the security team's awareness
    - type: slack
      url: "https://hooks.slack.com/services/T00/B00/xxx"
      min_severity: "Medium"
      min_security_score: 50

    # PagerDuty: Critical only — wake someone up
    - type: pagerduty
      routing_key: "your-pagerduty-events-v2-routing-key"
      min_severity: "Critical"
      min_security_score: 90

    # Custom webhook: High and above — for your SIEM or log aggregator
    - type: webhook
      url: "https://your-siem.internal/api/llm-alerts"
      min_severity: "High"
      min_security_score: 70
```

### Channel Types

| Type | Required Fields | Notes |
|------|----------------|-------|
| `slack` | `url` (Incoming Webhook URL) | Posts formatted Slack messages with finding details |
| `pagerduty` | `routing_key` (Events API v2) | Creates PagerDuty events |
| `webhook` | `url` (any HTTP endpoint) | POSTs a JSON payload with full finding data |
| `email` | _(none)_ | Accepted in config but currently skipped (not implemented) |

### Alert Severity Mapping

LLMTrace compares each finding's severity (`Info` → `Critical`) and confidence score (0–100) against the configured minimums. There is no fixed mapping between score and severity; both are emitted by the analyzers.

### Alert Deduplication

The `cooldown_seconds` setting prevents alert storms:

```yaml
alerts:
  cooldown_seconds: 300  # 5 minutes
```

This means: if the same finding type fires multiple times within 5 minutes, only the first alert is sent. This prevents a flood of identical alerts when an attacker probes your system repeatedly.

### Escalation (Not Implemented Yet)

The config schema includes an `alerts.escalation` block, but the proxy does not currently implement escalation behavior. Any escalation settings are ignored at runtime.

---

## Circuit Breaker

The circuit breaker degrades LLMTrace to a pure pass-through proxy when internal subsystems (storage, security analysis) fail repeatedly. This ensures your application keeps working even if LLMTrace's analysis layer has issues.

```yaml
circuit_breaker:
  enabled: true

  # Open the circuit after this many consecutive failures
  # Lower = faster degradation (more protective of upstream)
  # Higher = more tolerant of transient errors
  failure_threshold: 10

  # How long to wait before trying again (half-open state)
  # 30s is a good default; increase for slow-recovering backends
  recovery_timeout_ms: 30000

  # Number of probe requests in half-open state
  # If these succeed, the circuit closes and normal operation resumes
  half_open_max_calls: 3
```

### Circuit States

```
CLOSED (normal) → failures exceed threshold → OPEN (pass-through)
                                                    │
                                         recovery_timeout_ms
                                                    │
                                               HALF-OPEN
                                              (probe calls)
                                                 ╱     ╲
                                          success      failure
                                             │            │
                                          CLOSED        OPEN
```

### Tuning Guidelines

| Environment | `failure_threshold` | `recovery_timeout_ms` | Why |
|-------------|--------------------|-----------------------|-----|
| Development | 3 | 5000 | Fail fast, recover fast |
| Production (standard) | 10 | 30000 | Tolerate transient blips |
| Production (high-availability) | 5 | 60000 | Open quickly, recover cautiously |

---

## Anomaly Detection

Anomaly detection uses statistical analysis (moving averages and standard deviations) to identify unusual behavior per tenant — cost spikes, token spikes, velocity surges, and latency outliers.

```yaml
anomaly_detection:
  enabled: true

  # Sliding window size (number of recent observations)
  # Larger = more stable baseline, slower to react to real changes
  # Smaller = faster to react, but more false positives
  window_size: 100

  # Sigma threshold for anomaly flagging
  # 2.0 = ~5% false positive rate (aggressive)
  # 3.0 = ~0.3% false positive rate (balanced, recommended)
  # 4.0 = ~0.006% false positive rate (conservative)
  sigma_threshold: 3.0

  # Which dimensions to check
  check_cost: true       # Flag requests with abnormally high estimated cost
  check_tokens: true     # Flag requests with abnormally high token count
  check_velocity: true   # Flag tenants with abnormally high request rate
  check_latency: true    # Flag requests with abnormally high latency
```

### Anomaly Types

| Type | What It Detects | Typical Cause |
|------|----------------|---------------|
| `cost_spike` | Single request costs much more than the tenant's average | Runaway prompt, model upgrade without budget adjustment |
| `token_spike` | Unusually high token count for a single request | Prompt injection inflating context, copy-paste of large documents |
| `velocity_spike` | Tenant is sending requests much faster than usual | Automated loop, DDoS-like behavior, misconfigured retry logic |
| `latency_spike` | Response taking much longer than typical | Provider degradation, overly complex prompt, model overload |

### Choosing Window Size and Sigma

```
                    Sigma Threshold
                 2.0      3.0      4.0
              ┌────────┬────────┬────────┐
   Window 50  │ Noisy  │  OK    │ Quiet  │
   Window 100 │  OK    │ Best   │  OK    │
   Window 200 │ Good   │  OK    │ Slow   │
              └────────┴────────┴────────┘
```

Start with `window_size: 100` and `sigma_threshold: 3.0`. Adjust based on your false-positive tolerance.

---

## Streaming Security Analysis

For streaming responses (SSE), LLMTrace can run incremental security checks **during** the stream rather than waiting for completion. This provides early warning when a response starts leaking sensitive data mid-stream.

```yaml
# Must also have streaming enabled
enable_streaming: true

streaming_analysis:
  enabled: true

  # Check every N tokens during the stream
  # Lower = faster detection, marginally more CPU
  # Higher = less overhead, slower detection
  # 50 is a good balance for most workloads
  token_interval: 50

  # Enable output-side checks (PII/secrets/toxicity) on streaming content
  output_enabled: true

  # If a critical finding is detected mid-stream, inject a warning and stop
  early_stop_on_critical: true
```

**How it works:**
1. As SSE chunks arrive, the proxy accumulates tokens
2. Every `token_interval` tokens, it runs lightweight regex pattern matching on the accumulated content (streaming analysis uses regex only)
3. If a critical finding is detected mid-stream, an alert fires immediately (doesn't wait for stream completion)
4. After the stream completes, full analysis runs on the complete response

**Note:** Output-side streaming checks require `output_safety.enabled: true` in addition to `streaming_analysis.output_enabled`.

**When to enable:**
- Long-running streaming responses (creative writing, code generation)
- High-security environments where early detection matters
- When you want real-time alerts, not post-hoc analysis

---

## PII Detection & Redaction

Beyond detecting PII, LLMTrace can optionally **redact** it inside the security analyzer output. The proxy does **not** currently replace upstream responses or stored traces with redacted text — redaction is available for downstream processing and future pipeline use.

```yaml
pii:
  # "alert_only"       — Detect and report PII, but don't modify text (default)
  # "alert_and_redact" — Detect, report, AND replace PII with [PII:TYPE] tags
  # "redact_silent"    — Redact PII silently without generating findings
  action: "alert_only"
```

### PII Types Detected

| Type | Pattern | Example | Confidence |
|------|---------|---------|------------|
| `email` | Standard email format | `user@example.com` | 0.90 |
| `phone_number` | US formats | `555-123-4567`, `(555) 123-4567` | 0.85 |
| `ssn` | US Social Security Number | `456-78-9012` | 0.95 |
| `credit_card` | 16-digit card numbers | `4111 1111 1111 1111` | 0.90 |
| `uk_nin` | UK National Insurance Number | `AB 12 34 56 C` | 0.90 |
| `iban` | International Bank Account Number | `DE89 3704 0044 0532 0130 00` | 0.85 |
| `eu_passport_de` | German passport | `C01X00T2Z` | 0.60 |
| `eu_passport_fr` | French passport | `12AB34567` | 0.65 |
| `eu_passport_it` | Italian passport | `AA1234567` | 0.60 |
| `eu_passport_es` | Spanish passport | `ABC123456` | 0.60 |
| `eu_passport_nl` | Dutch passport | `NX1A2B3C4` | 0.60 |
| `intl_phone` | International phone numbers | `+44 20 7946 0958` | 0.80 |
| `nhs_number` | UK NHS number | `943 476 5919` | 0.70 |
| `canadian_sin` | Canadian Social Insurance Number | `046-454-286` | 0.80 |
| `australian_tfn` | Australian Tax File Number | `123 456 789` | 0.70 |

### False Positive Suppression

LLMTrace automatically suppresses PII matches that are likely false positives:
- Matches inside fenced code blocks (`` ``` ``)
- Matches on indented code lines (4+ spaces)
- Matches inside URLs
- Well-known placeholder values (e.g., `123-45-6789`, all-zeros)

### Redaction Example

With `action: "alert_and_redact"`, the text:
```
Contact John at john@example.com or call 555-123-4567
```
Becomes:
```
Contact John at [PII:EMAIL] or call [PII:PHONE_NUMBER]
```

---

## Compliance Reporting

LLMTrace generates compliance reports (SOC2, GDPR, HIPAA) from stored audit events and trace data. Reports are persisted in the metadata repository and can be retrieved via the API.

### How Reports Work

1. **Audit events** are recorded for tenant and API key operations (and report generation)
2. **Reports** aggregate audit events and trace data over a time period into a structured compliance document
3. **Storage**: Reports are stored as JSON in the metadata repository (SQLite or PostgreSQL)

### Report Types

| Type | Standard | What It Covers |
|------|----------|----------------|
| `soc2` | SOC 2 Type II | Audit trail of all operations, access control events, security findings |
| `gdpr` | GDPR | Data processing activity records, PII detection events, data retention compliance |
| `hipaa` | HIPAA | Audit logs for healthcare data, access tracking, security incident records |

### Enabling Audit Trail

Audit events are generated automatically when trace storage is enabled. For complete compliance coverage, ensure:

```yaml
# Recommended: traces must be stored to include trace data in reports
enable_trace_storage: true

# Optional: security analysis adds findings that enrich reports
enable_security_analysis: true

# Recommended: production storage for durable audit trail
storage:
  profile: "production"
  postgres_url: "postgres://llmtrace:llmtrace@localhost:5432/llmtrace"

  # Disable auto-migrate in production — run migrations explicitly
  auto_migrate: false
```

---

## OWASP LLM Top 10 Coverage

LLMTrace includes built-in tests mapped to the [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/). The current test suite covers the following categories:

### Coverage Summary (Tests Present)

| OWASP ID | Category | Tests |
|----------|----------|-------|
| **LLM01** | Prompt Injection | ✅ |
| **LLM02** | Insecure Output Handling | ✅ |
| **LLM06** | Sensitive Information Disclosure | ✅ |
| **LLM07** | Insecure Plugin Design | ✅ |

Other OWASP categories are not currently covered by tests in this repo.

### Running OWASP Tests

```bash
# All OWASP tests
cargo test --test owasp_llm_top10

# Specific category
cargo test --test owasp_llm_top10 owasp_llm01   # Prompt Injection
cargo test --test owasp_llm_top10 owasp_llm06   # PII Detection
cargo test --test owasp_llm_top10 owasp_llm07   # Agent Action Analysis
```

For detailed coverage breakdown, see [docs/security/OWASP_LLM_TOP10.md](../security/OWASP_LLM_TOP10.md).

---

## Putting It All Together

The example configurations in the [`examples/`](../../examples/) directory show complete, ready-to-use setups:

| Config | Use Case | Key Features |
|--------|----------|--------------|
| [`config-minimal.yaml`](../../examples/config-minimal.yaml) | Getting started | SQLite, regex security, basic rate limits |
| [`config-production.yaml`](../../examples/config-production.yaml) | Full production | ClickHouse + Postgres + Redis, all features, multi-channel alerts |
| [`config-high-security.yaml`](../../examples/config-high-security.yaml) | Maximum security | ML detection, streaming analysis, strict limits, PagerDuty escalation |
| [`config-cost-control.yaml`](../../examples/config-cost-control.yaml) | Cost management | Tight budgets, per-agent caps, cost anomaly alerts |

### Recommended Rollout Order

1. **Start with minimal** — Get the proxy running with `config-minimal.yaml`
2. **Add alerting** — Connect Slack/webhook so you see what's happening
3. **Enable cost caps** — Prevent billing surprises
4. **Tune rate limits** — Adjust per-tenant based on observed traffic
5. **Enable anomaly detection** — After you have ~100 requests of baseline data
6. **Consider ML detection** — If you handle untrusted user input
7. **Enable streaming analysis** — For long-running streaming responses
8. **Set up compliance** — When you need SOC2/GDPR/HIPAA audit trails

### Environment Variable Quick Reference

| Variable | Overrides | Example |
|----------|-----------|---------|
| `LLMTRACE_LISTEN_ADDR` | `listen_addr` | `0.0.0.0:9090` |
| `LLMTRACE_UPSTREAM_URL` | `upstream_url` | `http://localhost:11434` |
| `LLMTRACE_STORAGE_PROFILE` | `storage.profile` | `production` |
| `LLMTRACE_STORAGE_DATABASE_PATH` | `storage.database_path` | `/var/lib/llmtrace/traces.db` |
| `LLMTRACE_CLICKHOUSE_URL` | `storage.clickhouse_url` | `http://clickhouse:8123` |
| `LLMTRACE_CLICKHOUSE_DATABASE` | `storage.clickhouse_database` | `llmtrace` |
| `LLMTRACE_POSTGRES_URL` | `storage.postgres_url` | `postgres://user:pass@pg:5432/llmtrace` |
| `LLMTRACE_REDIS_URL` | `storage.redis_url` | `redis://redis:6379` |
| `LLMTRACE_LOG_LEVEL` | `logging.level` (via CLI env) | `debug` |
| `LLMTRACE_LOG_FORMAT` | `logging.format` (via CLI env) | `json` |
| `RUST_LOG` | Fine-grained tracing | `llmtrace_proxy=debug,info` |
