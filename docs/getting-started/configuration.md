# Configuration Guide

LLMTrace is highly configurable to fit your security, performance, and operational needs. This guide covers the most common configuration scenarios with copy-paste examples.

## Quick Start Configs

| Use Case | Config File | Description |
|----------|-------------|-------------|
| **Development**| [config-minimal.yaml](#minimal-config) | SQLite + basic security |
| **Production**| [config-production.yaml](#production-config) | PostgreSQL + full features |
| **High Security**| [config-security.yaml](#security-focused) | Maximum protection |
| **Cost Control**| [config-cost.yaml](#cost-control) | Budget limits + alerts |

## Configuration Sources

LLMTrace loads configuration from multiple sources in this order (highest priority wins):

1. **CLI flags:**`--upstream-url`, `--listen-addr`
2. **Environment variables:**`LLMTRACE_*`
3. **Config file:**`config.yaml`
4. **Defaults:** Built-in sensible defaults

```bash
# Example: Override config file settings
LLMTRACE_UPSTREAM_URL=http://localhost:11434 \
LLMTRACE_LOG_LEVEL=debug \
llmtrace-proxy --config config.yaml --listen-addr 0.0.0.0:9080
```

## Minimal Config

Perfect for development and small deployments:

```yaml
# config-minimal.yaml
upstream_url: "https://api.openai.com"
listen_addr: "0.0.0.0:8080"

# Use SQLite - simple and reliable
storage:
  profile: "lite"
  database_path: "./llmtrace.db"

# Basic security analysis
security:
  enable_prompt_injection_detection: true
  enable_pii_detection: true

# Simple logging
logging:
  level: "info"
  format: "pretty"
```

**Usage:**
```bash
curl -o config.yaml https://raw.githubusercontent.com/epappas/llmtrace/main/examples/config-minimal.yaml
llmtrace-proxy --config config.yaml
```

## Production Config

For production deployments with full observability:

```yaml
# config-production.yaml
upstream_url: "https://api.openai.com"
listen_addr: "0.0.0.0:8080"

# Production storage backends
storage:
  profile: "production"

  # PostgreSQL for structured data
  postgres_url: "postgresql://llmtrace:password@postgres:5432/llmtrace"

  # ClickHouse for high-volume analytics
  clickhouse_url: "http://clickhouse:8123"
  clickhouse_database: "llmtrace"

  # Redis for caching and rate limiting
  redis_url: "redis://redis:6379"

# Enhanced security analysis
security:
  enable_prompt_injection_detection: true
  enable_pii_detection: true
  enable_data_leakage_detection: true
  enable_streaming_analysis: true

  # Custom security rules
  prompt_injection:
    sensitivity: "high"
    custom_patterns:
      - "ignore.*previous.*instructions"
      - "system.*prompt.*override"

  pii_detection:
    types: ["email", "phone", "ssn", "credit_card"]
    redaction_enabled: true

# Rate limiting
rate_limiting:
  enabled: true
  requests_per_minute: 1000
  burst_capacity: 2000

  # Per-tenant limits
  per_tenant:
    requests_per_minute: 100
    burst_capacity: 200

# Cost controls
cost_control:
  enabled: true
  daily_budget_usd: 1000.0

  # Per-agent budgets
  per_agent_daily_budget_usd: 100.0

  # Token limits
  max_prompt_tokens: 4000
  max_completion_tokens: 2000

# Multi-channel alerting
alerts:
  # Slack integration
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
    channel: "#llm-alerts"
    mention_users: ["@security-team"]

  # PagerDuty for critical issues
  pagerduty:
    enabled: true
    integration_key: "your-pagerduty-key"

  # Email alerts
  email:
    enabled: true
    smtp_host: "smtp.company.com"
    smtp_port: 587
    from_address: "llmtrace@company.com"
    to_addresses: ["security@company.com", "devops@company.com"]

# Anomaly detection
anomaly_detection:
  enabled: true

  # Cost anomalies
  cost:
    threshold_multiplier: 2.0
    window_minutes: 60

  # Token usage anomalies
  tokens:
    threshold_multiplier: 3.0
    window_minutes: 30

  # Request velocity anomalies
  velocity:
    threshold_multiplier: 5.0
    window_minutes: 15

# Structured logging
logging:
  level: "info"
  format: "json"

  # Log sampling for high-volume environments
  sampling:
    enabled: true
    rate: 0.1  # Log 10% of requests

# Monitoring
monitoring:
  # Prometheus metrics
  prometheus:
    enabled: true
    listen_addr: "0.0.0.0:9090"

  # Health check configuration
  health_check:
    timeout_seconds: 5
    storage_check: true
    upstream_check: true

# Circuit breaker for resilience
circuit_breaker:
  enabled: true
  failure_threshold: 5
  timeout_seconds: 30
  half_open_max_requests: 3
```

## Security-Focused Config

Maximum security configuration for sensitive environments:

```yaml
# config-security.yaml
upstream_url: "https://api.openai.com"
listen_addr: "0.0.0.0:8080"

storage:
  profile: "production"
  postgres_url: "postgresql://llmtrace:password@postgres:5432/llmtrace"
  redis_url: "redis://redis:6379"

# Maximum security settings
security:
  enable_prompt_injection_detection: true
  enable_pii_detection: true
  enable_data_leakage_detection: true
  enable_streaming_analysis: true

  # Strict prompt injection detection
  prompt_injection:
    sensitivity: "maximum"
    block_suspicious_requests: true
    custom_patterns:
      - "ignore.*previous.*instructions"
      - "system.*prompt.*override"
      - "jailbreak|jail break"
      - "pretend.*you.*are"
      - "act.*as.*different"
      - "bypass.*safety"

  # Comprehensive PII detection
  pii_detection:
    types: ["email", "phone", "ssn", "credit_card", "passport", "driver_license"]
    redaction_enabled: true
    strict_mode: true

  # Data leakage protection
  data_leakage:
    detect_credential_exposure: true
    detect_system_prompt_leaks: true
    detect_api_key_exposure: true

  # OWASP LLM Top 10 coverage
  owasp_llm_top10:
    enabled: true
    strict_mode: true

# Strict rate limiting
rate_limiting:
  enabled: true
  requests_per_minute: 100
  burst_capacity: 200

  # Per-tenant strict limits
  per_tenant:
    requests_per_minute: 10
    burst_capacity: 20

# Conservative cost controls
cost_control:
  enabled: true
  daily_budget_usd: 100.0
  per_agent_daily_budget_usd: 10.0

  # Strict token limits
  max_prompt_tokens: 2000
  max_completion_tokens: 1000

  # Block expensive models
  blocked_models: ["gpt-4-turbo", "claude-3-opus"]

# Immediate alerting
alerts:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
    channel: "#security-alerts"
    mention_users: ["@security-team", "@incident-response"]

  email:
    enabled: true
    smtp_host: "smtp.company.com"
    to_addresses: ["security@company.com"]

  # Alert on any security finding
  security_thresholds:
    prompt_injection: "any"
    pii_detection: "any"
    data_leakage: "any"

# Audit logging
logging:
  level: "debug"
  format: "json"

  # Log everything for audit trails
  sampling:
    enabled: false

  # Secure log shipping
  audit:
    enabled: true
    destination: "syslog://audit.company.com:514"
```

## Cost Control Config

Focus on managing LLM expenses:

```yaml
# config-cost.yaml
upstream_url: "https://api.openai.com"
listen_addr: "0.0.0.0:8080"

storage:
  profile: "lite"
  database_path: "./llmtrace.db"

# Cost-focused settings
cost_control:
  enabled: true

  # Overall budget limits
  daily_budget_usd: 500.0
  weekly_budget_usd: 3000.0
  monthly_budget_usd: 10000.0

  # Per-agent limits
  per_agent_daily_budget_usd: 50.0
  per_agent_weekly_budget_usd: 300.0

  # Per-model limits
  per_model_daily_budget_usd:
    gpt-4: 200.0
    gpt-3.5-turbo: 100.0
    claude-3: 150.0

  # Token limits to prevent expensive requests
  max_prompt_tokens: 3000
  max_completion_tokens: 1500

  # Block expensive models during certain hours
  schedule:
    business_hours_only:
      models: ["gpt-4", "claude-3-opus"]
      hours: "09:00-17:00"
      timezone: "UTC"

# Aggressive cost anomaly detection
anomaly_detection:
  enabled: true

  cost:
    threshold_multiplier: 1.5  # Alert on 50% cost increase
    window_minutes: 30

  tokens:
    threshold_multiplier: 2.0
    window_minutes: 15

# Cost-focused alerting
alerts:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
    channel: "#cost-alerts"

  # Alert thresholds
  cost_thresholds:
    daily_spend_percentage: 80  # Alert at 80% of daily budget
    hourly_spend_usd: 50        # Alert if >$50/hour
    single_request_usd: 5       # Alert on expensive single requests

# Basic security (cost-optimized)
security:
  enable_prompt_injection_detection: true
  enable_pii_detection: false  # Disabled to reduce processing cost

  # Lightweight analysis only
  prompt_injection:
    sensitivity: "low"
    fast_mode: true

logging:
  level: "warn"  # Minimal logging for performance
  format: "json"
```

## Environment Variables

Override any config setting with environment variables:

### Common overrides:

```bash
# Network settings
export LLMTRACE_LISTEN_ADDR="0.0.0.0:9080"
export LLMTRACE_UPSTREAM_URL="http://localhost:11434"

# Storage
export LLMTRACE_STORAGE_PROFILE="production"
export LLMTRACE_STORAGE_POSTGRES_URL="postgresql://..."
export LLMTRACE_STORAGE_REDIS_URL="redis://..."

# Security
export LLMTRACE_SECURITY_ENABLE_PII_DETECTION="true"
export LLMTRACE_SECURITY_ENABLE_STREAMING_ANALYSIS="false"

# Cost control
export LLMTRACE_COST_CONTROL_DAILY_BUDGET_USD="1000"
export LLMTRACE_COST_CONTROL_PER_AGENT_DAILY_BUDGET_USD="100"

# Logging
export LLMTRACE_LOG_LEVEL="debug"
export LLMTRACE_LOG_FORMAT="json"
export RUST_LOG="llmtrace_proxy=debug,info"
```

### Docker environment file:

```bash
# .env file for Docker
LLMTRACE_UPSTREAM_URL=https://api.openai.com
LLMTRACE_STORAGE_PROFILE=lite
LLMTRACE_SECURITY_ENABLE_PII_DETECTION=true
LLMTRACE_LOG_LEVEL=info

# Use with Docker
docker run --env-file .env epappas/llmtrace:latest
```

## Validation

Validate your configuration before starting:

```bash
# Validate config file
llmtrace-proxy validate --config config.yaml

# Check what the final config looks like after env var overrides
llmtrace-proxy validate --config config.yaml --show-resolved
```

Example validation output:
```
 Configuration valid
 Storage backend reachable
 Upstream URL accessible
  Warning: PII detection disabled
 Expected memory usage: ~256MB
```

## Configuration Sections

### Storage Options

| Profile | Backend | Use Case | Memory | Persistence |
|---------|---------|----------|---------|-------------|
| `memory` | In-memory | Testing | Low | None |
| `lite` | SQLite | Development | Low | Local file |
| `production` | PostgreSQL + ClickHouse + Redis | Production | Medium | Distributed |

### Security Features

| Feature | Purpose | Performance Impact |
|---------|---------|-------------------|
| `prompt_injection_detection` | Detect jailbreaks, system prompt overrides | Low |
| `pii_detection` | Find emails, SSNs, credit cards | Medium |
| `data_leakage_detection` | Prevent credential exposure | Low |
| `streaming_analysis` | Real-time analysis of streaming responses | Medium |

### Alert Channels

| Channel | Configuration | Use Case |
|---------|---------------|----------|
| Slack | `webhook_url` | Team notifications |
| PagerDuty | `integration_key` | Critical incidents |
| Email | `smtp_*` settings | Management reports |
| Webhook | Custom HTTP endpoints | Custom integrations |

## Advanced Configuration

### Custom Security Patterns

```yaml
security:
  prompt_injection:
    custom_patterns:
      - "(?i)ignore.*previous.*instructions"
      - "(?i)system.*prompt.*override"
      - "(?i)pretend.*you.*are.*different"

  pii_detection:
    custom_patterns:
      internal_employee_id: "EMP\\d{6}"
      customer_id: "CUST-[A-Z0-9]{8}"
```

### Multi-Tenant Configuration

```yaml
# Tenant isolation
tenancy:
  mode: "api_key"  # or "header"
  header_name: "X-LLMTrace-Tenant-ID"

  # Per-tenant settings
  tenant_config:
    customer_a:
      cost_control:
        daily_budget_usd: 100
      rate_limiting:
        requests_per_minute: 50

    customer_b:
      security:
        enable_pii_detection: false  # They handle PII themselves
      cost_control:
        daily_budget_usd: 500
```

### Storage Partitioning

```yaml
storage:
  profile: "production"

  # Time-based partitioning
  partitioning:
    strategy: "time"
    partition_size: "daily"
    retention_days: 90

  # Hot/cold storage tiering
  tiering:
    hot_storage_days: 7
    cold_storage_backend: "s3"
    s3_bucket: "llmtrace-cold-storage"
```

### Performance Tuning

```yaml
performance:
  # Worker thread configuration
  worker_threads: 4
  blocking_threads: 8

  # Connection pooling
  connection_pools:
    postgres_max_connections: 20
    redis_max_connections: 10

  # Request buffering
  request_buffer_size: 1024
  response_buffer_size: 4096

  # Analysis queuing
  analysis_queue_size: 1000
  analysis_workers: 2
```

## Next Steps

- **[Quick Start Guide](quickstart.md)** — Test your configuration
- **[Integration Guides](../guides/)** — Connect your applications
- **[Custom Policies Guide](../guides/custom-policies.md)** — Deep dive into security configuration
- **[Production Deployment](../deployment/)** — Scale your configuration

**Need help?** [Configuration examples](https://github.com/epappas/llmtrace/tree/main/examples) and [troubleshooting guide](../deployment/troubleshooting.md).
