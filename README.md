# LLMTrace

[![CI](https://github.com/epappas/llmtrace/actions/workflows/ci.yml/badge.svg)](https://github.com/epappas/llmtrace/actions/workflows/ci.yml)
[![Security Audit](https://github.com/epappas/llmtrace/actions/workflows/security.yml/badge.svg)](https://github.com/epappas/llmtrace/actions/workflows/security.yml)

**Security-aware observability for LLM applications.**

LLMTrace is a transparent proxy that sits between your application and any OpenAI-compatible LLM API. It captures every interaction as structured traces, runs real-time security analysis (prompt injection detection, PII scanning), and stores everything in SQLite for inspection — with zero code changes to your application.

## Key Features

- **Transparent Proxy** — Drop-in HTTP proxy for any OpenAI-compatible API (`/v1/chat/completions`, `/v1/completions`). Supports both streaming (SSE) and non-streaming responses.
- **Prompt Injection Detection** — Regex-based detection of system prompt overrides, role injection, encoding attacks (base64), jailbreak patterns, and delimiter injection.
- **PII Scanning** — Automatic detection of email addresses, phone numbers, SSNs, and credit card numbers in both requests and responses.
- **Data Leakage Detection** — Detects system prompt leaks and credential exposure in LLM responses.
- **Streaming Metrics** — Tracks time-to-first-token (TTFT), completion token counts, and total latency for streaming responses.
- **Multi-Tenant** — Tenant isolation via API key derivation or custom `X-LLMTrace-Tenant-ID` header.
- **Circuit Breaker** — Degrades gracefully to pure pass-through when storage or security analysis fails.
- **Python SDK** — Native Python bindings via PyO3 for direct SDK integration.

## Quick Start

### 1. Build

```bash
cargo build --release
```

### 2. Configure

Copy the example config and adjust for your environment:

```bash
cp config.example.yaml config.yaml
# Edit config.yaml: set upstream_url to your LLM endpoint
```

### 3. Run

```bash
# Start the proxy
./target/release/llmtrace-proxy --config config.yaml

# Or with defaults (upstream: https://api.openai.com, listen: 0.0.0.0:8080)
./target/release/llmtrace-proxy
```

### 4. Use

Point your LLM client at the proxy instead of the real endpoint:

```bash
# Non-streaming
curl http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"Hello!"}]}'

# Streaming
curl -N http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"Hello!"}],"stream":true}'
```

### 5. Inspect Traces

```bash
sqlite3 llmtrace.db "SELECT trace_id, model_name, security_score, duration_ms FROM spans ORDER BY start_time DESC LIMIT 10;"
```

## Python SDK

Install the native module (requires [maturin](https://github.com/PyO3/maturin)):

```bash
cd crates/llmtrace-python
maturin develop
```

Usage:

```python
import llmtrace_python as llmtrace

# Create a tracer
tracer = llmtrace.configure({"enable_security": True})

# Start a span
span = tracer.start_span("chat_completion", "openai", "gpt-4")
span.set_prompt("What is 2+2?")
span.set_response("4")
span.set_token_counts(prompt_tokens=5, completion_tokens=1)

# Serialize
print(span.to_json())

# Instrument an existing client
import openai
client = openai.OpenAI()
instrumented = llmtrace.instrument(client, tracer=tracer)
```

See [`examples/python_sdk.py`](examples/python_sdk.py) for a full walkthrough.

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  Your App   │────▸│  LLMTrace Proxy  │────▸│  LLM Provider    │
│  (client)   │◂────│  (transparent)   │◂────│  (OpenAI, etc.)  │
└─────────────┘     └────────┬─────────┘     └──────────────────┘
                             │
                    ┌────────┴─────────┐
                    │  Background Tasks │
                    │  (async, non-    │
                    │   blocking)       │
                    ├──────────────────┤
                    │ Security Analysis│──▸ Findings
                    │ Trace Capture    │──▸ SQLite
                    └──────────────────┘
```

### Crate Structure

| Crate | Type | Description |
|-------|------|-------------|
| `llmtrace-core` | lib | Core types, traits, errors — shared by all crates |
| `llmtrace-proxy` | bin+lib | Transparent HTTP proxy server with axum |
| `llmtrace-storage` | lib | Storage abstraction: SQLite + in-memory backends |
| `llmtrace-security` | lib | Regex-based security analysis engine |
| `llmtrace-sdk` | lib | Embeddable Rust SDK for direct integration |
| `llmtrace-python` | cdylib | Python bindings via PyO3 |

For detailed architecture, see [`docs/architecture/`](docs/architecture/).

## Configuration & Policies

LLMTrace is highly configurable — security policies, rate limits, cost caps, alerting, and anomaly detection can all be tuned via `config.yaml`.

📖 **[Custom Policy Setup Guide](docs/guides/custom-policies.md)** — comprehensive guide covering all policy options with practical examples.

### Example Configurations

Ready-to-use configs for common scenarios:

| Config | Use Case | Highlights |
|--------|----------|------------|
| [`config-minimal.yaml`](examples/config-minimal.yaml) | Getting started | SQLite, regex security, basic rate limits |
| [`config-production.yaml`](examples/config-production.yaml) | Full production | ClickHouse + PostgreSQL + Redis, multi-channel alerts, anomaly detection |
| [`config-high-security.yaml`](examples/config-high-security.yaml) | Maximum security | ML detection, streaming analysis, PII redaction, PagerDuty escalation |
| [`config-cost-control.yaml`](examples/config-cost-control.yaml) | Cost management | Per-agent budgets, token caps, cost anomaly alerts |

### Key Policy Areas

- **Security Analysis** — Regex + ML-based prompt injection detection, PII scanning, encoding attack detection ([guide](docs/guides/custom-policies.md#security-analysis-policies))
- **Rate Limiting** — Per-tenant rate limits with burst handling ([guide](docs/guides/custom-policies.md#rate-limiting))
- **Cost Caps** — Per-agent budgets with soft/hard limits and token caps ([guide](docs/guides/custom-policies.md#cost-caps--budgets))
- **Alerting** — Multi-channel alerts (Slack, PagerDuty, webhook) with severity filtering ([guide](docs/guides/custom-policies.md#alert-channels))
- **Anomaly Detection** — Statistical detection of cost, token, velocity, and latency anomalies ([guide](docs/guides/custom-policies.md#anomaly-detection))
- **OWASP LLM Top 10** — Built-in test coverage for the OWASP LLM security taxonomy ([details](docs/security/OWASP_LLM_TOP10.md))

## Configuration Reference

### Config File (`config.yaml`)

See [`config.example.yaml`](config.example.yaml) for a fully commented example.

### CLI Flags

```
llmtrace-proxy [OPTIONS] [COMMAND]

Options:
  -c, --config <PATH>       Path to YAML config file [env: LLMTRACE_CONFIG]
      --log-level <LEVEL>   Override log level [env: LLMTRACE_LOG_LEVEL]
      --log-format <FMT>    Override log format [env: LLMTRACE_LOG_FORMAT]
  -h, --help                Print help
  -V, --version             Print version

Commands:
  validate    Validate config file and print resolved settings
```

### Environment Variables

| Variable | Overrides | Example |
|----------|-----------|---------|
| `LLMTRACE_CONFIG` | Config file path | `/etc/llmtrace/config.yaml` |
| `LLMTRACE_LISTEN_ADDR` | `listen_addr` | `0.0.0.0:9090` |
| `LLMTRACE_UPSTREAM_URL` | `upstream_url` | `http://localhost:11434` |
| `LLMTRACE_STORAGE_PROFILE` | `storage.profile` | `memory` |
| `LLMTRACE_STORAGE_DATABASE_PATH` | `storage.database_path` | `/var/lib/llmtrace/traces.db` |
| `LLMTRACE_LOG_LEVEL` | `logging.level` | `debug` |
| `LLMTRACE_LOG_FORMAT` | `logging.format` | `json` |
| `RUST_LOG` | Fine-grained tracing filter | `llmtrace_proxy=debug,info` |

**Precedence** (highest wins): CLI flags → env vars → config file → defaults.

## Examples

See the [`examples/`](examples/) directory:

- **[`basic_proxy.sh`](examples/basic_proxy.sh)** — Start the proxy, send requests, query traces
- **[`security_test.sh`](examples/security_test.sh)** — Prompt injection detection demo with 8 attack patterns
- **[`python_sdk.py`](examples/python_sdk.py)** — Python SDK walkthrough
- **[`config-minimal.yaml`](examples/config-minimal.yaml)** — Minimal configuration to get started
- **[`config-production.yaml`](examples/config-production.yaml)** — Full production setup with all features
- **[`config-high-security.yaml`](examples/config-high-security.yaml)** — Maximum security posture configuration
- **[`config-cost-control.yaml`](examples/config-cost-control.yaml)** — Cost management focused configuration

## Development

```bash
# Build all crates
cargo build --workspace

# Run all tests (unit + integration)
cargo test --workspace

# Format check
cargo fmt --all --check

# Lint
cargo clippy --workspace -- -D warnings

# Release build
cargo build --release
```

## License

[MIT](LICENSE)
