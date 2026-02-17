# LLMTrace

[![CI](https://github.com/epappas/llmtrace/actions/workflows/ci.yml/badge.svg)](https://github.com/epappas/llmtrace/actions/workflows/ci.yml)
[![Security Audit](https://github.com/epappas/llmtrace/actions/workflows/security.yml/badge.svg)](https://github.com/epappas/llmtrace/actions/workflows/security.yml)
[![crates.io](https://img.shields.io/crates/v/llmtrace.svg)](https://crates.io/crates/llmtrace)
[![PyPI](https://img.shields.io/pypi/v/llmtracing.svg)](https://pypi.org/project/llmtracing/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![GitHub Stars](https://img.shields.io/github/stars/epappas/llmtrace)](https://github.com/epappas/llmtrace/stargazers)

**Zero-code LLM observability and security for production.**

LLMTrace is a transparent proxy that captures, analyzes, and secures your LLM interactions in real-time. Drop it between your app and any OpenAI-compatible API to get instant visibility into prompt injection attacks, PII leaks, cost overruns, and performance bottlenecks — without changing a single line of code.

## Why LLMTrace?

Production LLM applications face three critical blind spots:

- **Security vulnerabilities** — Prompt injection, data leakage, PII exposure
- **Cost runaway** — Uncontrolled API spend, inefficient token usage
- **Performance opacity** — No visibility into latency, failure rates, or user behavior

LLMTrace solves this by sitting transparently between your application and LLM providers, giving you complete observability and control.

## Key Features

- **Transparent Proxy** — Drop-in replacement for any OpenAI-compatible API
- **ML Ensemble Detection** — Multi-detector majority voting (regex, DeBERTa, InjecGuard, PIGuard)
- **Real-time Security** — Prompt injection detection, PII scanning, data leakage prevention
- **Performance Monitoring** — Latency, token usage, streaming metrics (TTFT), error tracking
- **Cost Control** — Per-agent budgets, rate limits, anomaly detection
- **Multi-tenant Ready** — Isolated per API key or custom tenant headers
- **High Performance** — Built in Rust, handles streaming responses, circuit breaker protection

## Security Performance

| Metric    | Value |
|-----------|-------|
| Accuracy  | 87.6% |
| Precision | 95.5% |
| F1 Score  | 86.9% |
| Recall    | 79.7% |

Tested on a 153-sample adversarial corpus across 12 attack categories including CyberSecEval2, BIPIA, TensorTrust, and InjecAgent. See [benchmarks/](benchmarks/) for methodology and full results.

## Quick Start

### 1. Install

```bash
curl -sS https://raw.githubusercontent.com/epappas/llmtrace/main/scripts/install.sh | bash
```

Or use one of the other methods:

```bash
cargo install llmtrace                # from crates.io
docker pull ghcr.io/epappas/llmtrace-proxy:latest  # Docker
```

### 2. Run

```bash
export OPENAI_API_KEY="sk-..."
llmtrace-proxy --config config.yaml
```

### 3. Try it with your existing code

```python
import openai

# Before: Point to OpenAI directly
client = openai.OpenAI()

# After: Point to LLMTrace proxy (that's it!)
client = openai.OpenAI(base_url="http://localhost:8080/v1")

# Your code stays exactly the same
response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello!"}]
)
```

### 4. See your traces

```bash
# View recent activity
curl http://localhost:8080/api/v1/traces | jq '.[0]'

# Check security findings
curl http://localhost:8080/api/v1/security/findings | jq

# Monitor costs
curl http://localhost:8080/api/v1/costs/current | jq
```

**That's it!** You now have full observability into your LLM interactions.

## Architecture

```mermaid
graph LR
    A[Your Application] -->|HTTP| B[LLMTrace Proxy]
    B -->|HTTP| C[OpenAI/LLM Provider]
    B -->|Async| D[Security Engine]
    B -->|Async| E[Storage Engine]

    D --> F[SQLite/PostgreSQL]
    E --> F
    D --> G[Real-time Alerts]

    H[Dashboard] -->|REST API| B
    I[Monitoring] -->|Metrics API| B

    style B fill:#e1f5fe
    style D fill:#fff3e0
    style E fill:#f3e5f5
```

**How it works:**
1. **Transparent Proxy** — Your app sends requests to LLMTrace instead of OpenAI
2. **Pass-through** — LLMTrace forwards requests to the real LLM provider
3. **Background Analysis** — Security analysis and trace capture happen asynchronously
4. **Zero Impact** — Your application never waits for analysis, even if something fails

## Integration Examples

### OpenAI Python SDK
```python
import openai

# Just change the base_url
client = openai.OpenAI(
    base_url="http://localhost:8080/v1",
    api_key="your-openai-key"
)
```

### OpenAI Node.js SDK
```javascript
import OpenAI from 'openai';

const openai = new OpenAI({
  baseURL: 'http://localhost:8080/v1',
  apiKey: 'your-openai-key'
});
```

### LangChain
```python
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(
    base_url="http://localhost:8080/v1",
    api_key="your-openai-key"
)
```

### curl
```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4", "messages": [{"role": "user", "content": "Hello!"}]}'
```

**[View all integration guides ->](docs/README.md#guides)**

## Dashboard & Monitoring

LLMTrace includes a built-in dashboard for visualizing traces, security findings, and costs:

```bash
# Access the dashboard
open http://localhost:3000

# Or use the REST API
curl http://localhost:8080/api/v1/traces
curl http://localhost:8080/api/v1/security/findings
curl http://localhost:8080/api/v1/costs/current
```

**Dashboard features:**
- Real-time trace visualization
- Security incident timeline
- Cost breakdown by model/agent
- Performance metrics and alerts

## Configuration

### Minimal Configuration
```yaml
# config.yaml
upstream_url: "https://api.openai.com"
listen_addr: "0.0.0.0:8080"

storage:
  profile: "lite"  # SQLite for simple deployments

security:
  enable_prompt_injection_detection: true
  enable_pii_detection: true
```

### Production Configuration
```yaml
# config.yaml
upstream_url: "https://api.openai.com"
listen_addr: "0.0.0.0:8080"

storage:
  profile: "production"
  postgres_url: "postgresql://user:pass@localhost/llmtrace"
  clickhouse_url: "http://localhost:8123"
  redis_url: "redis://localhost:6379"

security:
  enable_prompt_injection_detection: true
  enable_pii_detection: true
  enable_streaming_analysis: true

cost_control:
  daily_budget_usd: 1000
  per_agent_daily_budget_usd: 100

alerts:
  slack:
    webhook_url: "https://hooks.slack.com/..."

rate_limiting:
  requests_per_minute: 1000
  burst_capacity: 2000
```

**[Full configuration guide ->](docs/getting-started/configuration.md)**

## API Reference

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/traces` | List recent traces |
| `GET /api/v1/traces/{id}` | Get specific trace details |
| `GET /api/v1/security/findings` | List security incidents |
| `GET /api/v1/costs/current` | Cost breakdown and usage |
| `GET /health` | Health check and circuit breaker status |
| `POST /policies/validate` | Validate custom security policies |

**[Full API documentation ->](docs/guides/API.md)**

## Installation

### Cargo (Rust Proxy)
```bash
cargo install llmtrace
llmtrace-proxy --config config.yaml
```

### Pip (Python SDK)
```bash
pip install llmtracing
```

```python
import llmtrace

tracer = llmtrace.configure({"enable_security": True})
span = tracer.start_span("chat_completion", "openai", "gpt-4")
span.set_prompt("Hello!")
span.set_response("Hi there!")
print(span.to_dict())
```

### Docker
```bash
docker pull ghcr.io/epappas/llmtrace-proxy:latest
docker run -p 8080:8080 ghcr.io/epappas/llmtrace-proxy:latest
```

### Docker Compose with Dependencies
```bash
curl -o compose.yaml https://raw.githubusercontent.com/epappas/llmtrace/main/compose.yaml
docker compose up -d
```

### From Source
```bash
git clone https://github.com/epappas/llmtrace
cd llmtrace
cargo build --release --features ml
./target/release/llmtrace-proxy --config config.yaml
```

### Kubernetes
```bash
helm install llmtrace ./deployments/helm/llmtrace
```

**[Installation guide with all methods ->](docs/getting-started/installation.md)**

## Production Deployment

### High-Availability Setup
- **Load Balancer** -> Multiple LLMTrace instances
- **PostgreSQL** for persistent trace storage
- **ClickHouse** for high-volume analytics
- **Redis** for caching and rate limiting

### Security Best Practices
- API key validation and tenant isolation
- TLS termination at load balancer
- Network segmentation between components
- Regular security policy updates

### Monitoring & Alerting
- Prometheus metrics export
- Grafana dashboards
- PagerDuty/Slack integration
- OWASP LLM Top 10 compliance reporting

**[Production deployment guide ->](docs/deployment/kubernetes.md)**

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
```bash
git clone https://github.com/epappas/llmtrace
cd llmtrace
cargo build --workspace
cargo test --workspace
```

### Project Structure
| Crate | Package | Purpose |
|-------|---------|---------|
| `llmtrace-core` | - | Shared types and traits |
| `llmtrace` | [crates.io](https://crates.io/crates/llmtrace) | HTTP proxy server (`cargo install llmtrace`) |
| `llmtrace-security` | - | Security analysis engine (regex + DeBERTa + InjecGuard + PIGuard ensemble) |
| `llmtrace-storage` | - | Storage backends (SQLite, PostgreSQL, ClickHouse, Redis) |
| `llmtrace-python` | [PyPI](https://pypi.org/project/llmtracing/) | Python SDK (`pip install llmtracing`, imports as `import llmtrace`) |

**[Development guide ->](CONTRIBUTING.md)**

## License

[MIT](LICENSE) - Free for commercial and personal use.

---

**Star this repo** if LLMTrace helps secure your LLM applications!

**Found a bug?** [Open an issue](https://github.com/epappas/llmtrace/issues)

**Questions?** [Start a discussion](https://github.com/epappas/llmtrace/discussions)
