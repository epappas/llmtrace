# Installation Guide

This guide covers supported ways to run LLMTrace as implemented in this repository. All instructions are based on the current codebase and bundled files.

## Options

| Method | Best For | Notes |
|--------|----------|-------|
| `cargo install` | Quickest install | Pre-built from [crates.io](https://crates.io/crates/llmtrace) |
| `pip install` | Python SDK | Pre-built from [PyPI](https://pypi.org/project/llmtracing/) |
| Docker (GHCR) | Containerized runs | Pre-built multi-arch image from GHCR |
| From source | Development | Uses local Rust toolchain |
| Docker Compose | Local infra/dev stack | Starts ClickHouse/Postgres/Redis and dashboard |
| Helm chart | Kubernetes clusters | Chart under `deployments/helm/llmtrace` |

---

## Cargo Install (Proxy)

Install the proxy binary directly from crates.io:

```bash
cargo install llmtrace

# Run with a config file
cp config.example.yaml config.yaml
llmtrace-proxy --config config.yaml
```

---

## Pip Install (Python SDK)

Install the Python SDK from PyPI (imports as `import llmtrace`):

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

---

## From Source

**Prerequisite:** Rust 1.93+.

```bash
# 1. Clone
git clone https://github.com/epappas/llmtrace
cd llmtrace

# 2. Build
cargo build --release --bin llmtrace-proxy

# 3. Run with example config
cp config.example.yaml config.yaml
./target/release/llmtrace-proxy --config config.yaml
```

---

## Docker (GHCR)

Pre-built multi-arch images (amd64 + arm64) are published to GHCR on every release:

```bash
docker pull ghcr.io/epappas/llmtrace-proxy:latest
docker run -p 8080:8080 ghcr.io/epappas/llmtrace-proxy:latest
```

To customize configuration, mount a config file:

```bash
docker run -p 8080:8080 \
  -v $(pwd)/config.yaml:/etc/llmtrace/config.yaml \
  ghcr.io/epappas/llmtrace-proxy:latest
```

### Build Locally

```bash
docker build -t llmtrace-proxy .
docker run -p 8080:8080 --env-file .env llmtrace-proxy
```

---

## Docker Compose (Infra + Dashboard)

`compose.yaml` starts **ClickHouse**, **PostgreSQL**, **Redis**, and the **dashboard** UI. It does **not** run the proxy.

```bash
# 1. Copy env file
cp .env.example .env

# 2. Start infra services
docker compose up -d

# 3. Run the proxy separately (example)
cargo run --bin llmtrace-proxy -- --config config.yaml
```

Notes:

- The dashboard expects the proxy at `http://localhost:8080`.
- Use `storage.profile: production` with ClickHouse/Postgres/Redis from compose.

---

## Helm (Local Chart)

A Helm chart is included under `deployments/helm/llmtrace`.

```bash
# From repo root
helm install llmtrace ./deployments/helm/llmtrace
```

Notes:

- The chart defaults to the GHCR image `ghcr.io/epappas/llmtrace-proxy`.
- Override `proxy.image.repository` and `proxy.image.tag` in `values.yaml` if using a custom registry.

---

## Verify the Proxy

```bash
# Health check
curl http://localhost:8080/health

# Proxy a test OpenAI-compatible request
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4", "messages": [{"role": "user", "content": "Hello"}]}'
```

---

## Next Steps

- `docs/getting-started/quickstart.md`
- `docs/getting-started/configuration.md`
