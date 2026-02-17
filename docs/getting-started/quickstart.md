# Quick Start Guide

This guide gets the LLMTrace proxy running and verifies that traces and findings are captured. All steps below map to the current codebase.

## Prerequisites

- OpenAI API key (or another OpenAI-compatible upstream)
- Either Rust toolchain or Docker

---

## Option A: Cargo Install (Fastest)

```bash
cargo install llmtrace
cp config.example.yaml config.yaml
llmtrace-proxy --config config.yaml
```

---

## Option B: Docker (GHCR)

```bash
docker pull ghcr.io/epappas/llmtrace-proxy:latest
docker run -p 8080:8080 ghcr.io/epappas/llmtrace-proxy:latest
```

---

## Option C: From Source

```bash
git clone https://github.com/epappas/llmtrace
cd llmtrace
cargo build --release --bin llmtrace-proxy
cp config.example.yaml config.yaml
./target/release/llmtrace-proxy --config config.yaml
```

---

## Optional: Start Infra + Dashboard (Docker Compose)

`compose.yaml` starts ClickHouse/Postgres/Redis and the dashboard. Run the proxy separately.

```bash
cp .env.example .env
docker compose up -d

# Then run the proxy (from source or Docker)
```

---

## Test the Proxy

### 1) Send a test request

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4", "messages": [{"role": "user", "content": "Hello, LLMTrace!"}]}'
```

You should receive a normal OpenAI-compatible response.

### 2) Fetch traces

```bash
curl http://localhost:8080/api/v1/traces | jq '.[0]'
```

### 3) Fetch security findings

```bash
curl http://localhost:8080/api/v1/security/findings | jq
```

---

## Quick Integration Example (OpenAI SDK)

```python
import openai

client = openai.OpenAI(
    base_url="http://localhost:8080/v1",
    api_key="your-key"
)

response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello"}]
)
```

---

## Next Steps

- `docs/getting-started/configuration.md`
- `docs/guides/API.md`
- `docs/architecture/SYSTEM_ARCHITECTURE.md`
