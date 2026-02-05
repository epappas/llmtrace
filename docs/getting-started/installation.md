# Installation Guide

This guide covers supported ways to run LLMTrace as implemented in this repository. All instructions are based on the current codebase and bundled files.

## Options (Accurate to This Repo)

| Method | Best For | Notes |
|--------|----------|-------|
| From source (cargo) | Development | Uses local Rust toolchain.
| Docker (build locally) | Containerized runs | Build with `Dockerfile` in repo.
| Docker Compose (infra + dashboard) | Local infra/dev stack | Compose starts ClickHouse/Postgres/Redis and dashboard; you run the proxy separately.
| Helm chart (local) | Kubernetes clusters | Chart is under `deployments/helm/llmtrace`.

---

## From Source (Recommended for Development)

**Prerequisite:** Rust 1.93 (per repo instructions).

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

## Docker (Build Locally)

The repository includes a multi-stage `Dockerfile` that builds the `llmtrace-proxy` binary.

```bash
# Build the proxy image
docker build -t llmtrace-proxy .

# Run with environment variables (or mount a config file)
docker run -p 8080:8080 --env-file .env llmtrace-proxy
```

To customize configuration, mount a config file:

```bash
docker run -p 8080:8080 \
  -v $(pwd)/config.yaml:/etc/llmtrace/config.yaml \
  llmtrace-proxy
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

- The chart defaults to an image repository named `llmtrace-proxy`.
- You must build and push an image (or adjust the image settings in `values.yaml`).

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
