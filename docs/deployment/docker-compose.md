# Docker Compose Deployment Guide

LLMTrace ships two distinct Compose setups:

- The repo-root [`compose.yaml`](https://github.com/epappas/llmtrace/blob/main/compose.yaml) for local development and integration testing.
- The production-oriented stack under [`deployments/docker-compose`](https://github.com/epappas/llmtrace/tree/main/deployments/docker-compose) for running the proxy, dashboard, TLS ingress, and optional monitoring.

## Files

| File | Purpose |
|------|---------|
| `compose.yaml` | Base production stack: ClickHouse, PostgreSQL, Redis, proxy, dashboard, nginx |
| `compose.override.yaml` | Developer-friendly overrides (direct ports, debug logging, disable nginx port binding) |
| `compose.ml.yaml` | GPU and higher-memory overlay for ML-enabled deployments |
| `compose.monitoring.yaml` | Prometheus + Grafana overlay |
| `.env.example` | Environment variables and secret placeholders |

## Quick Start

```bash
cd deployments/docker-compose
cp .env.example .env

# base production-style stack
docker compose -f compose.yaml up -d

# add monitoring
docker compose -f compose.yaml -f compose.monitoring.yaml up -d

# add GPU / ML tuning
docker compose -f compose.yaml -f compose.ml.yaml up -d
```

For local source builds and direct dashboard/proxy ports:

```bash
docker compose \
  -f compose.yaml \
  -f compose.override.yaml \
  up -d
```

## Required Inputs

- `../../config.yaml` must exist and contain a valid proxy configuration.
- `.env` must define the backing-service URLs and any bootstrap secrets you need.
- TLS certificate and key files must exist at the paths configured by `TLS_CERT_PATH` and `TLS_KEY_PATH`.

## Operations

```bash
# Validate the merged Compose model
docker compose \
  -f compose.yaml \
  -f compose.monitoring.yaml \
  config

# Tail proxy logs
docker compose logs -f proxy

# Graceful stop
docker compose down
```

The proxy container is configured with:

- `stop_grace_period: 60s`
- `depends_on.condition: service_healthy`
- persistent volumes for ClickHouse, PostgreSQL, Redis, and ML model cache
- `/health` HTTP health checks

## Monitoring

When `compose.monitoring.yaml` is enabled:

- Prometheus scrapes `proxy:8080/metrics`
- Grafana loads a pre-provisioned `LLMTrace Overview` dashboard
- Grafana listens on `http://localhost:3001`

## GPU / ML

The ML overlay enables:

- `LLMTRACE_ML_ENABLED=1`
- `LLMTRACE_ML_PRELOAD=1`
- `gpus: all`
- larger CPU and memory limits for the proxy

Hosts must have the NVIDIA Container Toolkit installed for GPU scheduling to work.
