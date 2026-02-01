# Integration Tests

LLMTrace integration tests run against real infrastructure services
(ClickHouse, PostgreSQL, Redis) via Docker Compose. They are marked with
`#[ignore]` so `cargo test` skips them by default — you opt in by passing
`-- --ignored`.

## Prerequisites

- **Docker** and **Docker Compose** (v2) installed and running
- **Rust toolchain** (`rustup`, `cargo`)
- Ports 8123, 9000, 5432, and 6379 available on localhost

## Quick Start

```bash
# 1. Start infrastructure (ClickHouse, PostgreSQL, Redis)
docker compose up -d --wait clickhouse postgres redis

# 2. Export the connection URLs
export LLMTRACE_CLICKHOUSE_URL=http://localhost:8123
export LLMTRACE_CLICKHOUSE_DATABASE=llmtrace
export LLMTRACE_POSTGRES_URL=postgres://llmtrace:llmtrace@localhost:5432/llmtrace
export LLMTRACE_REDIS_URL=redis://127.0.0.1:6379

# 3. Run integration tests
cargo test --workspace --features "clickhouse,postgres,redis_backend" -- --ignored

# 4. Tear down
docker compose down -v
```

Or source the provided `.env.example` which sets the same variables:

```bash
docker compose up -d --wait clickhouse postgres redis
source .env.example
cargo test --workspace --features "clickhouse,postgres,redis_backend" -- --ignored
```

## What Gets Tested

The integration tests exercise **production storage backends** that require
running services:

| Backend | Crate | Tests |
|---|---|---|
| **ClickHouse** | `llmtrace-storage` | Trace/span CRUD, schema migrations, batch inserts |
| **PostgreSQL** | `llmtrace-storage` | Tenant/metadata CRUD, audit events, migrations |
| **Redis** | `llmtrace-storage` | Cache get/set/TTL, invalidation, connection pooling |
| **Production profile** | `llmtrace-storage` | Full `StorageProfile::Production` composite build |

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `LLMTRACE_CLICKHOUSE_URL` | `http://localhost:8123` | ClickHouse HTTP endpoint |
| `LLMTRACE_CLICKHOUSE_DATABASE` | `llmtrace` | ClickHouse database name |
| `LLMTRACE_POSTGRES_URL` | `postgres://llmtrace:llmtrace@localhost:5432/llmtrace` | PostgreSQL connection string |
| `LLMTRACE_REDIS_URL` | `redis://127.0.0.1:6379` | Redis connection URL |

## Running in CI

The GitHub Actions CI pipeline (`.github/workflows/ci.yml`) has a dedicated
`integration` job that:

1. Waits for unit tests to pass (`needs: test`)
2. Starts Docker Compose services with `docker compose up -d --wait`
3. Verifies service health (ClickHouse ping, `pg_isready`, Redis `PING`)
4. Runs `cargo test --workspace --features "clickhouse,postgres,redis_backend" -- --ignored`
5. Tears down services (`docker compose down -v`) regardless of test outcome

## Troubleshooting

### Services won't start

```bash
# Check service status and logs
docker compose ps
docker compose logs clickhouse
docker compose logs postgres
docker compose logs redis
```

### Port conflicts

If another process occupies 8123/5432/6379, override via environment:

```bash
CLICKHOUSE_PORT=18123 POSTGRES_PORT=15432 REDIS_PORT=16379 docker compose up -d
```

Then update `LLMTRACE_*_URL` variables to match (e.g.,
`http://localhost:18123`).

### Tests hang or time out

Each service has a health check with 5 retries × 5s intervals. If a service is
slow to start, wait or check `docker compose logs`. Tests have their own
timeouts; look for `connect_timeout` or `timeout` in test output.

## Container Image Scanning

The release pipeline (`.github/workflows/release.yml`) scans the Docker image
with [Trivy](https://github.com/aquasecurity/trivy) before pushing to GHCR:

- **Release builds**: Trivy scans fail the pipeline on CRITICAL/HIGH CVEs
- **PR/CI builds**: Trivy runs as an advisory scan (does not block merge)
- SARIF results are uploaded to the GitHub Security tab

To scan locally:

```bash
docker build -t llmtrace-proxy:local .
trivy image --severity CRITICAL,HIGH llmtrace-proxy:local
```
