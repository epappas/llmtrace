# RALPH Loops — LLMTrace Build Plan

Each loop is a self-contained task. The spawned coding agent must:
1. Read the relevant architecture docs for context
2. Complete the task fully
3. Ensure `cargo fmt --check` passes
4. Ensure `cargo clippy -- -D warnings` passes
5. Ensure `cargo test` passes (if tests exist)
6. Commit with a meaningful message
7. Push to origin/main

## Loop 0: Scaffold the Workspace

**Goal**: Create the Rust workspace with the initial crate structure, CI-ready.

**Context files**: `docs/architecture/SYSTEM_ARCHITECTURE.md` (crate architecture section)

**Tasks**:
- Initialize a Cargo workspace at the repo root
- Create the following crates with stub `lib.rs` / `main.rs`:
  - `llmtrace-core` (lib) — core types, traits, errors
  - `llmtrace-proxy` (bin) — the transparent proxy server binary
  - `llmtrace-sdk` (lib) — embeddable SDK for Rust consumers
  - `llmtrace-storage` (lib) — storage abstraction (trait + SQLite backend)
  - `llmtrace-security` (lib) — security analysis (prompt injection detection)
  - `llmtrace-python` (lib, cdylib) — Python bindings via PyO3
- Add a root `README.md` with project description
- Add `.gitignore` for Rust
- Add `rustfmt.toml` with `edition = "2021"`
- Add `clippy.toml` if needed
- Every crate must compile cleanly
- Commit and push

**Acceptance**: `cargo build --workspace` succeeds, `cargo fmt --check` passes, `cargo clippy --workspace -- -D warnings` passes.

---

## Loop 1: Core Types & Traits

**Goal**: Define the foundational types in `llmtrace-core`.

**Context files**: `docs/architecture/SYSTEM_ARCHITECTURE.md`, `docs/architecture/TRANSPARENT_PROXY.md`

**Tasks**:
- Define core types in `llmtrace-core`:
  - `TraceEvent` — represents a single LLM call trace (request metadata, response metadata, timing, token counts)
  - `TraceSpan` — a span within a trace (prompt analysis, inference, response processing)
  - `TenantId` — newtype for tenant identification
  - `SecurityFinding` — represents a security issue found (prompt injection, PII leak, etc.)
  - `SecuritySeverity` — enum (Critical, High, Medium, Low, Info)
  - `LLMProvider` — enum (OpenAI, Anthropic, VLLm, SGLang, TGI, Ollama, AzureOpenAI, Bedrock, Custom)
  - `ProxyConfig` — configuration struct for the proxy (upstream URL, listen address, timeouts, etc.)
- Define core traits:
  - `StorageBackend` — async trait for persisting traces (`store_trace`, `query_traces`, `health_check`)
  - `SecurityAnalyzer` — async trait for security analysis (`analyze_request`, `analyze_response`)
- Use `thiserror` for error types
- Use `serde` for serialization on all public types
- Use `chrono` or `time` for timestamps
- Add unit tests for serialization roundtrips
- Commit and push

**Acceptance**: `cargo test -p llmtrace-core` passes, all types serialize/deserialize correctly.

---

## Loop 2: SQLite Storage Backend

**Goal**: Implement the SQLite storage backend in `llmtrace-storage`.

**Context files**: `docs/architecture/SYSTEM_ARCHITECTURE.md` (storage section)

**Tasks**:
- Add `sqlx` with SQLite feature to `llmtrace-storage`
- Implement `StorageBackend` trait for `SqliteStorage`:
  - `store_trace` — inserts a `TraceEvent` into SQLite
  - `query_traces` — basic query by tenant, time range, provider
  - `health_check` — verifies DB connectivity
- Schema: create table(s) for traces with proper indexes
- Use migrations (sqlx migrations or embedded SQL)
- Add `new()` constructor that creates/opens the SQLite database and runs migrations
- Add integration tests with a temp database
- Commit and push

**Acceptance**: `cargo test -p llmtrace-storage` passes, traces can be stored and retrieved.

---

## Loop 3: Basic Prompt Injection Detection

**Goal**: Implement regex-based prompt injection detection in `llmtrace-security`.

**Context files**: `docs/architecture/ARCHITECTURE_SUPPLEMENT.md` (security section)

**Tasks**:
- Implement `SecurityAnalyzer` trait for `RegexSecurityAnalyzer`:
  - `analyze_request` — scans prompt text for known injection patterns
  - `analyze_response` — scans response for data leakage patterns
- Include at minimum these detection patterns:
  - System prompt override attempts ("ignore previous instructions", "you are now", etc.)
  - Role injection ("system:", "assistant:", etc. in user messages)
  - Encoding attacks (base64-encoded instructions)
  - PII patterns (email, phone, SSN, credit card — regex-based)
- Each finding produces a `SecurityFinding` with severity and description
- Add comprehensive tests with known attack examples
- Commit and push

**Acceptance**: `cargo test -p llmtrace-security` passes, known injection patterns are detected.

---

## Loop 4: Transparent Proxy — Core Implementation

**Goal**: Build the transparent proxy server in `llmtrace-proxy`.

**Context files**: `docs/architecture/TRANSPARENT_PROXY.md`

**Tasks**:
- Use `axum` + `hyper` + `tokio` for the proxy server
- Implement the core proxy flow:
  1. Accept incoming HTTP requests on configurable listen address
  2. Parse request: extract model, messages, API key from headers/body
  3. Identify tenant from API key or custom header
  4. Forward request to configurable upstream URL (preserve all headers except Host)
  5. Capture response (including streaming SSE)
  6. Return response to client
- Support both `/v1/chat/completions` and `/v1/completions` (OpenAI-compatible)
- Async trace capture — spawn background task, never block the response
- Async security analysis — spawn background task
- Circuit breaker: if storage/security is failing, degrade to pure pass-through
- Load `ProxyConfig` from a YAML config file (use `serde_yaml`)
- Add a basic health endpoint `/health`
- The binary should start, listen, and proxy requests
- Commit and push

**Acceptance**: Binary compiles and runs, can proxy a request to a mock upstream, `cargo clippy` clean.

---

## Loop 5: Streaming SSE Support

**Goal**: Add proper Server-Sent Events streaming passthrough.

**Context files**: `docs/architecture/TRANSPARENT_PROXY.md` (streaming section)

**Tasks**:
- Detect streaming requests (`"stream": true` in request body)
- For streaming responses:
  - Forward SSE chunks as they arrive (do not buffer the whole response)
  - Parse each SSE chunk to extract token data incrementally
  - Track token count, latency to first token (TTFT), and completion tokens
  - Assemble the complete trace after the stream ends
- Non-streaming requests continue to work as before
- Add integration test using a mock SSE upstream
- Commit and push

**Acceptance**: Streaming and non-streaming requests both work, traces capture correct token counts.

---

## Loop 5.5: Storage Layer — Repository Pattern Refactoring

**Goal**: Refactor the storage layer into modular, swappable repositories. SQLite stays as the lite/dev backend. The abstraction must cleanly support ClickHouse + PostgreSQL + Redis as the production stack without touching the proxy or analysis layers.

**Context files**: `docs/architecture/SYSTEM_ARCHITECTURE.md` (Storage Architecture section, Technical Choices 2–4), `docs/architecture/ARCHITECTURE_SUPPLEMENT.md`

**Design**:

The north-star architecture has *three* storage concerns, each with different backends:

| Concern | Dev/Lite (SQLite) | Production |
|---|---|---|
| **Traces & Spans** (analytical, high-volume) | SQLite | ClickHouse |
| **Metadata** (tenants, configs, audit) | SQLite | PostgreSQL |
| **Cache** (hot queries, sessions) | In-memory HashMap | Redis |

The current `StorageBackend` trait handles only traces. Refactor into focused repository traits and a composite `Storage` struct.

**Tasks**:

1. **Split `StorageBackend` into focused repository traits** in `llmtrace-core`:
   - `TraceRepository` — store/query traces and spans (same methods as current `StorageBackend`)
   - `MetadataRepository` — tenant CRUD, security config, audit events
   - `CacheLayer` — generic get/set/invalidate with TTL
   - Keep `SecurityAnalyzer` unchanged (it's already clean)

2. **Add metadata types** to `llmtrace-core`:
   - `Tenant` — id, name, plan, quotas, created_at, config (JsonValue)
   - `TenantConfig` — security thresholds, feature flags
   - `AuditEvent` — tenant_id, event_type, actor, resource, data, timestamp
   - Keep it minimal — only what's needed for the trait signatures

3. **Add a `Storage` composite struct** in `llmtrace-core`:
   ```rust
   pub struct Storage {
       pub traces: Arc<dyn TraceRepository>,
       pub metadata: Arc<dyn MetadataRepository>,
       pub cache: Arc<dyn CacheLayer>,
   }
   ```

4. **Add `StorageProfile` enum + factory** in `llmtrace-storage`:
   ```rust
   pub enum StorageProfile {
       /// SQLite for everything — zero infrastructure
       Lite { database_path: String },
       /// In-memory only — for tests
       Memory,
   }
   
   impl StorageProfile {
       pub async fn build(self) -> Result<Storage> { ... }
   }
   ```
   Production profiles (ClickHouse/PG/Redis) will be added in later loops — the factory just needs to be extensible.

5. **Implement SQLite backends for all three traits**:
   - `SqliteTraceRepository` — migrate existing `SqliteStorage` (rename, impl new trait)
   - `SqliteMetadataRepository` — new, with tables for tenants, security_configs, audit_events
   - `InMemoryCacheLayer` — simple `DashMap<String, (Bytes, Instant)>` with TTL expiry

6. **Keep `InMemoryStorage` as `InMemoryTraceRepository`** — rename, impl `TraceRepository`

7. **Update the proxy** (`llmtrace-proxy`):
   - Replace `Arc<dyn StorageBackend>` with `Storage` in `AppState`
   - Use `storage.traces` for trace capture
   - Update health endpoint to report health of all three subsystems
   - Load storage from `StorageProfile::Lite` or `StorageProfile::Memory` based on config

8. **Update `ProxyConfig`** to include a `storage` section:
   ```yaml
   storage:
     profile: "lite"          # "lite" | "memory"
     database_path: "llmtrace.db"
   ```
   Replace the flat `database_url` field with a structured storage config.

**Performance considerations** (don't be dogmatic):
- Trait objects (`dyn TraceRepository`) at the boundary are fine — the overhead is negligible vs IO
- No unnecessary wrapper layers within a single backend implementation
- The cache layer is *optional* — if cache misses, go direct to the backing store
- Hot path (trace ingestion) should not go through the cache layer at all
- Keep `store_trace` / `store_span` as lean as possible — no extra allocations

**Do NOT**:
- Add ClickHouse, PostgreSQL, or Redis implementations yet — that's a later loop
- Over-abstract — three traits + one composite is enough
- Add a generic `Repository<T>` pattern — the three concerns have different query shapes

**Acceptance**:
- `StorageBackend` trait is removed, replaced by `TraceRepository` + `MetadataRepository` + `CacheLayer`
- `Storage` composite works with `StorageProfile::Lite` (SQLite) and `StorageProfile::Memory`
- Proxy compiles and works with the new storage layer
- All existing tests pass (adapted to new trait names)
- New tests for `MetadataRepository` (tenant CRUD, audit events)
- New tests for `CacheLayer` (get/set/TTL/invalidate)
- `cargo test --workspace` passes, `cargo clippy --workspace -- -D warnings` clean

---

## Loop 6: Configuration & CLI

**Goal**: Add proper CLI and configuration management.

**Tasks**:
- Use `clap` for CLI argument parsing
- Support:
  - `llmtrace proxy --config config.yaml` — start the proxy
  - `llmtrace validate --config config.yaml` — validate configuration
  - `--version`, `--help`
- Create a default `config.example.yaml` with all options documented
- Environment variable overrides (e.g., `LLMTRACE_LISTEN_ADDR`, `LLMTRACE_UPSTREAM_URL`)
- Add `tracing` + `tracing-subscriber` for structured logging
- Commit and push

**Acceptance**: Binary starts with config file, env vars work, `--help` shows usage.

---

## Loop 7: Python Bindings

**Goal**: Create Python bindings so users can `pip install` and use the SDK.

**Context files**: `docs/architecture/TRANSPARENT_PROXY.md` (Python SDK section)

**Tasks**:
- Set up `llmtrace-python` with PyO3 and maturin
- Expose Python API:
  - `LLMSecTracer` class — wraps the core tracer
  - `instrument(client)` function — wraps an OpenAI client to add tracing
  - `configure(config_dict)` — configure from Python
- Add a `pyproject.toml` for maturin build
- Add basic Python tests in `tests/test_python.py`
- Commit and push

**Acceptance**: `maturin develop` succeeds, Python import works, basic test passes.

---

## Loop 8: Integration Test & Polish

**Goal**: End-to-end integration test and documentation.

**Tasks**:
- Create an integration test that:
  1. Starts the proxy server
  2. Starts a mock LLM upstream (returns canned responses)
  3. Sends requests through the proxy
  4. Verifies traces are stored in SQLite
  5. Verifies security findings are generated for injection attempts
- Add top-level `README.md` with:
  - Quick start (binary + config)
  - Python SDK usage
  - Architecture overview (link to docs)
  - Configuration reference
- Add `LICENSE` (MIT or Apache-2.0 — your choice)
- Final `cargo fmt`, `cargo clippy`, `cargo test`
- Commit and push

**Acceptance**: Full test suite passes, README is clear, repo is clean.

---

# Phase 2: Production Readiness

## Loop 9: REST Query API

**Goal**: Add HTTP API endpoints for querying traces, spans, and security findings — so users don't need direct SQLite access.

**Tasks**:
- Add new routes to the proxy's axum router:
  - `GET /api/v1/traces` — list traces with filters (tenant, time range, provider, model, limit, offset)
  - `GET /api/v1/traces/:trace_id` — get a single trace with all spans
  - `GET /api/v1/spans` — list spans with filters (security_score range, operation_name, model)
  - `GET /api/v1/spans/:span_id` — get a single span
  - `GET /api/v1/stats` — storage stats for a tenant
  - `GET /api/v1/security/findings` — list spans with security findings (security_score > 0)
- Tenant identification via `Authorization: Bearer` header or `X-LLMTrace-Tenant-ID` header (reuse existing `resolve_tenant` logic)
- JSON responses with proper pagination (limit, offset, total count)
- Query parameters map to `TraceQuery` fields
- Add tests for each endpoint
- Commit and push

**Acceptance**: All API endpoints return correct filtered data, pagination works, tests pass.

---

## Loop 10: LLM Provider Auto-Detection

**Goal**: Automatically detect the LLM provider from the request instead of hardcoding `LLMProvider::OpenAI`.

**Tasks**:
- Detect provider from:
  1. Request URL path patterns (`/v1/chat/completions` → OpenAI-compatible, `/api/generate` → Ollama, `/v1/messages` → Anthropic)
  2. Request headers (e.g., `x-api-key` + Anthropic URL patterns)
  3. Upstream URL hostname (api.openai.com → OpenAI, api.anthropic.com → Anthropic, etc.)
  4. Custom header `X-LLMTrace-Provider` for explicit override
- Extract response metadata per provider (different response formats for usage/tokens)
- Parse Anthropic-style responses (`content[0].text`, `usage.input_tokens`/`output_tokens`)
- Parse Ollama-style responses (`response`, `eval_count`/`prompt_eval_count`)
- Store the detected provider on the span
- Add tests with mock responses for each provider format
- Commit and push

**Acceptance**: Provider is correctly detected and stored for OpenAI, Anthropic, Ollama, and vLLM requests.

---

## Loop 11: Cost Estimation Engine

**Goal**: Estimate costs per request based on model and token counts.

**Tasks**:
- Create a cost estimation module in `llmtrace-core` or `llmtrace-proxy`:
  - Pricing table for common models (GPT-4, GPT-4o, GPT-3.5, Claude 3.5 Sonnet/Haiku/Opus, Llama, Qwen — input/output per 1M tokens)
  - `estimate_cost(provider, model, prompt_tokens, completion_tokens) -> Option<f64>`
  - Support custom pricing via config (override or add models)
  - Return `None` for unknown models (don't guess)
- Wire into trace capture: set `estimated_cost_usd` on spans
- Add `total_cost` aggregation to the stats endpoint
- Add a config section for custom model pricing
- Add tests
- Commit and push

**Acceptance**: Known models get cost estimates stored on spans, custom pricing works via config.

---

## Loop 12: Alert Engine — Webhook Notifications

**Goal**: Send webhook notifications when security findings exceed thresholds.

**Tasks**:
- Add alert configuration to `ProxyConfig`:
  ```yaml
  alerts:
    enabled: true
    webhook_url: "https://hooks.slack.com/..."
    min_severity: "High"          # Only alert on High or Critical
    min_security_score: 70
    cooldown_seconds: 300         # Don't re-alert same pattern within 5 min
  ```
- Implement `AlertEngine` in the proxy:
  - After security analysis, check if findings exceed thresholds
  - If so, POST a JSON payload to the webhook URL with trace details, findings, and timestamp
  - Respect cooldown to prevent alert spam
  - Fire-and-forget (async, don't block trace storage)
- Webhook payload format (Slack-compatible):
  ```json
  {
    "text": "🚨 Security Alert: prompt_injection detected",
    "blocks": [...]
  }
  ```
- Add tests with a mock webhook server
- Commit and push

**Acceptance**: Webhook fires on high-severity findings, cooldown works, doesn't block the proxy.

---

## Loop 13: Tenant Management API

**Goal**: CRUD API for managing tenants and their configurations.

**Tasks**:
- Add tenant management routes:
  - `POST /api/v1/tenants` — create tenant (name, plan)
  - `GET /api/v1/tenants` — list tenants
  - `GET /api/v1/tenants/:id` — get tenant details + stats
  - `PUT /api/v1/tenants/:id` — update tenant config
  - `DELETE /api/v1/tenants/:id` — soft-delete tenant
- Tenant config includes:
  - Security analysis toggle
  - Custom alert thresholds
  - Rate limits
  - Retention policy
- Auto-create tenant on first request if not exists (upsert on proxy flow)
- Audit events logged for all tenant operations
- Add tests
- Commit and push

**Acceptance**: Tenant CRUD works, auto-creation on first proxy request, audit trail recorded.

---

# Phase 3: Production Storage Backends

## Loop 14: ClickHouse TraceRepository ✅ COMPLETE

Implemented in commit `dcf100d`. ClickHouseTraceRepository with MergeTree engine, ZSTD compression, feature-gated, 9 ignored tests. See `crates/llmtrace-storage/src/clickhouse.rs`.

---

## Loop 15: PostgreSQL MetadataRepository

**Goal**: Implement a PostgreSQL-backed `MetadataRepository` in `llmtrace-storage` for production tenant/config/audit storage.

**Context files**: `docs/architecture/SYSTEM_ARCHITECTURE.md` (PostgreSQL Configuration)

**Tasks**:

1. **Add `sqlx` PostgreSQL feature** to `llmtrace-storage/Cargo.toml`:
   - Gate behind a `postgres` Cargo feature:
     ```toml
     [features]
     default = []
     clickhouse = ["dep:clickhouse"]
     postgres = ["sqlx/postgres"]
     ```
   - The existing `sqlx` dependency already has `runtime-tokio-rustls` and `chrono`/`uuid` features — just add `postgres` conditionally.

2. **Create `crates/llmtrace-storage/src/postgres.rs`** implementing `PostgresMetadataRepository`:
   - Constructor takes a PostgreSQL connection URL (e.g., `postgres://user:pass@localhost/llmtrace`)
   - On construction, run migrations to create tables:
     ```sql
     CREATE TABLE IF NOT EXISTS tenants (
         id UUID PRIMARY KEY,
         name VARCHAR(255) NOT NULL,
         plan VARCHAR(50) NOT NULL,
         created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
         config JSONB NOT NULL DEFAULT '{}'
     );
     CREATE TABLE IF NOT EXISTS tenant_configs (
         tenant_id UUID PRIMARY KEY REFERENCES tenants(id),
         security_thresholds JSONB NOT NULL DEFAULT '{}',
         feature_flags JSONB NOT NULL DEFAULT '{}'
     );
     CREATE TABLE IF NOT EXISTS audit_events (
         id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
         tenant_id UUID NOT NULL REFERENCES tenants(id),
         event_type VARCHAR(100) NOT NULL,
         actor VARCHAR(255) NOT NULL,
         resource VARCHAR(255) NOT NULL,
         data JSONB NOT NULL DEFAULT '{}',
         timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
     );
     CREATE INDEX IF NOT EXISTS idx_audit_tenant_time ON audit_events(tenant_id, timestamp DESC);
     CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_events(tenant_id, event_type);
     ```

3. **Implement `MetadataRepository` trait** for `PostgresMetadataRepository`:
   - `create_tenant` — INSERT with conflict handling
   - `get_tenant` — SELECT by id
   - `update_tenant` — UPDATE name, plan, config
   - `list_tenants` — SELECT all
   - `delete_tenant` — DELETE (hard delete)
   - `get_tenant_config` — SELECT from tenant_configs
   - `upsert_tenant_config` — INSERT ON CONFLICT UPDATE
   - `record_audit_event` — INSERT into audit_events
   - `query_audit_events` — SELECT with filters from `AuditQuery`
   - `health_check` — simple `SELECT 1`
   - Use native JSONB, UUID, TIMESTAMPTZ

4. **Add tests** (same pattern as Loop 14):
   - `#[cfg(feature = "postgres")]` gated, `#[ignore]` by default
   - Env var: `LLMTRACE_POSTGRES_URL`
   - Test: create_tenant → get_tenant roundtrip
   - Test: update_tenant changes fields
   - Test: list_tenants returns all
   - Test: delete_tenant removes tenant
   - Test: upsert_tenant_config create + update
   - Test: record_audit_event → query_audit_events
   - Test: audit query with event_type filter
   - Test: audit query with time range filter
   - Test: health_check succeeds

5. **Update `llmtrace-storage/src/lib.rs`** — conditionally export.

**Acceptance**:
- `cargo build --workspace` passes (postgres not compiled by default)
- `cargo build -p llmtrace-storage --features postgres` compiles cleanly
- `cargo clippy --workspace -- -D warnings` passes
- `cargo test --workspace` passes
- With a running PostgreSQL: `cargo test -p llmtrace-storage --features postgres -- --ignored` passes
- All existing tests still pass

---

## Loop 16: Redis CacheLayer + Production StorageProfile + Docker Compose

**Goal**: Implement Redis-backed `CacheLayer`, wire everything into a `StorageProfile::Production` variant, update config/proxy to support it, and provide a Docker Compose file for local dev.

**Tasks**:

1. **Add `redis` crate dependency** to `llmtrace-storage/Cargo.toml` behind a `redis_backend` feature.

2. **Create `crates/llmtrace-storage/src/redis_cache.rs`** implementing `RedisCacheLayer`:
   - Use `redis::aio::ConnectionManager`
   - `get` → GET, `set` → SET EX, `invalidate` → DEL, `health_check` → PING

3. **Add `StorageProfile::Production`** wiring ClickHouse + PostgreSQL + Redis.

4. **Update `StorageConfig`** in core with optional `clickhouse_url`, `clickhouse_database`, `postgres_url`, `redis_url` fields.

5. **Update proxy** to construct `StorageProfile::Production` when `profile = "production"`. Enable all storage features in proxy Cargo.toml.

6. **Update `config.example.yaml`** with production storage examples.

7. **Create `docker-compose.yml`** with ClickHouse, PostgreSQL, and Redis services.

8. **Add Redis tests** (`#[ignore]`, env var `LLMTRACE_REDIS_URL`).

9. **Add full production profile integration test** (`#[ignore]`).

**Acceptance**: Default build works, proxy compiles with all backends, Docker Compose starts all services, all ignored tests pass with services running.

---

## Loop 17: Agent Cost Caps & Budget Enforcement

**Goal**: Per-agent budget caps (hourly/daily/weekly/monthly USD) and per-request token limits with real-time enforcement.

**Design**: Hard caps → 429 rejection with reset time. Soft caps → allow + alert. Agent identified via `X-LLMTrace-Agent-ID` header.

**Tasks**:

1. **Core types**: `BudgetWindow`, `BudgetCap`, `TokenCap`, `CostCapConfig`, `AgentCostCap` in llmtrace-core.
2. **Config**: Add `cost_caps` section to `ProxyConfig` + `config.example.yaml`.
3. **CostTracker** module (`cost_caps.rs`): cache-backed spend tracking per tenant/agent/window/period. Period keys with auto-TTL.
4. **Pre-request enforcement**: token caps (reject if exceeded), budget caps (check running total).
5. **Post-request tracking**: async spend recording via cost estimation engine.
6. **REST API**: `GET /api/v1/costs/current` — real-time spend per window with remaining budget.
7. **Alert integration**: soft cap exceeded or 80% threshold → webhook alert.
8. **Tests**: period key calculation, token cap enforcement, budget checking, integration tests.

**Acceptance**: Hard caps reject with 429 + reset time, soft caps alert, agent overrides work, visibility API returns spend data, all tests pass.

---

## Loop 18: Agent Tool & Skill Usage Tracing

**Goal**: Capture what an agent *did* — which tools/skills it invoked, why, and any external actions (commands, web requests, file access). Full agent action observability.

**Design**:

| Action Type | Examples | Captured Data |
|-------------|----------|---------------|
| Tool call | function_call, tool_use | tool name, args, result, duration |
| Skill invocation | agent skill/plugin | skill name, trigger reason, outcome |
| Command execution | shell, subprocess, exec | command, exit code, stdout summary |
| Web access | HTTP, curl, fetch, browser | URL, method, status code, response size |
| File access | read, write, delete | path, operation, size |

**Tasks**:

1. **Core types**: `AgentActionType` enum, `AgentAction` struct in llmtrace-core.
2. **Extend `TraceSpan`** with `agent_actions: Vec<AgentAction>` + helper methods (`add_agent_action`, `tool_calls()`, `web_accesses()`, `commands()`).
3. **Auto-parse tool calls** from proxied OpenAI (`tool_calls`/`function_call`) and Anthropic (`tool_use`) responses into `AgentAction` entries automatically.
4. **Reporting API**: `POST /api/v1/traces/:trace_id/actions` — client reports actions that happened after the LLM call (commands executed, web requests made, etc.).
5. **Query extensions**: `has_tool_calls=true`, `has_web_access=true`, `has_commands=true`, `action_name=X` filters. `GET /api/v1/actions/summary` for aggregate view.
6. **Security analysis**: flag suspicious commands (`rm -rf`, `curl | sh`, base64-encoded), bad domains, sensitive file paths → generate `SecurityFinding`.
7. **Storage**: `agent_actions` as JSON string column in SQLite and ClickHouse (ZSTD compressed).
8. **Python SDK**: `tracer.report_action(...)` method.
9. **Tests**: serialization, auto-parsing, security analysis, API roundtrips.

**Do NOT**: implement action streaming/replay, capture full stdout/response bodies (truncate at 4KB).

**Acceptance**: Tool calls auto-extracted from LLM responses, client reporting API works, actions queryable, suspicious actions flagged, Python SDK supports reporting, all tests pass.
