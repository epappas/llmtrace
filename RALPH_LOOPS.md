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
- Add basic Python tests in `crates/llmtrace-python/tests/test_python.py`
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

---

# Phase 4: Platform Maturity

## Loop 19: ML-Based Prompt Injection Detection (Candle)

**Goal**: Upgrade from regex-only prompt injection detection to an ML classifier using HuggingFace's `candle` framework, running inference locally in Rust with no Python dependency.

**Context files**: `docs/architecture/SYSTEM_ARCHITECTURE.md` (Security Architecture), `crates/llmtrace-security/src/lib.rs` (existing RegexSecurityAnalyzer)

**Tasks**:

1. **Add candle dependencies** to `llmtrace-security/Cargo.toml` behind an `ml` feature gate:
   - `candle-core`, `candle-nn`, `candle-transformers`, `tokenizers`, `hf-hub` (for model download)
   - Keep regex analyzer as the default — ML is opt-in

2. **Create `crates/llmtrace-security/src/ml_detector.rs`**:
   - `MLSecurityAnalyzer` struct implementing `SecurityAnalyzer` trait
   - Use a small text classification model (e.g., `distilbert-base-uncased` fine-tuned for injection detection, or a similar small model from HuggingFace)
   - Model loading: download from HuggingFace Hub on first use, cache locally
   - `analyze_request` — tokenize prompt, run inference, return `SecurityFinding` if injection score > threshold
   - `analyze_response` — same for response content
   - Configurable confidence threshold (default 0.8)
   - Fallback: if ML model fails to load, log warning and delegate to regex analyzer

3. **Create `crates/llmtrace-security/src/ensemble.rs`**:
   - `EnsembleSecurityAnalyzer` that combines regex + ML results
   - Strategy: run both, take highest severity finding, boost confidence when both agree
   - This becomes the default analyzer when `ml` feature is enabled

4. **Add config options** to `ProxyConfig`:
   ```yaml
   security_analysis:
     ml_enabled: true
     ml_model: "protectai/deberta-v3-base-prompt-injection-v2"  # or similar
     ml_threshold: 0.8
     ml_cache_dir: "~/.cache/llmtrace/models"
   ```

5. **Benchmark**: add a simple benchmark comparing regex vs ML vs ensemble latency (use `criterion` or just a test with timing)

6. **Tests**:
   - ML analyzer detects known injection patterns
   - ML analyzer doesn't false-positive on benign prompts
   - Ensemble combines results correctly
   - Graceful fallback when model unavailable
   - Feature-gated: `#[cfg(feature = "ml")]`

**Acceptance**: ML detection works behind feature flag, ensemble combines regex+ML, fallback works, all existing tests pass.

---

## Loop 20: OpenTelemetry Ingestion Gateway

**Goal**: Accept traces in OpenTelemetry format (OTLP/HTTP) alongside the existing proxy, so users can send OTEL-instrumented traces directly.

**Context files**: `docs/architecture/SYSTEM_ARCHITECTURE.md` (Trace Ingestion Engine)

**Tasks**:

1. **Add OTEL dependencies** to a new `crates/llmtrace-ingest/` crate (or extend proxy):
   - `opentelemetry-proto` for protobuf types
   - `prost` for protobuf decoding
   - `tonic` for gRPC (optional, behind feature gate — HTTP/JSON first)

2. **Add OTLP/HTTP endpoint** to the proxy:
   - `POST /v1/traces` — accepts OTLP JSON or protobuf trace export requests
   - Parse `ExportTraceServiceRequest`, convert OTEL spans to `TraceSpan`
   - Map OTEL attributes to LLMTrace fields (model name, token counts, etc. from semantic conventions)
   - Store via existing `TraceRepository`
   - Run security analysis on span content

3. **OTEL → LLMTrace mapping**:
   - `service.name` → tenant identification
   - `gen_ai.system` → `LLMProvider`
   - `gen_ai.request.model` → `model_name`
   - `gen_ai.usage.prompt_tokens` / `gen_ai.usage.completion_tokens` → token counts
   - `gen_ai.prompt` / `gen_ai.completion` → prompt/response content
   - Unknown attributes → `tags` map

4. **Config**: `otel_ingest.enabled`, `otel_ingest.listen_addr` (can share port with proxy)

5. **Tests**: OTLP JSON roundtrip, attribute mapping, security analysis on ingested traces

**Acceptance**: OTLP/HTTP endpoint accepts traces, maps to internal format, stores and analyzes them, all existing tests pass.

---

## Loop 21: Web Dashboard (Next.js)

**Goal**: Build a web dashboard for viewing traces, security findings, cost data, and tenant management.

**Tasks**:

1. **Scaffold Next.js app** in `dashboard/`:
   - Next.js 14+ with App Router, TypeScript, Tailwind CSS
   - shadcn/ui component library for consistent UI

2. **Pages**:
   - `/` — Overview dashboard: trace count, security score distribution, cost summary, recent alerts
   - `/traces` — Trace list with filters (tenant, time range, provider, model, security score)
   - `/traces/[id]` — Trace detail: spans, agent actions, security findings, cost
   - `/security` — Security findings list, severity breakdown, top attack patterns
   - `/costs` — Cost dashboard: spend by tenant/agent/model, budget cap status, trends
   - `/tenants` — Tenant management CRUD
   - `/settings` — Configuration viewer

3. **API client**: typed fetch wrapper hitting the LLMTrace REST API

4. **Charts**: use `recharts` or `tremor` for time series, bar charts, pie charts

5. **Docker**: add `dashboard` service to `compose.yaml`, Dockerfile for Next.js

**Acceptance**: Dashboard runs, connects to proxy API, displays real data, all pages functional.

---

## Loop 22: CI/CD Pipeline (GitHub Actions)

**Goal**: Automated lint, test, build, and publish pipeline on every push/PR.

**Tasks**:

1. **`.github/workflows/ci.yml`** — runs on every push and PR:
   - `cargo fmt --check`
   - `cargo clippy --workspace -- -D warnings`
   - `cargo test --workspace`
   - Cache `~/.cargo` and `target/` for fast builds

2. **`.github/workflows/release.yml`** — runs on tag push (`v*`):
   - Build Docker image
   - Push to `ghcr.io/epappas/llmtrace-proxy`
   - Create GitHub Release with changelog

3. **`.github/workflows/security.yml`** — weekly:
   - `cargo audit`
   - `cargo deny check`
   - Dependabot alerts

4. **Badge**: add CI status badge to README.md

**Acceptance**: CI runs on every push, release workflow builds+pushes Docker image on tags, security scanning runs weekly.

---

## Loop 23: RBAC & Auth

**Goal**: API key management and role-based access control for multi-tenant security.

**Tasks**:

1. **API key management**:
   - Generate API keys per tenant (stored hashed in PostgreSQL)
   - `POST /api/v1/auth/keys` — create key, `DELETE` — revoke
   - Keys identify tenant + permission level

2. **Roles**: `admin` (full access), `operator` (read + write traces), `viewer` (read only)

3. **Auth middleware**: validate API key on every request, inject tenant context

4. **Tenant isolation enforcement**: all queries scoped to authenticated tenant

5. **Config**: `auth.enabled`, `auth.admin_key` (bootstrap key)

**Acceptance**: API keys work, roles enforced, tenant isolation via auth, admin can manage keys.

---

## Loop 24: Compliance Reporting

**Goal**: Automated compliance report generation for SOC2, GDPR, HIPAA.

**Tasks**:

1. **Report generator** in `crates/llmtrace-proxy/src/compliance.rs`:
   - Query audit events, security findings, access logs for a time period
   - Generate structured JSON reports

2. **Report types**: SOC2 audit trail, GDPR data processing records, HIPAA access logs

3. **API**: `POST /api/v1/reports/generate` with report type and date range, `GET /api/v1/reports/:id`

4. **PDF export**: optional, using a lightweight PDF library

**Acceptance**: Reports generate with real data, cover required compliance fields, API works.

---

## Loop 25: gRPC Ingestion Gateway

**Goal**: High-throughput gRPC endpoint for trace ingestion using `tonic`.

**Tasks**:

1. **Define protobuf** schema in `crates/llmtrace-proto/llmtrace.proto` for trace/span ingestion
2. **Implement gRPC server** using `tonic` in the proxy (or separate binary)
3. **Streaming ingestion**: support client-side streaming for batch trace upload
4. **Config**: `grpc.enabled`, `grpc.listen_addr`

**Acceptance**: gRPC endpoint accepts traces, stores them, high throughput (benchmark vs HTTP).

---

## Loop 26: Kubernetes Operator + Helm Chart

**Goal**: K8s-native deployment with Helm chart and optional CRD operator.

**Tasks**:

1. **Helm chart** in `deployments/helm/llmtrace/`:
   - Proxy deployment + service + HPA
   - ClickHouse, PostgreSQL, Redis as subcharts (or external references)
   - ConfigMap for proxy config, Secret for credentials
   - Ingress configuration
   - `values.yaml` with sensible defaults, `values-production.yaml` for prod

2. **CRD** (optional): `LLMTraceInstance` custom resource for declarative config

3. **Docs**: deployment guide in `docs/deployment/kubernetes.md`

**Acceptance**: `helm install` deploys working stack, HPA scales proxy, docs cover setup.

---

## Loop 27: WASM Bindings

**Goal**: WebAssembly bindings for browser-based security analysis and trace viewing.

**Tasks**:

1. **Create `crates/llmtrace-wasm/`** using `wasm-bindgen`
2. **Expose**: prompt injection analysis, PII detection, cost estimation to JS
3. **Build**: `wasm-pack build` producing npm package
4. **Tests**: browser-compatible test suite

**Acceptance**: WASM module loads in browser, security analysis works client-side.

---

## Loop 28: Node.js Bindings (NAPI)

**Goal**: Native Node.js bindings via NAPI-RS for server-side JS/TS integration.

**Tasks**:

1. **Create `crates/llmtrace-nodejs/`** using `napi-rs`
2. **Expose**: `LLMSecTracer` class, `instrument()` function, action reporting
3. **TypeScript types**: generated `.d.ts` files
4. **npm package**: `package.json`, build scripts, publish-ready
5. **Tests**: Jest test suite

**Acceptance**: `npm install` works, TypeScript types correct, tracer instruments LLM calls.

---

# Phase 5: AI Engineer Review Fixes

> Driven by independent AI Engineer review (rated 6.5/10 AI/ML maturity, ~55% architecture coverage).
> See ADR-009 in docs/architecture/ADR.md for rationale.

## Loop 29: Statistical Anomaly Detection Engine

**Goal**: Per-tenant anomaly detection using statistical baselines — the #1 gap identified by AI engineer review.

**Tasks**:
1. Create `crates/llmtrace-proxy/src/anomaly.rs` with `AnomalyDetector`
2. Track per-tenant moving averages: request cost, token usage, request velocity, latency
3. Sliding window with configurable size (default 100), flag on mean + Nσ (default 3σ)
4. Severity mapping: 3σ = Medium, 5σ = High, 10σ = Critical
5. Use `CacheLayer` for state persistence
6. Wire into proxy pipeline (async, post-trace-capture)
7. Integrate with alert engine
8. Config section `anomaly_detection` in ProxyConfig
9. Tests for statistical calculations and detection

**Acceptance**: Anomalies detected and alerted for cost/token/velocity/latency spikes, all tests pass.

---

## Loop 30: Real-time Streaming Security Analysis

**Goal**: Incremental security analysis during SSE streaming, not just after completion.

**Tasks**:
1. Extend `StreamingAccumulator` with `should_analyze()` check (every N tokens or on pattern match)
2. Run regex patterns on accumulated buffer incrementally during streaming
3. Generate interim `SecurityFinding`s before stream completes
4. Fire alerts for critical findings mid-stream (don't wait for completion)
5. Configurable analysis interval (default: every 50 tokens)
6. Tests with mock SSE streams containing injection patterns

**Acceptance**: Security findings generated during streaming, not just after. Mid-stream alerts fire.

---

## Loop 31: Expanded PII Detection

**Goal**: International PII patterns, context-aware suppression, and PII redaction capability.

**Tasks**:
1. Add international PII patterns: UK NIN, IBAN, EU passport, non-US phone formats, NHS number
2. Context-aware false-positive suppression (code examples, documentation patterns)
3. Add PII redaction/masking option (replace detected PII with `[REDACTED]` or `[PII:TYPE]`)
4. Configurable redaction mode: `alert_only` (current), `alert_and_redact`, `redact_silent`
5. Config section for PII in ProxyConfig
6. Tests for each new pattern, false positive tests, redaction tests

**Acceptance**: International PII detected, false positives reduced, redaction works when enabled.

---

## Loop 32: ML-based PII Detection via NER

**Goal**: Named Entity Recognition model for detecting PII that regex can't catch (names, addresses, medical terms).

**Tasks**:
1. Add NER model support in `llmtrace-security` behind `ml` feature flag
2. Use a small NER model (e.g., `dslim/bert-base-NER`) via Candle
3. Detect: person names, organizations, locations, medical terms
4. Map NER entities to `SecurityFinding` with appropriate severity
5. Integrate into ensemble analyzer (regex PII + ML NER)
6. Tests with known PII samples

**Acceptance**: ML-based PII detection works behind feature flag, ensemble combines regex + NER findings.

---

## Loop 33: ML Inference Monitoring + Model Warm-up

**Goal**: Track ML model inference latency and pre-load models at startup.

**Tasks**:
1. Add inference timing to ML detectors (prompt injection + NER)
2. Expose inference latency metrics (P50/P95/P99) via internal tracking
3. Pre-load ML models at proxy startup (not on first request)
4. Add model download health check to startup sequence
5. Config: `ml.preload: true`, `ml.download_timeout_seconds: 300`
6. Tests for warm-up and timing

**Acceptance**: Models pre-loaded at startup, inference timing tracked, no cold-start penalty on first request.

---

## Loop 34: Multi-Channel Alerting

**Goal**: Alert via Slack, PagerDuty, and email in addition to generic webhooks.

**Tasks**:
1. Extend alert engine with channel abstraction (`AlertChannel` trait)
2. Implement: `SlackChannel` (Incoming Webhook API), `PagerDutyChannel` (Events API v2), `EmailChannel` (SMTP)
3. Config: multiple alert channels per tenant, per-channel severity filters
4. Alert escalation: if not acknowledged within N minutes, escalate to next channel
5. Deduplication across channels (same finding doesn't alert on all channels)
6. Tests with mock servers for each channel

**Acceptance**: Alerts fire to configured channels, escalation works, deduplication prevents spam.

---

## Loop 35: Externalize Pricing + OWASP LLM Top 10 Tests

**Goal**: Move pricing to config file and add structured security test framework.

**Tasks**:
1. Externalize model pricing to a YAML/JSON config file (not hardcoded)
2. Support runtime pricing updates without rebuild
3. Add OWASP LLM Top 10 test suite as integration tests:
   - LLM01: Prompt Injection
   - LLM02: Insecure Output Handling
   - LLM06: Sensitive Information Disclosure
   - LLM07: Insecure Plugin Design (agent action analysis)
4. Document test coverage against OWASP categories
5. Tests for pricing config loading and OWASP patterns

**Acceptance**: Pricing loaded from config, OWASP test suite documents coverage.

---

# Phase 6: MLOps Review Fixes

> Driven by independent MLOps Engineer review (rated 7.0/10 operational readiness).
> See ADR-009 for rationale.

## Loop 36: Graceful Shutdown + Signal Handling

**Goal**: Handle SIGTERM/SIGINT with connection draining — critical for Kubernetes deployments.

**Tasks**:
1. Add `tokio::signal` handling for SIGTERM and SIGINT
2. Graceful shutdown on axum server (drain existing connections)
3. Coordinated shutdown of gRPC server
4. Track background tasks (trace capture) via `JoinSet` or `TaskTracker`
5. Wait for in-flight tasks before exit (with timeout)
6. Add `terminationGracePeriodSeconds: 60` to Helm chart
7. Tests for shutdown behavior

**Acceptance**: Clean shutdown on SIGTERM, in-flight traces complete, no data loss.

---

## Loop 37: Prometheus Metrics Endpoint

**Goal**: `/metrics` endpoint for runtime observability — currently zero metrics export.

**Tasks**:
1. Add `prometheus` or `metrics-rs` crate
2. Expose `/metrics` endpoint with:
   - `llmtrace_requests_total` (counter, by provider/model/status)
   - `llmtrace_request_duration_seconds` (histogram)
   - `llmtrace_tokens_total` (counter, prompt/completion)
   - `llmtrace_security_findings_total` (counter, by severity/type)
   - `llmtrace_circuit_breaker_state` (gauge, by subsystem)
   - `llmtrace_storage_operations_total` (counter, by operation/status)
   - `llmtrace_cost_usd_total` (counter, by tenant/model)
   - `llmtrace_anomalies_total` (counter, by type)
3. Wire metrics into proxy handler, storage, security, anomaly detector
4. Tests for metric increments

**Acceptance**: `/metrics` returns Prometheus-format metrics, all key operations instrumented.

---

## Loop 38: Database Migration Management

**Goal**: Versioned schema migrations for safe evolution.

**Tasks**:
1. Add `sqlx migrate` support for PostgreSQL with versioned migration files
2. Add versioned DDL scripts for ClickHouse
3. Schema version tracking table
4. CLI subcommand: `llmtrace-proxy migrate` to run pending migrations
5. Option to auto-migrate on startup (dev) or require explicit migration (prod)
6. Tests for migration ordering

**Acceptance**: Migrations versioned and tracked, CLI can apply them, safe schema evolution.

---

## Loop 39: Secrets Hardening + Startup Probe

**Goal**: Fix plaintext secrets in Helm and add startup probe for cold starts.

**Tasks**:
1. Remove placeholder passwords from `values-production.yaml`
2. Enable Redis auth in production values
3. Document External Secrets Operator / Sealed Secrets workflow
4. Add `startupProbe` to Helm deployment (failureThreshold × periodSeconds = 300s)
5. Add health check for storage initialization during startup
6. Tests for startup sequence

**Acceptance**: No plaintext secrets in checked-in values, startup probe prevents premature liveness kills.

---

## Loop 40: Integration Tests in CI + Container Scanning

**Goal**: Run integration tests with Docker Compose in CI, scan container images.

**Tasks**:
1. Add Docker Compose service startup to CI test job
2. Run integration tests against real ClickHouse/PostgreSQL/Redis
3. Add Trivy container image scanning to release workflow
4. Fail release on critical/high CVEs
5. Document integration test setup

**Acceptance**: Integration tests run in CI with real services, container images scanned on release.

---

## Loop 41: Per-tenant Rate Limiting + Compliance Report Persistence

**Goal**: Tenant-isolated rate limiting and persistent compliance reports.

**Tasks**:
1. Implement per-tenant rate limiting middleware (token bucket or sliding window)
2. Use CacheLayer for rate limit state (Redis-backed in production)
3. Config: per-tenant rate limits with default and override
4. Persist compliance reports to PostgreSQL (currently in-memory HashMap)
5. Add report listing/pagination endpoint
6. Tests for rate limiting isolation and report persistence

**Acceptance**: Per-tenant rate limits enforced, compliance reports survive restarts.
