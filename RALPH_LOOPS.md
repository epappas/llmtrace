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
