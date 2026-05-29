# Proxy Configuration Catalogue

This page catalogues every configuration field recognised by the LLMTrace proxy. Fields are grouped by YAML section to match the structure of the config file. Each entry includes the YAML path, any environment-variable override, type, default, accepted values, and a description of operational consequences.

## How configuration loads

The proxy reads a single YAML file whose path is supplied via `--config <file>` or the `LLMTRACE_CONFIG` environment variable. When no file is supplied, built-in defaults are used for every field.

After loading the file, the proxy applies a sidecar runtime overlay (`config.runtime.yaml`, written by `PUT /api/v1/config/features`) that sits between the file and environment-variable overrides. Then it applies environment-variable overrides. Finally, any `--log-level` / `--log-format` CLI flags win over all other sources.

**Override precedence (highest wins)**:

1. CLI flags (`--log-level`, `--log-format`)
2. Environment variables (`LLMTRACE_*`)
3. Sidecar runtime overlay (`config.runtime.yaml`)
4. Config file values (`--config`)
5. Built-in defaults

To validate a config without starting the proxy:

```bash
llmtrace-proxy validate --config config.yaml
```

---

## Top-level structure (YAML at a glance)

```yaml
listen_addr: "0.0.0.0:8080"
upstream_url: "https://api.openai.com"

storage:
  profile: "lite"

logging:
  level: "info"
  format: "text"

timeout_ms: 30000
connection_timeout_ms: 5000
max_connections: 1000

enable_tls: false
enable_security_analysis: true
enable_trace_storage: true
enable_streaming: true
max_request_size_bytes: 52428800
max_response_size_bytes: 52428800
security_analysis_timeout_ms: 5000
trace_storage_timeout_ms: 10000
llm_advisory_injection_enabled: true

rate_limiting: { ... }
circuit_breaker: { ... }
health_check: { ... }
alerts: { ... }
cost_estimation: { ... }
cost_caps: { ... }
security_analysis: { ... }
enforcement: { ... }
output_safety: { ... }
streaming_analysis: { ... }
pii: { ... }
anomaly_detection: { ... }
boundary_defense: { ... }
otel_ingest: { ... }
auth: { ... }
grpc: { ... }
judge: { ... }
action_router: { ... }
ml_pipeline: { ... }
shutdown: { ... }
server: { ... }
```

---

## Open questions (TODO)

- `LLMTRACE_DATAMARKING_ENABLED` and `LLMTRACE_DATAMARKING_SHADOW_MODE` appear in `pro.yaml` but are not wired through `apply_env_overrides` in `crates/llmtrace-proxy/src/config.rs`. Clarify whether these are applied via the Basilica lifecycle layer only, or whether they should be added to `apply_env_overrides`.
- `LLMTRACE_ZONE_DETECTION_ENABLED` appears in `pro.yaml` with the same open question.

---

## Catalogue

### Network / listener

| Field | YAML path | Env override | Type | Default | Allowed values |
|---|---|---|---|---|---|
| Listen address | `listen_addr` | `LLMTRACE_LISTEN_ADDR` | `string` | `"0.0.0.0:8080"` | Any valid `host:port` |
| Upstream URL | `upstream_url` | `LLMTRACE_UPSTREAM_URL` | `string` | `"https://api.openai.com"` | `http://` or `https://` URL |
| Request timeout | `timeout_ms` | — | `u64 ms` | `30000` | `> 0` |
| Connection timeout | `connection_timeout_ms` | — | `u64 ms` | `5000` | `> 0` |
| Max connections | `max_connections` | — | `u32` | `1000` | `>= 1` |
| Enable TLS | `enable_tls` | — | `bool` | `false` | `true` / `false` |
| TLS cert file | `tls_cert_file` | — | `string?` | `null` | File path; required when `enable_tls: true` |
| TLS key file | `tls_key_file` | — | `string?` | `null` | File path; required when `enable_tls: true` |

**`listen_addr`** — The address and port the proxy HTTP server binds to. Changing this requires a restart. All proxy, metrics (`/metrics`), and health (`/health`) endpoints are served from this address.

**`upstream_url`** — The base URL for the upstream LLM provider. The proxy strips its own path prefix and forwards the remainder. Must start with `http://` or `https://`. Supports OpenAI, vLLM, Ollama, Anthropic, and any OpenAI-compatible endpoint.

**`timeout_ms`** — Full round-trip timeout for upstream requests. When exceeded the proxy returns `504 Gateway Timeout`. Does not affect the enforcement sync analysis path (governed by `enforcement.timeout_ms`).

**`connection_timeout_ms`** — TCP connection-establishment timeout for the upstream socket. A tightly set value here surfaces DNS/connectivity problems quickly.

**`max_connections`** — Maximum concurrent upstream connections held open by the HTTP client. Exceeding this causes queuing inside the client pool; does not return 503 by itself.

**`enable_tls` / `tls_cert_file` / `tls_key_file`** — Enables TLS on the proxy listener. Both cert and key files are required when `enable_tls: true`; omitting either is a startup validation error. For Kubernetes deployments TLS termination at the ingress is usually preferred.

---

### Feature toggles (top-level booleans)

| Field | YAML path | Env override | Type | Default |
|---|---|---|---|---|
| Security analysis | `enable_security_analysis` | — | `bool` | `true` |
| Trace storage | `enable_trace_storage` | — | `bool` | `true` |
| Streaming | `enable_streaming` | — | `bool` | `true` |
| Advisory injection | `llm_advisory_injection_enabled` | — | `bool` | `true` |

**`enable_security_analysis`** — When `false`, all security analyzers are bypassed for every request. Traces are stored with `security_score: null` and no findings. The `pipeline_dropped` tag added in [#298](https://github.com/techlab-innov/llmtrace/issues/298) is stamped with `reason=disabled` on every dropped trace. This flag cannot currently be hot-swapped via the feature-flags API; it requires a restart.

**`enable_trace_storage`** — When `false`, completed spans are not persisted to the storage backend. The proxy still runs security analysis (if `enable_security_analysis: true`) and forwards the request; it just discards the trace record.

**`enable_streaming`** — When `false`, the proxy does not forward `Transfer-Encoding: chunked` / SSE responses from the upstream. Non-streaming requests are unaffected. Disabling this breaks streaming clients.

**`llm_advisory_injection_enabled`** — When `true` (default) and the synchronous enforcement pipeline produced at least one finding, the proxy prepends a synthetic `system` message to the messages array forwarded upstream, describing the detections. Applies to non-streaming chat-completions (`/v1/chat/completions`) only; streaming requests are left byte-exact. Can be hot-swapped via `PUT /api/v1/config/features` (`llm_advisory_injection_enabled`). See [#300](https://github.com/techlab-innov/llmtrace/issues/300).

---

### Request / response size limits

| Field | YAML path | Env override | Type | Default |
|---|---|---|---|---|
| Max request size | `max_request_size_bytes` | `LLMTRACE_MAX_REQUEST_BYTES` | `u64` | `52428800` (50 MiB) |
| Max response size | `max_response_size_bytes` | — | `u64` | `52428800` (50 MiB) |
| Security analysis timeout | `security_analysis_timeout_ms` | — | `u64 ms` | `5000` |
| Trace storage timeout | `trace_storage_timeout_ms` | — | `u64 ms` | `10000` |

**`max_request_size_bytes`** — Hard limit on the request body enforced by a Tower middleware layer before any handler runs. Requests exceeding this are rejected with `413 Payload Too Large`. The env override `LLMTRACE_MAX_REQUEST_BYTES` defaults to `1048576` (1 MiB) when the YAML field is set to 50 MiB — note that the env var applies a *separate* middleware-level cap that the proxy builder resolves at router build time; it is not patched into `ProxyConfig.max_request_size_bytes`. Must be `> 0`.

**`max_response_size_bytes`** — Responses from upstream larger than this value are truncated in the stored trace record, but forwarded to the downstream client in full. This prevents very large streaming completions from exhausting storage write buffers. Must be `> 0`.

**`security_analysis_timeout_ms`** — Timeout for the *async* (post-response) background security analysis task. Exceeding this does not affect the downstream client; the task is abandoned and the trace is stored without a security score.

**`trace_storage_timeout_ms`** — Timeout for the *async* trace-storage write. Exceeding this abandons the write silently; the circuit breaker accumulates the failure.

---

### `storage`

| Field | YAML path | Env override | Type | Default |
|---|---|---|---|---|
| Profile | `storage.profile` | `LLMTRACE_STORAGE_PROFILE` | `string` | `"lite"` |
| Database path | `storage.database_path` | `LLMTRACE_STORAGE_DATABASE_PATH` | `string` | `"llmtrace.db"` |
| ClickHouse URL | `storage.clickhouse_url` | `LLMTRACE_CLICKHOUSE_URL` | `string?` | `null` |
| ClickHouse database | `storage.clickhouse_database` | `LLMTRACE_CLICKHOUSE_DATABASE` | `string?` | `null` |
| PostgreSQL URL | `storage.postgres_url` | `LLMTRACE_POSTGRES_URL` | `string?` | `null` |
| Redis URL | `storage.redis_url` | `LLMTRACE_REDIS_URL` | `string?` | `null` |
| Auto migrate | `storage.auto_migrate` | — | `bool` | `true` |

**`storage.profile`** — Selects the storage backend. Accepted values:

- `"lite"` or `"sqlite"` (alias) — SQLite file at `database_path`. Zero infrastructure. Not suitable for multi-replica deployments because each pod gets its own SQLite file.
- `"memory"` — In-process `DashMap`; all data is lost on restart. Useful for CI and ephemeral dev environments.
- `"production"` — ClickHouse (traces), PostgreSQL (metadata), Redis (cache). Requires all three URLs.

The Basilica `starter.yaml` example uses `LLMTRACE_STORAGE_PROFILE=memory`; `pro.yaml` uses `LLMTRACE_STORAGE_PROFILE=sqlite`.

**`storage.auto_migrate`** — When `true` (default), the proxy runs pending database migrations automatically on startup. Set to `false` in production and run `llmtrace-proxy migrate --config config.yaml` as a pre-startup Job or init-container.

---

### `logging`

| Field | YAML path | Env override | Type | Default | Allowed values |
|---|---|---|---|---|---|
| Level | `logging.level` | `LLMTRACE_LOG_LEVEL`, `RUST_LOG` | `string` | `"info"` | `trace`, `debug`, `info`, `warn`, `error` |
| Format | `logging.format` | `LLMTRACE_LOG_FORMAT` | `string` | `"text"` | `text`, `json` |

**`logging.level`** — Minimum log level. `RUST_LOG` takes highest precedence and supports per-module directives (e.g. `llmtrace_proxy=debug,info`). The `--log-level` CLI flag wins over `LLMTRACE_LOG_LEVEL` and the YAML value.

**`logging.format`** — `"text"` produces human-readable output; `"json"` produces structured JSON suitable for log aggregators (ELK, Datadog, etc.). The Basilica `starter.yaml` and `pro.yaml` examples both set `LLMTRACE_LOG_FORMAT=json`.

---

### `rate_limiting`

| Field | YAML path | Env override | Type | Default |
|---|---|---|---|---|
| Enabled | `rate_limiting.enabled` | — | `bool` | `true` |
| Requests per second | `rate_limiting.requests_per_second` | `LLMTRACE_RATE_LIMIT_RPS` | `u32` | `100` |
| Burst size | `rate_limiting.burst_size` | `LLMTRACE_RATE_LIMIT_BURST` | `u32` | `200` |
| Window seconds | `rate_limiting.window_seconds` | — | `u32` | `60` |
| Per-tenant overrides | `rate_limiting.tenant_overrides` | — | `map<uuid, {rps, burst}>` | `{}` |

Rate limiting is per-tenant using a token-bucket algorithm backed by the cache layer (Redis in production, in-process `DashMap` in lite/memory). Requests exceeding the limit are rejected with `429 Too Many Requests`.

**`rate_limiting.requests_per_second`** — Steady-state refill rate. The env overrides `LLMTRACE_RATE_LIMIT_RPS` and `LLMTRACE_RATE_LIMIT_BURST` accept strictly positive `u32`; zero and non-numeric values are ignored (the YAML value or default is kept).

**`rate_limiting.tenant_overrides`** — Per-tenant overrides keyed by tenant UUID string. Each entry has `requests_per_second` and `burst_size` fields. Example:

```yaml
rate_limiting:
  tenant_overrides:
    "d4e5f6a7-b8c9-0d1e-f2a3-b4c5d6e7f8a9":
      requests_per_second: 500
      burst_size: 1000
```

**Hot-swap**: `rate_limiting.enabled` can be toggled at runtime via `PUT /api/v1/config/features` (`rate_limiting_enabled`).

---

### `circuit_breaker`

| Field | YAML path | Type | Default |
|---|---|---|---|
| Enabled | `circuit_breaker.enabled` | `bool` | `true` |
| Failure threshold | `circuit_breaker.failure_threshold` | `u32` | `10` |
| Recovery timeout | `circuit_breaker.recovery_timeout_ms` | `u64 ms` | `30000` |
| Half-open max calls | `circuit_breaker.half_open_max_calls` | `u32` | `3` |

The circuit breaker monitors storage and security-analysis failures. When consecutive failures exceed `failure_threshold`, the breaker opens and the proxy degrades to pass-through (no analysis, no trace storage). After `recovery_timeout_ms` it transitions to half-open and allows `half_open_max_calls` probe requests. Success resets the breaker to closed.

Circuit-breaker state is exposed via the `llmtrace_circuit_breaker_state` Prometheus gauge and the `/health` endpoint.

---

### `health_check`

| Field | YAML path | Type | Default |
|---|---|---|---|
| Enabled | `health_check.enabled` | `bool` | `true` |
| Path | `health_check.path` | `string` | `"/health"` |
| Interval | `health_check.interval_seconds` | `u32` | `10` |
| Timeout | `health_check.timeout_ms` | `u64 ms` | `5000` |
| Retries | `health_check.retries` | `u32` | `3` |

The `/health` endpoint returns storage connectivity, circuit-breaker state, ML model status, and proxy uptime. Use it for Kubernetes liveness and readiness probes.

---

### `alerts`

| Field | YAML path | Type | Default |
|---|---|---|---|
| Enabled | `alerts.enabled` | `bool` | `false` |
| Webhook URL (legacy) | `alerts.webhook_url` | `string` | `""` |
| Min severity (legacy) | `alerts.min_severity` | `string` | `"High"` |
| Min security score (legacy) | `alerts.min_security_score` | `u8` | `70` |
| Cooldown | `alerts.cooldown_seconds` | `u64` | `300` |
| Channels | `alerts.channels[]` | `list` | `[]` |
| Escalation | `alerts.escalation` | `object?` | `null` |

When `alerts.channels` is non-empty it takes precedence over the legacy top-level fields. Each channel entry has:

| Sub-field | Type | Default | Description |
|---|---|---|---|
| `type` | `string` | required | `"webhook"`, `"slack"`, `"pagerduty"`, or `"email"` |
| `url` / `webhook_url` | `string?` | `null` | Destination URL |
| `routing_key` | `string?` | `null` | PagerDuty routing key |
| `min_severity` | `string` | `"High"` | Minimum severity for this channel |
| `min_security_score` | `u8` | `70` | Minimum score (0–100) for this channel |

**`alerts.cooldown_seconds`** — After an alert fires for a given finding type, the engine suppresses duplicate alerts for this many seconds.

**`alerts.escalation.escalate_after_seconds`** — If no acknowledgement is received, the alert is re-sent at the next higher severity channel after this interval. Default: `600`.

---

### `cost_estimation`

| Field | YAML path | Type | Default |
|---|---|---|---|
| Enabled | `cost_estimation.enabled` | `bool` | `true` |
| Pricing file | `cost_estimation.pricing_file` | `string?` | `null` |
| Custom models | `cost_estimation.custom_models` | `map<name, pricing>` | `{}` |

**`cost_estimation.pricing_file`** — Path to an external YAML/JSON pricing file. Loaded at startup and reloaded on `SIGHUP`. Built-in defaults are used when the file is absent.

Each `custom_models` entry has `input_per_million` (USD per 1M prompt tokens) and `output_per_million` (USD per 1M completion tokens).

---

### `cost_caps`

| Field | YAML path | Type | Default |
|---|---|---|---|
| Enabled | `cost_caps.enabled` | `bool` | `false` |
| Default budget caps | `cost_caps.default_budget_caps[]` | `list<BudgetCap>` | `[]` |
| Default token cap | `cost_caps.default_token_cap` | `object?` | `null` |
| Per-agent overrides | `cost_caps.agents[]` | `list<AgentCostCap>` | `[]` |

**`BudgetCap`** fields:

| Field | Type | Description |
|---|---|---|
| `window` | `string` | `"hourly"`, `"daily"`, `"weekly"`, or `"monthly"` |
| `hard_limit_usd` | `f64` | Requests are rejected (`429`) when this is exceeded |
| `soft_limit_usd` | `f64?` | Triggers an alert but allows the request |

**`TokenCap`** fields:

| Field | Type | Description |
|---|---|---|
| `max_prompt_tokens` | `u32?` | Per-request prompt token cap |
| `max_completion_tokens` | `u32?` | Per-request completion token cap |
| `max_total_tokens` | `u32?` | Per-request total token cap |

Agents are identified by the `X-LLMTrace-Agent-ID` request header. Per-agent overrides win over `default_budget_caps` and `default_token_cap`.

**Hot-swap**: `cost_caps.enabled` can be toggled via `PUT /api/v1/config/features` (`cost_caps_enabled`).

---

### `security_analysis`

Controls the ML and regex ensemble analyzer. See also [Analysers Breakdown](../security/ANALYSERS_TECHNICAL_BREAKDOWN.md) and [Ensemble Detection](../ml/ensemble.md).

| Field | YAML path | Env override | Type | Default |
|---|---|---|---|---|
| ML enabled | `security_analysis.ml_enabled` | `LLMTRACE_ML_ENABLED` | `bool` | `true` |
| ML model | `security_analysis.ml_model` | — | `string` | `"protectai/deberta-v3-base-prompt-injection-v2"` |
| ML threshold | `security_analysis.ml_threshold` | — | `f64` | `0.8` |
| ML cache dir | `security_analysis.ml_cache_dir` | `LLMTRACE_ML_CACHE_DIR` | `string` | `"~/.cache/llmtrace/models"` |
| ML preload | `security_analysis.ml_preload` | `LLMTRACE_ML_PRELOAD` | `bool` | `true` |
| ML download timeout | `security_analysis.ml_download_timeout_seconds` | — | `u64` | `300` |
| NER enabled | `security_analysis.ner_enabled` | — | `bool` | `false` |
| NER model | `security_analysis.ner_model` | — | `string` | `"dslim/bert-base-NER"` |
| Fusion enabled | `security_analysis.fusion_enabled` | — | `bool` | `false` |
| Fusion model path | `security_analysis.fusion_model_path` | — | `string?` | `null` |
| Jailbreak enabled | `security_analysis.jailbreak_enabled` | — | `bool` | `true` |
| Jailbreak threshold | `security_analysis.jailbreak_threshold` | — | `f32` | `0.7` |
| InjecGuard enabled | `security_analysis.injecguard_enabled` | — | `bool` | `false` |
| InjecGuard model | `security_analysis.injecguard_model` | — | `string` | `"leolee99/InjecGuard"` |
| InjecGuard threshold | `security_analysis.injecguard_threshold` | — | `f64` | `0.85` |
| PIGuard enabled | `security_analysis.piguard_enabled` | — | `bool` | `false` |
| PIGuard model | `security_analysis.piguard_model` | — | `string` | `"leolee99/PIGuard"` |
| PIGuard threshold | `security_analysis.piguard_threshold` | — | `f64` | `0.85` |
| Operating point | `security_analysis.operating_point` | — | `string` | `"balanced"` |
| Over-defence | `security_analysis.over_defence` | — | `bool` | `false` |
| Max analysis text | `security_analysis.max_analysis_text_bytes` | — | `usize` | `1048576` (1 MiB) |
| Zone detection | `security_analysis.zone_detection` | — | `object` | disabled |

**Memory requirements**: Each DeBERTa model requires ~400–600 MiB of RAM. With `ml_enabled`, `injecguard_enabled`, and `piguard_enabled` all `true`, expect ~1.2–1.8 GiB total for three model instances. The Basilica `pro.yaml` example runs on a `memory: 8Gi` pod shape.

**`ml_enabled`** — When `false`, the ensemble falls back to regex-only analysis. The env var `LLMTRACE_ML_ENABLED=0` (or `false` / `no`) disables ML at runtime without reloading the YAML file. Hot-swappable via `PUT /api/v1/config/features` (`analyzer_ml_enabled`).

**`ml_preload`** — When `true` (default), ML models are loaded before `/health` returns ready. This eliminates cold-start latency on the first request but extends the proxy startup time (600–1500 s on 2-core pods). The Basilica configs set `startup_timeout_seconds: 1500` explicitly for this reason. When `false`, models load on the first request.

**`ml_download_timeout_seconds`** — Maximum time in seconds allowed for downloading model weights from HuggingFace Hub at startup. If exceeded, the proxy falls back to regex-only and logs a warning. Default `300` s.

**`jailbreak_enabled`** — Enables the dedicated jailbreak detector (DAN patterns, character-play injections, privilege-escalation heuristics, encoding-evasion checks — base64, ROT13, leetspeak, reversed text). Runs alongside the ML injection classifier in the ensemble. Hot-swappable via `analyzer_jailbreak_enabled`.

**`operating_point`** — Adjusts ensemble voting thresholds for the precision-recall trade-off. Accepted values: `"balanced"` (default, recommended), `"high_recall"` (catch everything, more false positives), `"high_precision"` (production-safe, fewer false positives). Hot-swappable via `PUT /api/v1/config/features` (`operating_point`).

**`over_defence`** — Enables the InjecGuard over-defence suppressor that reduces false positives caused by benign trigger words. Hot-swappable via `over_defence`.

**`max_analysis_text_bytes`** — Inputs larger than this are truncated before normalization and ML inference. Must be `> 0`.

**`zone_detection`** — See the [Zone detection](#security_analysiszone_detection) sub-section below.

#### `security_analysis.zone_detection`

| Field | YAML path | Type | Default |
|---|---|---|---|
| Enabled | `security_analysis.zone_detection.enabled` | `bool` | `false` |
| Mode | `security_analysis.zone_detection.mode` | `string` | `"both"` |
| Scan instruction zones | `security_analysis.zone_detection.scan_instruction_zones` | `bool` | `false` |

Zone-aware injection scanning (IS-060 PR-1). When enabled, the proxy splits each chat message into instruction and data zones (heuristically and/or via operator-supplied `<llmtrace-data>` markers) and runs the ensemble per data zone. Disabled by default so existing deployments are byte-identical until opt-in. See [Spotlighting Indirect Injection](../architecture/SPOTLIGHTING_INDIRECT_INJECTION.md).

**`zone_detection.mode`** accepted values:

- `"heuristic"` — format-detection FSM only (HTML tables, code fences, etc.); operator markers are ignored.
- `"operator"` — honour inline `<llmtrace-data>` markers and `X-LLMTrace-Data-Boundary` request header only; heuristics are off.
- `"both"` (default) — heuristics first, operator markers override on overlap.

---

### `enforcement`

Controls synchronous pre-request enforcement. Full guide: [Pre-Request Enforcement](enforcement.md).

| Field | YAML path | Type | Default |
|---|---|---|---|
| Mode | `enforcement.mode` | `string` | `"log"` |
| Analysis depth | `enforcement.analysis_depth` | `string` | `"full"` |
| Min severity | `enforcement.min_severity` | `string` | `"High"` |
| Min confidence | `enforcement.min_confidence` | `f64` | `0.8` |
| Timeout | `enforcement.timeout_ms` | `u64 ms` | `5000` |
| Per-category overrides | `enforcement.categories[]` | `list` | `[]` |

**`enforcement.mode`** — Accepted values:
- `"log"` (default) — no enforcement; requests are always forwarded. Analysis results are still attached to the envelope and advisory injection still fires if `llm_advisory_injection_enabled: true`.
- `"block"` — requests that trigger enforcement criteria receive `403 Forbidden` and are not forwarded upstream.
- `"flag"` — requests are forwarded but finding metadata is attached as `X-LLMTrace-Flagged`, `X-LLMTrace-Finding-Type`, and `X-LLMTrace-Severity` response headers.

Hot-swappable via `PUT /api/v1/config/features` (`enforcement_mode`).

**`enforcement.analysis_depth`** — Defaulted to `"full"` (changed from `"fast"` in [#300](https://github.com/techlab-innov/llmtrace/issues/300)) so the response envelope `findings[]`, `security_score`, and the advisory injection see the same ensemble the async post-response pipeline writes to the trace. Set to `"fast"` explicitly for latency-critical deployments that accept regex-only coverage.

- `"fast"` — regex-only; near-zero added latency (microseconds).
- `"full"` — full ensemble (regex + ML); adds ~50–500 ms ML inference latency (bounded by `enforcement.timeout_ms`).

**`enforcement.min_severity`** — Minimum finding severity to trigger enforcement. Accepted values: `"Info"`, `"Low"`, `"Medium"`, `"High"` (default), `"Critical"`.

**`enforcement.min_confidence`** — Minimum confidence score (0.0–1.0) to trigger enforcement. A finding must meet *both* `min_severity` and `min_confidence` to activate enforcement. Must be in `[0.0, 1.0]`.

**`enforcement.timeout_ms`** — Enforcement analysis is fail-open: if analysis exceeds this timeout the request is forwarded without enforcement. Must be `> 0`. Default `5000` ms matches the async background analysis timeout so the sync `full` ensemble has the same budget the async path does (see [#300](https://github.com/techlab-innov/llmtrace/issues/300)).

**`enforcement.categories[]`** — Per-finding-type action overrides. Each entry:

```yaml
enforcement:
  categories:
    - finding_type: "prompt_injection"
      action: "block"
    - finding_type: "pii_detected"
      action: "flag"
```

The `categories` list takes precedence over the top-level `mode`. Finding types not listed fall back to `mode`.

---

### `output_safety`

| Field | YAML path | Type | Default |
|---|---|---|---|
| Enabled | `output_safety.enabled` | `bool` | `false` |
| Toxicity enabled | `output_safety.toxicity_enabled` | `bool` | `false` |
| Toxicity threshold | `output_safety.toxicity_threshold` | `f32` | `0.7` |
| Block on critical | `output_safety.block_on_critical` | `bool` | `false` |
| Hallucination enabled | `output_safety.hallucination_enabled` | `bool` | `false` |
| Hallucination model | `output_safety.hallucination_model` | `string` | `"vectara/hallucination_evaluation_model"` |
| Hallucination threshold | `output_safety.hallucination_threshold` | `f32` | `0.5` |
| Hallucination min length | `output_safety.hallucination_min_response_length` | `usize` | `50` |

Output safety runs after the upstream response is received (post-processing). It analyses response content for toxicity, PII leakage, secret exposure, and hallucination.

**`output_safety.block_on_critical`** — When `true`, critical toxicity detections (`severe_toxic`, `threat`, score >= 0.9) replace the response body with an error. Use with caution in production.

**`output_safety.hallucination_threshold`** — Response sentences scoring below this threshold on the cross-encoder consistency model are flagged as potentially hallucinated. Lower values are more permissive.

**`output_safety.hallucination_min_response_length`** — Responses shorter than this (characters) skip hallucination detection to avoid false positives on short answers.

---

### `streaming_analysis`

| Field | YAML path | Type | Default |
|---|---|---|---|
| Enabled | `streaming_analysis.enabled` | `bool` | `false` |
| Token interval | `streaming_analysis.token_interval` | `u32` | `50` |
| Output enabled | `streaming_analysis.output_enabled` | `bool` | `false` |
| Early stop on critical | `streaming_analysis.early_stop_on_critical` | `bool` | `false` |

Incremental regex-based security checks during SSE streaming. The proxy runs pattern matching every `token_interval` completion tokens while the stream is in progress. Full analysis still runs after stream completion.

**`streaming_analysis.early_stop_on_critical`** — If a critical finding is detected mid-stream, the proxy injects a warning into the SSE stream and terminates. This cuts off the LLM response mid-generation.

---

### `pii`

| Field | YAML path | Type | Default |
|---|---|---|---|
| Action | `pii.action` | `string` | `"alert_only"` |

**`pii.action`** — How the security analyzer handles detected PII patterns:

- `"alert_only"` (default) — generate security findings but do not modify text.
- `"alert_and_redact"` — generate findings *and* replace PII with `[PII:TYPE]` tags in the forwarded request.
- `"redact_silent"` — replace PII without generating findings.

---

### `anomaly_detection`

| Field | YAML path | Type | Default |
|---|---|---|---|
| Enabled | `anomaly_detection.enabled` | `bool` | `false` |
| Window size | `anomaly_detection.window_size` | `usize` | `100` |
| Sigma threshold | `anomaly_detection.sigma_threshold` | `f64` | `3.0` |
| Check cost | `anomaly_detection.check_cost` | `bool` | `true` |
| Check tokens | `anomaly_detection.check_tokens` | `bool` | `true` |
| Check velocity | `anomaly_detection.check_velocity` | `bool` | `true` |
| Check latency | `anomaly_detection.check_latency` | `bool` | `true` |

When enabled, the proxy tracks per-tenant moving averages across the sliding window and flags statistical anomalies (cost spikes, token spikes, request-velocity spikes, latency spikes) using the sigma threshold. Detected anomalies appear as `llmtrace_anomalies_total` Prometheus counter increments.

**`anomaly_detection.sigma_threshold`** — Observations more than `sigma_threshold` standard deviations above the moving mean trigger an anomaly finding. Higher values reduce false-positive noise.

---

### `boundary_defense`

| Field | YAML path | Type | Default |
|---|---|---|---|
| Enabled | `boundary_defense.enabled` | `bool` | `false` |
| Shadow mode | `boundary_defense.shadow_mode` | `bool` | `false` |
| Wrap roles | `boundary_defense.wrap_roles` | `list<string>` | `["tool"]` |
| Delimiter | `boundary_defense.delimiter` | `string` | `"llmtrace-boundary"` |
| Randomize nonce | `boundary_defense.randomize_nonce` | `bool` | `false` |
| Inject system reminder | `boundary_defense.inject_system_reminder` | `bool` | `true` |
| System reminder text | `boundary_defense.system_reminder_text` | `string` | `""` (use built-in) |
| Datamarking | `boundary_defense.datamarking` | `object` | disabled |

Boundary token injection defence wraps untrusted message content (tool outputs) with structural delimiter tags before forwarding to the upstream LLM provider. Reduces indirect prompt injection ASR by ~10x on the BIPIA benchmark (KDD 2025). See [Boundary Token Defence](../architecture/BOUNDARY_TOKEN_DEFENCE.md).

**`boundary_defense.shadow_mode`** — Compute the modified body and log all metrics, but forward the original bytes to upstream. Use for production validation before enabling live rewriting. Rollout recommendation: enable with shadow first, validate for 24+ hours, then disable shadow.

**`boundary_defense.wrap_roles`** — Message roles whose content is wrapped. `"tool"` covers tool-call results in OpenAI-compatible APIs. Validation requires this list to be non-empty when `enabled: true`.

**`boundary_defense.randomize_nonce`** — Append a random hex nonce to the delimiter tag per request so attackers who leak the system prompt cannot pre-craft payloads that close the boundary.

**`boundary_defense.inject_system_reminder`** — When `true` (default), prepend an instruction to the system prompt telling the model to treat delimited content as untrusted data.

Hot-swappable: `boundary_defense.enabled` and `boundary_defense.shadow_mode` via `PUT /api/v1/config/features` (`boundary_defense_enabled`, `boundary_defense_shadow_mode`).

#### `boundary_defense.datamarking`

IS-060 PR-2. Replaces Unicode whitespace inside detected Data zones with a marker codepoint from the Unicode Private Use Area, telling the upstream model via a system-reminder addendum that the marked text is data, not instructions.

| Field | YAML path | Type | Default |
|---|---|---|---|
| Enabled | `boundary_defense.datamarking.enabled` | `bool` | `false` |
| Shadow mode | `boundary_defense.datamarking.shadow_mode` | `bool` | `true` |
| Marker strategy | `boundary_defense.datamarking.marker_strategy.kind` | `string` | `"randomized"` |

**`datamarking.shadow_mode`** defaults to `true` — the transform is computed and emitted in metrics, but original bytes are forwarded upstream. Flip to `false` only after one nightly cycle confirms zero upstream 4xx delta.

**`marker_strategy.kind`** accepted values:
- `"randomized"` (default) — sample a fresh codepoint from `U+E000..=U+F8FF` per request. Recommended for production; prevents pre-crafted evasion.
- `"fixed"` — use a pinned codepoint (`value: ""`). Useful for reproducible nightly diffs and unit tests.

---

### `otel_ingest`

| Field | YAML path | Type | Default |
|---|---|---|---|
| Enabled | `otel_ingest.enabled` | `bool` | `false` |

When `true`, the proxy exposes `POST /v1/traces` to accept traces in the standard OTLP/HTTP format (JSON and protobuf). Uses the same HTTP listener as the rest of the proxy.

---

### `auth`

| Field | YAML path | Env override | Type | Default |
|---|---|---|---|---|
| Enabled | `auth.enabled` | `LLMTRACE_AUTH_ENABLED` | `bool` | `false` |
| Admin key | `auth.admin_key` | `LLMTRACE_AUTH_ADMIN_KEY` | `string?` | `null` |

When `auth.enabled: true`, every request (except `GET /health`) must carry a valid API key in `Authorization: Bearer <key>`. The admin key is a bootstrap key for initial tenant and key management; it is compared directly from config (not hashed).

**`LLMTRACE_AUTH_ENABLED`** — Accepted truthy values: `"1"`, `"true"`, `"yes"` (case-insensitive). All other values are treated as `false`.

See the full RBAC model and key-lifecycle guide in [Auth & Multi-Tenancy](auth-tenancy.md).

---

### `grpc`

| Field | YAML path | Type | Default |
|---|---|---|---|
| Enabled | `grpc.enabled` | `bool` | `false` |
| Listen address | `grpc.listen_addr` | `string` | `"0.0.0.0:50051"` |

When enabled, the proxy starts a Tonic gRPC server on a separate address that accepts traces in the LLMTrace-native protobuf format. The gRPC server shares the same graceful-shutdown cancellation token as the HTTP server.

---

### `judge`

Full guide: [LLM Judge Setup](llm-judge.md). Architecture: [LLM Judge](../architecture/LLM_JUDGE.md).

| Field | YAML path | Type | Default |
|---|---|---|---|
| Enabled | `judge.enabled` | `bool` | `false` |
| Backend | `judge.backend` | `string` | `"vllm"` |
| Min score threshold | `judge.min_score_threshold` | `u8` | `30` |
| Persist verdicts | `judge.persist_verdicts` | `bool` | `true` |
| System prompt | `judge.system_prompt` | `string?` | `null` (built-in) |

**`judge.backend`** — Accepted values: `"vllm"`, `"openai"`, `"anthropic"`, `"deberta"`, `"cascade"`. API keys are read from `LLMTRACE_JUDGE_OPENAI_API_KEY` and `LLMTRACE_JUDGE_ANTHROPIC_API_KEY` environment variables at startup.

**`judge.min_score_threshold`** — The judge is only invoked for requests whose prior ensemble security score is at or above this value. Default `30` bounds cost by skipping clean traffic.

**`judge.persist_verdicts`** — When `false`, verdicts are used for ensemble voting but not written to the `judge_verdicts` table. Shadow mode for ensemble contribution without storage cost.

**Hot-swap**: `judge.enabled` via `PUT /api/v1/config/features` (`llm_judge_enabled`).

#### `judge.vllm`

| Field | YAML path | Type | Default |
|---|---|---|---|
| Base URL | `judge.vllm.base_url` | `string` | `"http://localhost:8000"` |
| Model | `judge.vllm.model` | `string` | `"security-judge-v1"` |
| Max tokens | `judge.vllm.max_tokens` | `u32` | `512` |
| Temperature | `judge.vllm.temperature` | `f32` | `0.1` |
| Allow plaintext | `judge.vllm.allow_plaintext` | `bool` | `false` |

**`judge.vllm.allow_plaintext`** — When `false` (default), non-loopback `http://` URLs are rejected at startup with a clear error ([#77](https://github.com/techlab-innov/llmtrace/issues/77)). Loopback URLs (`127.0.0.1`, `::1`, `localhost`) are always allowed. Set `true` only for on-premise deployments on private networks.

#### `judge.openai`

| Field | YAML path | Type | Default |
|---|---|---|---|
| Base URL | `judge.openai.base_url` | `string` | `"https://api.openai.com"` |
| Model | `judge.openai.model` | `string` | `"gpt-4o-mini"` |
| Max tokens | `judge.openai.max_tokens` | `u32` | `512` |
| Temperature | `judge.openai.temperature` | `f32` | `0.1` |

**`judge.openai.base_url`** — Supports any OpenAI-compatible gateway (OpenRouter, Azure OpenAI, LiteLLM) without a separate backend kind.

#### `judge.anthropic`

| Field | YAML path | Type | Default |
|---|---|---|---|
| Model | `judge.anthropic.model` | `string` | `"claude-3-5-haiku-20241022"` |
| Max tokens | `judge.anthropic.max_tokens` | `u32` | `512` |
| Temperature | `judge.anthropic.temperature` | `f32` | `0.1` |

#### `judge.deberta`

| Field | YAML path | Type | Default |
|---|---|---|---|
| Model ID | `judge.deberta.model_id` | `string` | `"protectai/deberta-v3-base-prompt-injection-v2"` |
| Threshold | `judge.deberta.threshold` | `f64` | `0.5` |
| Cache dir | `judge.deberta.cache_dir` | `string?` | `null` (HuggingFace default) |

Local DeBERTa classifier judge backend ([#87](https://github.com/techlab-innov/llmtrace/issues/87)). Runs through the existing candle-based ML machinery.

#### `judge.cascade`

| Field | YAML path | Type | Default |
|---|---|---|---|
| Fast backend | `judge.cascade.fast_backend` | `string` | `"deberta"` |
| Slow backend | `judge.cascade.slow_backend` | `string?` | `null` |
| Ambiguous low | `judge.cascade.ambiguous_low` | `f64` | `0.3` |
| Ambiguous high | `judge.cascade.ambiguous_high` | `f64` | `0.7` |

The cascade composes a fast backend (default `deberta`) with an optional slow backend. The fast backend runs first; if its `confidence` falls in the ambiguous band `(ambiguous_low, ambiguous_high)` and a slow backend is configured, the slow backend runs and its verdict wins. Set `slow_backend: null` to ship the fast tier alone ([#88](https://github.com/techlab-innov/llmtrace/issues/88)).

#### `judge.worker`

| Field | YAML path | Type | Default |
|---|---|---|---|
| Channel buffer | `judge.worker.channel_buffer` | `usize` | `1000` |
| Max concurrency | `judge.worker.max_concurrency` | `usize` | `4` |
| Timeout | `judge.worker.timeout_ms` | `u64 ms` | `30000` |
| Max analysis text bytes | `judge.worker.max_analysis_text_bytes` | `u32` | `65536` (64 KiB) |
| Total deadline | `judge.worker.total_deadline_ms` | `u64 ms` | `45000` |

**`judge.worker.max_analysis_text_bytes`** — Analysis text on a judge request envelope is truncated to this length at construction time. Bounds worst-case in-flight memory: `channel_buffer × max_analysis_text_bytes` ([#78](https://github.com/techlab-innov/llmtrace/issues/78)).

**`judge.worker.total_deadline_ms`** — Hard ceiling on end-to-end latency of one `judge()` call including all retries. `0` disables the ceiling ([#73](https://github.com/techlab-innov/llmtrace/issues/73)).

#### `judge.retry`

| Field | YAML path | Type | Default |
|---|---|---|---|
| Max retries | `judge.retry.max_retries` | `u32` | `2` |
| Backoff base | `judge.retry.backoff_base_ms` | `u64 ms` | `1000` |

#### `judge.promotion`

Gates whether a judge verdict is allowed to override the prior enforcement decision. Defaults are conservative — require high confidence, a meaningful security score, and at least one supporting prior ensemble finding.

| Field | YAML path | Type | Default |
|---|---|---|---|
| Min confidence | `judge.promotion.min_confidence` | `f64` | `0.7` |
| Min security score | `judge.promotion.min_security_score` | `u8` | `60` |
| Require ensemble support | `judge.promotion.require_ensemble_support` | `bool` | `true` |
| Shadow | `judge.promotion.shadow` | `bool` | `false` |

**`judge.promotion.min_confidence`** — Pre-calibration placeholder (not an empirically-derived probability). Recalibrate via Platt scaling or isotonic regression against a golden set whenever the judge model, provider family, or system prompt changes. See [#66](https://github.com/techlab-innov/llmtrace/issues/66).

**`judge.promotion.require_ensemble_support`** — When `true` (default), a judge Block promotion requires at least one prior ensemble finding of severity `Medium` or higher. Prevents the judge from single-handedly blocking clean-ensemble traffic.

**`judge.promotion.shadow`** — When `true`, the judge runs end-to-end (persists verdicts, emits metrics) but `verdict_to_outcome` never promotes a verdict to `BlockRequested`. Every would-be promotion increments `llmtrace_judge_shadow_would_block_total`. Recommended during initial rollout and after any model, provider, or prompt change.

---

### `action_router`

| Field | YAML path | Type | Default |
|---|---|---|---|
| Enabled | `action_router.enabled` | `bool` | `false` |
| Default actions | `action_router.default_actions` | `list<string>` | `["log"]` |
| Rules | `action_router.rules[]` | `list<ActionRuleConfig>` | `[]` |

#### `action_router.ip_block`

| Field | YAML path | Type | Default |
|---|---|---|---|
| TTL seconds | `action_router.ip_block.ttl_seconds` | `u64` | `3600` |
| Max offenses | `action_router.ip_block.max_offenses` | `u32` | `3` |

Must be `> 0` when `action_router.enabled: true`.

#### `action_router.webhook`

| Field | YAML path | Type | Default |
|---|---|---|---|
| URL | `action_router.webhook.url` | `string` | `""` |
| Timeout | `action_router.webhook.timeout_ms` | `u64 ms` | `5000` |

`url` must be non-empty when a `"webhook"` action is referenced by `default_actions` or any rule. Must be `> 0`.

#### `action_router.judge_route`

| Field | YAML path | Type | Default |
|---|---|---|---|
| Inline await | `action_router.judge_route.inline_await` | `bool` | `false` |
| Inline timeout | `action_router.judge_route.inline_timeout_ms` | `u64 ms` | `10000` |

**`action_router.rules[]`** — Each rule has `finding_type` (optional, string), `min_severity`, `min_confidence`, and `actions` (list of action names). Rules take precedence over `default_actions`.

---

### `ml_pipeline`

| Field | YAML path | Env override | Type | Default |
|---|---|---|---|---|
| Max concurrent requests | `ml_pipeline.max_concurrent_requests` | `LLMTRACE_ML_MAX_CONCURRENT` | `usize` | `8` |

Concurrency cap for the CPU-bound ML detection pipeline. On every inbound request the proxy may run several CPU-bound ML detectors. Without a bound, a flood of requests can saturate the pod's CPU. When the cap is exceeded the proxy returns `503 Service Unavailable` with `Retry-After: 1`. Must be `>= 1`.

The default `8` is a safe lower bound for typical 4-core pods. SaaS operators tune this via `LLMTRACE_ML_MAX_CONCURRENT`.

---

### `shutdown`

| Field | YAML path | Type | Default |
|---|---|---|---|
| Timeout seconds | `shutdown.timeout_seconds` | `u64` | `30` |

Maximum seconds to wait for in-flight background tasks (trace capture, security analysis) to complete after a `SIGTERM`/`SIGINT` signal. After this timeout the process force-exits. In Kubernetes, set `terminationGracePeriodSeconds > shutdown.timeout_seconds` (e.g. 60 s grace period with 30 s shutdown timeout gives 30 s headroom).

---

### `server`

| Field | YAML path | Type | Default |
|---|---|---|---|
| Debug endpoints | `server.debug_endpoints` | `bool` | `false` |

When `true`, registers `/debug/judge/verdicts` and `/debug/judge/golden_set/replay`. These endpoints return un-auth-gated verdict payloads by trace ID and are intended for the e2e adversarial test framework ([#91](https://github.com/techlab-innov/llmtrace/issues/91), [#95](https://github.com/techlab-innov/llmtrace/issues/95)). Never enable in production.

---

## Environment variable precedence and naming

Environment variables always override the YAML value for the same field. Variables follow the `LLMTRACE_` prefix convention. The complete list of wired variables (from `crates/llmtrace-proxy/src/config.rs`):

| Variable | Overrides |
|---|---|
| `LLMTRACE_CONFIG` | `--config` path (CLI flag) |
| `LLMTRACE_RUNTIME_CONFIG` | `--runtime-config` path (CLI flag) |
| `LLMTRACE_LISTEN_ADDR` | `listen_addr` |
| `LLMTRACE_UPSTREAM_URL` | `upstream_url` |
| `LLMTRACE_STORAGE_PROFILE` | `storage.profile` |
| `LLMTRACE_STORAGE_DATABASE_PATH` | `storage.database_path` |
| `LLMTRACE_CLICKHOUSE_URL` | `storage.clickhouse_url` |
| `LLMTRACE_CLICKHOUSE_DATABASE` | `storage.clickhouse_database` |
| `LLMTRACE_POSTGRES_URL` | `storage.postgres_url` |
| `LLMTRACE_REDIS_URL` | `storage.redis_url` |
| `LLMTRACE_AUTH_ENABLED` | `auth.enabled` |
| `LLMTRACE_AUTH_ADMIN_KEY` | `auth.admin_key` |
| `LLMTRACE_RATE_LIMIT_RPS` | `rate_limiting.requests_per_second` |
| `LLMTRACE_RATE_LIMIT_BURST` | `rate_limiting.burst_size` |
| `LLMTRACE_ML_ENABLED` | `security_analysis.ml_enabled` (startup wiring) |
| `LLMTRACE_ML_PRELOAD` | `security_analysis.ml_preload` (startup wiring) |
| `LLMTRACE_ML_CACHE_DIR` | `security_analysis.ml_cache_dir` (startup wiring) |
| `LLMTRACE_ML_MAX_CONCURRENT` | `ml_pipeline.max_concurrent_requests` |
| `LLMTRACE_LOG_LEVEL` | `logging.level` |
| `LLMTRACE_LOG_FORMAT` | `logging.format` |
| `LLMTRACE_MAX_REQUEST_BYTES` | HTTP body-limit middleware cap (not `max_request_size_bytes`) |
| `RUST_LOG` | Tracing filter directives (highest precedence for log filtering) |
| `LLMTRACE_JUDGE_OPENAI_API_KEY` | OpenAI API key for judge backend |
| `LLMTRACE_JUDGE_ANTHROPIC_API_KEY` | Anthropic API key for judge backend |

Note: `LLMTRACE_ML_ENABLED`, `LLMTRACE_ML_PRELOAD`, and `LLMTRACE_ML_CACHE_DIR` are read in `build_security_analyzer` at startup and applied to the in-memory analyzer wiring. They do not patch `ProxyConfig` struct fields via `apply_env_overrides`; the running config shown by `GET /api/v1/config/live` may not reflect them.

---

## Runtime hot-swap via feature-flags API

Some fields can be toggled at runtime without a restart via `PUT /api/v1/config/features`. Changes are applied atomically via `ConfigHandle.update()` (lock-free reads via `arc_swap`, serialized writes via an internal mutex). Changes are persisted to `config.runtime.yaml` if the path is writable; they survive restarts only when that file is on a writable volume.

Fields that are NOT hot-swappable require a full restart: `listen_addr`, `upstream_url`, all `storage.*` fields, `enable_tls` and TLS cert/key paths, `enable_security_analysis`, `enable_trace_storage`, `enable_streaming`, ML model identities (`ml_model`, `injecguard_model`, `piguard_model`, `ner_model`), `grpc.*`, `otel_ingest.*`, `auth.*`, `shutdown.*`, and `server.*`.

Hot-swappable flags exposed on `GET /api/v1/config/features`:

| Wire flag | Maps to |
|---|---|
| `analyzer_ml_enabled` | `security_analysis.ml_enabled` (EnsembleRuntimeHandle) |
| `analyzer_injecguard_enabled` | `security_analysis.injecguard_enabled` |
| `analyzer_piguard_enabled` | `security_analysis.piguard_enabled` |
| `analyzer_jailbreak_enabled` | `security_analysis.jailbreak_enabled` |
| `enforcement_mode` | `enforcement.mode` |
| `boundary_defense_enabled` | `boundary_defense.enabled` |
| `boundary_defense_shadow_mode` | `boundary_defense.shadow_mode` |
| `rate_limiting_enabled` | `rate_limiting.enabled` |
| `cost_caps_enabled` | `cost_caps.enabled` |
| `operating_point` | `security_analysis.operating_point` |
| `over_defence` | `security_analysis.over_defence` |
| `llm_judge_enabled` | `judge.enabled` |
| `llm_advisory_injection_enabled` | `llm_advisory_injection_enabled` |

`analyzer_regex_enabled` is intentionally absent — regex detection is always-on and cannot be toggled.

See the full runbook in [Feature Flags](../runbooks/feature-flags.md).
