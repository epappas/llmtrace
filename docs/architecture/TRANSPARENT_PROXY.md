# LLMTrace Transparent Proxy Architecture

**Version**: 2.0
**Date**: 2026-02-04
**Status**: Living
**Related Documents**: `docs/architecture/SYSTEM_ARCHITECTURE.md`

---

## Purpose

This document explains, at a technical level, how the LLMTrace transparent proxy works today in this repository. It focuses on the runtime behavior, request/response flow, streaming handling, security analysis, and failure modes as implemented in `llmtrace-proxy`.

---

## What “Transparent Proxy” Means Here

LLMTrace is an HTTP proxy that forwards OpenAI-compatible requests to an upstream LLM provider and returns responses verbatim while capturing data for observability and security analysis. The client changes only the base URL; request/response format remains unchanged.

Key properties implemented today:

- **Protocol compatibility**: OpenAI-style `/v1/chat/completions` and `/v1/completions` payloads are parsed for metadata and forwarded unchanged. All other paths are proxied as-is without LLM-specific parsing.
- **SSE passthrough**: Streaming responses are relayed to the client while being parsed incrementally.
- **Async analysis**: Trace capture and security analysis are performed in background tasks and do not block the response path.
- **Fail-open**: If analysis fails or circuit breakers open, the proxy still forwards upstream responses.

---

## Request Lifecycle (Non-Streaming)

1. **Receive request**
   - The proxy accepts the HTTP request and reads the full body.
   - It extracts metadata: tenant ID, agent ID, provider, and model info.

2. **Resolve tenant**
   - If `X-LLMTrace-Tenant-ID` is present and valid UUID, it is used.
   - When auth is disabled, a deterministic UUID v5 is derived from the API key if present.
   - When auth is enabled, tenant identity is derived from the API key record (or from the admin key + header).

3. **Forward upstream**
   - The request is forwarded to the configured `upstream_url`.
   - Response headers and status code are mirrored to the client.

4. **Capture + analyze in background**
   - The proxy spawns a background task that:
     - Aggregates the response body.
     - Runs security analysis (`SecurityAnalyzer::analyze_interaction`).
     - Runs output safety analysis when enabled.
     - Stores the trace + findings.
     - Emits alerts if thresholds are exceeded.

---

## Request Lifecycle (Streaming SSE)

1. **Receive request**
   - The proxy detects `stream: true` in the body.

2. **Stream passthrough**
   - The upstream response stream is read chunk-by-chunk.
   - Each chunk is forwarded to the client immediately.

3. **Incremental parsing**
   - SSE chunks are parsed to accumulate content and token counts.
   - Time-to-first-token (TTFT) is recorded on the first token.

4. **Incremental security checks**
   - `StreamingSecurityMonitor` runs regex-based checks on new content every N tokens.
   - `StreamingOutputMonitor` performs output-safety checks (PII/leakage, optional toxicity) on the delta.

5. **Early stop (optional)**
   - If `streaming_analysis.early_stop_on_critical` is enabled and a critical output issue is detected, the proxy injects a warning event and terminates the stream.

6. **Post-stream analysis**
   - After the stream finishes, the full captured prompt/response is analyzed in the background (same as non-streaming).

---

## Architecture Components

### 1. HTTP Proxy Handler

Implemented in `crates/llmtrace-proxy/src/proxy.rs`:

- Parses requests
- Determines tenant and agent IDs
- Detects provider and model
- Forwards to upstream with original headers
- Spawns background tasks for analysis and storage

### 2. Security Analysis Pipeline

Implemented by `llmtrace-security`:

- Default: regex analyzer for prompt injection, PII, leakage, jailbreak patterns
- Optional ML ensemble when `ml` feature and `ml_preload` are enabled
- Output safety analysis uses `OutputAnalyzer` with response-only checks

### 3. Storage

Implemented by `llmtrace-storage`:

- `memory`: in-memory only (tests/dev)
- `lite`: SQLite (traces + metadata), in-memory cache
- `production`: ClickHouse + PostgreSQL + Redis (feature gated)

### 4. Auth & RBAC

Implemented in `crates/llmtrace-proxy/src/auth.rs`:

- `auth.enabled = true`: API key required; roles enforced
- `auth.enabled = false`: permissive admin context; tenant resolved from header or API key

### 5. Alerts

Implemented in `crates/llmtrace-proxy/src/alerts.rs`:

- Supported: webhook, Slack, PagerDuty
- Email channel is recognized in config but not implemented
- Cooldown-based deduplication per finding type

---

## Error Handling and Fail-Open Behavior

- **Upstream errors**: return `502 Bad Gateway` with error response body.
- **Security analysis failures**: logged; request still succeeds.
- **Storage failures**: logged; proxy response still succeeds.
- **Circuit breakers**: if open, skip storage/analysis to protect latency.

---

## Configuration Surface (Relevant to Proxy Behavior)

Key proxy controls (see `ProxyConfig` in `llmtrace-core`):

- `upstream_url`: destination LLM API
- `enable_security_analysis`: enable/disable background analysis
- `enable_trace_storage`: enable/disable trace persistence
- `enable_streaming`: enable streaming passthrough
- `streaming_analysis.*`: token interval, early stop, output analysis
- `security_analysis.*`: ML model config, thresholds, preload behavior
- `auth.*`: API key enforcement
- `storage.*`: profile and backing services

---

## Current Limitations

- No inline policy enforcement or request blocking beyond optional output early-stop during streaming.
- No UI/dashboard served by the proxy runtime.
- No external IdP integration; auth is API-key based.
- ML models load only when `ml` feature is enabled and `ml_preload` is true; otherwise regex-only analysis is used.

---

## References in Code

- Proxy routing and main server: `crates/llmtrace-proxy/src/main.rs`
- Proxy handler and SSE parsing: `crates/llmtrace-proxy/src/proxy.rs`
- Streaming monitors: `crates/llmtrace-proxy/src/streaming.rs`
- Auth and RBAC: `crates/llmtrace-proxy/src/auth.rs`
- Storage profiles: `crates/llmtrace-storage/src/lib.rs`
- Security analyzers: `crates/llmtrace-security/src/lib.rs`
