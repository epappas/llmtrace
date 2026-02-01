# Architecture Decision Records (ADR)

This document captures key architecture decisions, their rationale, and status.

---

## ADR-001: Loop-Based Incremental Development (RALPH Pattern)

**Date**: 2026-01-31
**Status**: Adopted
**Context**: Need a structured approach to build the platform incrementally with spawned coding agents.
**Decision**: Use the RALPH loop pattern (Geoffrey Huntley) — single agent, single repo, single process, loop on a goal. Each loop is self-contained with clear acceptance criteria and quality gates (`cargo fmt`, `cargo clippy`, `cargo test`).
**Consequence**: 28 loops completed Phase 1-4 in ~24 hours. Each commit is atomic and tested.

---

## ADR-002: Rust Monorepo with Workspace Crates

**Date**: 2026-01-31
**Status**: Adopted
**Context**: Need clean separation of concerns while maintaining a single build.
**Decision**: Cargo workspace with 7 crates: `core` (types/traits), `proxy` (binary), `storage` (backends), `security` (analysis), `sdk` (embeddable), `python` (PyO3), `wasm` (wasm-bindgen). Node.js bindings in `bindings/node/` excluded from workspace to avoid wasm32 target conflicts.
**Consequence**: Feature-gated heavy deps (ClickHouse, Postgres, Redis, ML). Dev builds are fast (SQLite-only). Production compiles all backends.

---

## ADR-003: Repository Pattern for Storage (Three Concerns)

**Date**: 2026-01-31
**Status**: Adopted
**Context**: Different storage concerns need different backends at different scales.
**Decision**: Split into three repository traits:
- `TraceRepository` — high-volume analytical (SQLite dev / ClickHouse prod)
- `MetadataRepository` — ACID metadata (SQLite dev / PostgreSQL prod)
- `CacheLayer` — hot cache with TTL (in-memory dev / Redis prod)

Composite `Storage` struct holds all three. `StorageProfile` enum provides factory construction.
**Consequence**: Clean backend swapping. Dev runs with zero infrastructure. Production uses purpose-built stores.

---

## ADR-004: Transparent Proxy as Core Architecture

**Date**: 2026-01-31
**Status**: Adopted
**Context**: Need to observe LLM API calls without requiring SDK integration.
**Decision**: HTTP reverse proxy using axum + hyper. Intercepts requests, forwards to upstream, captures traces asynchronously. Circuit breakers ensure proxy degrades to pass-through on subsystem failures.
**Consequence**: Zero-integration observability. Supports any OpenAI-compatible provider. SSE streaming pass-through with TTFT tracking.

---

## ADR-005: Dual Circuit Breakers (Storage + Security)

**Date**: 2026-01-31
**Status**: Adopted
**Context**: Storage or security subsystem failures must not block LLM API calls.
**Decision**: Separate circuit breakers for storage and security. 3-state machine (Closed → Open → HalfOpen). When open, subsystem is bypassed — proxy continues as pure pass-through.
**Consequence**: LLM calls never fail due to observability infrastructure issues.

---

## ADR-006: Regex-First Security Analysis with ML Opt-In

**Date**: 2026-01-31
**Status**: Adopted
**Context**: Need prompt injection detection that's fast, predictable, and works everywhere.
**Decision**: `RegexSecurityAnalyzer` as default (13 injection patterns, PII, leakage detection). ML-based `DeBERTa v3` detector via Candle behind `ml` feature flag. `EnsembleSecurityAnalyzer` combines both when ML is enabled.
**Consequence**: <1ms regex analysis on every request. ML adds ~50-100ms but improves detection. Ensemble boosts confidence when both agree.

---

## ADR-007: gRPC Additive, Not Replacing HTTP

**Date**: 2026-02-01
**Status**: Adopted
**Context**: Loop 25 added gRPC ingestion. Must not break existing HTTP API.
**Decision**: gRPC server runs as a separate background tokio task on its own listen address. HTTP axum server unchanged. Both share the same `AppState` and storage pipeline. gRPC is opt-in via `grpc.enabled` config.
**Consequence**: Existing integrations unaffected. High-throughput clients can use gRPC. Both endpoints get security analysis and cost estimation.

---

## ADR-008: RBAC with API Key Authentication

**Date**: 2026-02-01
**Status**: Adopted
**Context**: Multi-tenant platform needs access control.
**Decision**: API key-based auth with three roles: `admin` (full access), `operator` (read + write), `viewer` (read only). Keys stored SHA-256 hashed in metadata repository. Auth middleware extracts tenant context from key. Bootstrap admin key via config.
**Consequence**: Simple, stateless auth. No external auth provider dependency. Tenant isolation enforced at query level.

---

## ADR-009: Review-Driven Phase 5 Architecture (AI + MLOps Feedback)

**Date**: 2026-02-01
**Status**: Adopted
**Context**: Three independent reviews (Rust Engineer 7.5/10, AI Engineer 6.5/10, MLOps Engineer 7.0/10) identified gaps. Need to prioritize fixes.
**Decision**: Address AI Engineer feedback first (detection/analysis gaps), then MLOps (operational hardening), then Rust Engineer (code quality). New loops 29-41:

**AI Engineer priorities (Loops 29-35):**
- Loop 29: Statistical Anomaly Detection Engine (critical gap — 0% implemented)
- Loop 30: Real-time Streaming Security Analysis (incremental during SSE)
- Loop 31: Expanded PII Detection (international formats, context-aware, redaction)
- Loop 32: ML-based PII Detection via NER model (Candle)
- Loop 33: ML Inference Monitoring + Model Warm-up
- Loop 34: Multi-Channel Alerting (Slack, PagerDuty, email)
- Loop 35: Externalize Pricing Config + OWASP LLM Top 10 test framework

**MLOps priorities (Loops 36-41):**
- Loop 36: Graceful Shutdown + Signal Handling (critical — data loss prevention)
- Loop 37: Prometheus `/metrics` Endpoint (critical — no runtime observability)
- Loop 38: DB Migration Management (critical — safe schema evolution)
- Loop 39: Secrets Hardening + Startup Probe
- Loop 40: Integration Tests in CI + Container Scanning
- Loop 41: Per-tenant Rate Limiting + Compliance Report Persistence

**Rationale**: AI gaps affect detection capability (the product's core value). MLOps gaps affect production readiness. Rust quality issues are important but non-blocking. Addressing in this order maximizes product value then operational safety.
**Consequence**: ~13 additional loops to reach production readiness. Estimated ~65-80% architecture coverage after completion.

---

## ADR-010: Anomaly Detection via Statistical Baselines (Not ML)

**Date**: 2026-02-01
**Status**: Adopted
**Context**: Architecture docs describe anomaly detection. AI engineer review flagged as #1 gap (0% implemented).
**Decision**: Use exponential moving average + standard deviation for anomaly detection. Per-tenant sliding windows for cost, tokens, velocity, and latency. Configurable sigma threshold (default 3σ). State stored in CacheLayer for persistence across restarts.
**Consequence**: Simple, interpretable, no training data needed. Establishes baselines automatically from traffic. Can be enhanced with ML later. Generates SecurityFinding objects that flow through existing alert pipeline.

---

## ADR-011: Helm Chart Infrastructure Defaults

**Date**: 2026-02-01
**Status**: Adopted
**Context**: Need K8s deployment for production.
**Decision**: Helm chart with Bitnami subcharts for ClickHouse, PostgreSQL, Redis. Hardened defaults: non-root user, read-only rootfs, dropped capabilities, PDB, NetworkPolicy. Production overlay with HPA (3-20 replicas), pod anti-affinity, Ingress with TLS/cert-manager.
**Consequence**: `helm install` deploys full stack. Dev and prod configurations separated. Security-first defaults.

---

## ADR-012: CI Requires protoc for gRPC

**Date**: 2026-02-01
**Status**: Adopted
**Context**: Loop 25 (gRPC) added a `build.rs` that compiles `.proto` files via `tonic-build`, which requires the `protoc` binary.
**Decision**: Install `protobuf-compiler` via apt in CI workflow (clippy, test, build jobs). Fmt job doesn't need it.
**Consequence**: CI green. Any future proto changes are automatically compiled in CI.

---

*Add new ADRs as architectural decisions are made. Each ADR should capture context, decision, and consequences.*
