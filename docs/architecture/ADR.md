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
**Decision**: Cargo workspace with 7 crates: `core` (types/traits), `proxy` (binary), `storage` (backends), `security` (analysis), `sdk` (embeddable), `python` (PyO3), `wasm` (wasm-bindgen). Node.js bindings in `crates/llmtrace-nodejs/` excluded from workspace to avoid wasm32 target conflicts.
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

## ADR-013: Feature-Level Fusion for Prompt Injection Detection

**Date**: 2026-02-01
**Status**: Proposed
**Context**: Research validation against the DMPI-PMHFE paper (arxiv.org/html/2506.06384v1, June 2025) revealed that our score-level ensemble (regex score + ML score → combined) underperforms feature-level fusion (DeBERTa embeddings + heuristic feature vector → FC classifier → prediction) by ~6% F1 and ~9% recall on external validation datasets. The paper demonstrates that ProtectAI's DeBERTa model (which we use) achieves only 75.32% recall on deepset-v2, while feature-level fusion achieves 84.31%.
**Decision**: Evolve the `EnsembleSecurityAnalyzer` to support feature-level fusion:
1. Extract DeBERTa's 768-dim embedding vector (average-pooled hidden states) instead of classification scores
2. Construct a typed heuristic feature vector (12-16 binary dimensions) covering: ignore/override, urgency, flattery, covert/stealth, format manipulation, hypothetical/roleplay, impersonation, immorality, many-shot Q&A, token repetition
3. Concatenate embeddings + heuristic features → FC layer (ReLU) → FC layer (softmax) → prediction
4. Train the FC layers offline on labelled prompt injection datasets (safeguard-v2, PromptShield benchmark)
5. Ship trained FC weights as a model artifact alongside DeBERTa weights
**Consequence**: Requires modifying the Candle model loading to extract intermediate embeddings. The FC layer adds <1ms inference. Training pipeline needs to be built (can use Python + export to safetensors). Expected improvement: +6% F1, +9% recall on external datasets. Score-level ensemble remains as fallback when FC weights unavailable.

---

## ADR-014: Unicode Normalisation as Security Preprocessing

**Date**: 2026-02-01
**Status**: Proposed
**Context**: Research from ACL LLMSEC 2025 (Mindgard, "Bypassing LLM Guardrails") demonstrated that character injection techniques (Unicode zero-width characters, homoglyphs, character smuggling) can bypass all tested guardrail systems including ProtectAI, Llama Guard, and Azure Prompt Shield. Our regex patterns are especially vulnerable because they match raw text without normalisation.
**Decision**: Add a mandatory Unicode normalisation preprocessing step before all security analysis:
1. Apply NFKC normalisation (canonical decomposition + compatibility composition)
2. Strip zero-width characters (U+200B, U+200C, U+200D, U+FEFF, U+200E, U+200F)
3. Normalise common homoglyphs (Cyrillic а→a, е→e, etc.)
4. This runs before `RegexSecurityAnalyzer`, `MLSecurityAnalyzer`, and `NerDetector`
**Consequence**: Small performance cost (<0.1ms). Closes a major adversarial vulnerability. May need a configurable allowlist for legitimate Unicode content in multilingual deployments.

---

## ADR-015: Output Safety Analysis Pipeline

**Date**: 2026-02-01
**Status**: Proposed
**Context**: Security state-of-the-art research (2026-02-01) identified output safety as the #1 gap in LLMTrace. We analyse inputs extensively but barely analyse outputs beyond PII and credential leakage. Industry frameworks (LLM Guard, LlamaFirewall, NeMo Guardrails) all include output toxicity/safety analysis. OWASP LLM Top 10 2025 adds Misinformation (LLM09) as a new category requiring hallucination and factual error detection.
**Decision**: Build a three-tier output safety pipeline:
1. **Tier 1 — Toxicity classifier**: BERT-based toxicity model (e.g., `unitary/toxic-bert`) run on all LLM responses via Candle. Detects harmful, toxic, biased content.
2. **Tier 2 — Streaming output moderation**: Extend existing SSE streaming analysis to run toxicity + PII + leakage checks on accumulated response tokens during streaming. Support early-stopping when harmful content threshold exceeded.
3. **Tier 3 — Hallucination detection** (future): HaluGate-style pipeline with sentinel pre-classification → token-level detection → NLI explanation. Leverages tool-call results visible in proxy traffic as ground truth.
**Consequence**: Tier 1 adds ~50-100ms per response (can be async). Tier 2 adds incremental cost during streaming. Tier 3 is a larger effort requiring new model training. Each tier is independently deployable behind feature flags.

---

## ADR-016: OWASP LLM Top 10 2025 Alignment

**Date**: 2026-02-01
**Status**: Proposed
**Context**: The OWASP LLM Top 10 was updated for 2025 with significant changes. Two new categories were added: System Prompt Leakage (LLM07) and Vector/Embedding Weaknesses (LLM08). Misinformation (LLM09) replaced Overreliance and now explicitly covers hallucinations. Sensitive Information Disclosure jumped from #6 to #2. Our current OWASP mapping (`docs/security/OWASP_LLM_TOP10.md`) references the 2024 categories.
**Decision**: Update OWASP mapping and test coverage for 2025:
1. Update `OWASP_LLM_TOP10.md` to reflect 2025 categories and numbering
2. Add detection for LLM07 (System Prompt Leakage): adversarial extraction attempt patterns, multi-turn extraction monitoring
3. Add detection for LLM08 (Vector/Embedding Weaknesses): RAG retrieval anomaly monitoring (where proxy can observe retrieval context)
4. Add detection for LLM09 (Misinformation): hallucination detection (see ADR-015 Tier 3)
5. Add detection for LLM10 (Unbounded Consumption): context window flooding detection
**Consequence**: Requires new detection patterns and potentially new models. Ensures LLMTrace remains aligned with the industry-standard threat model. Test file `owasp_llm_top10.rs` needs expansion.

---

*Add new ADRs as architectural decisions are made. Each ADR should capture context, decision, and consequences.*
