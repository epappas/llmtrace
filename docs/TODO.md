# LLMTrace Implementation TODO

**Generated from:** `docs/FEATURE_ROADMAP.md`
**Updated:** 2026-02-03
**Methodology:** RALPH loops — each loop spawns a Claude Code agent with strict quality gates, reviewed by lead engineer before merge.

---

## Status Legend
- ⬜ Not started
- 🔄 In progress
- ✅ Done
- ❌ Blocked

---

## Acceptance Criteria (Literature-Anchored)
These criteria define when a task can be marked ✅. If any criterion is not met, status must remain 🔄 or ⬜.

Input Security (IS): Must implement the specific algorithmic behaviors described in the literature, not heuristic approximations. For IS-001–IS-003, MOF requires token-wise bias detection, debiasing data generation, and retraining with reported over-defense gains in `docs/research/injecguard-over-defense-mitigation.md`. For IS-006/IS-007, thresholds must be calibrated at 0.1/0.5/1% FPR with TPR reporting per `docs/research/security-state-of-art-2026.md`. For IS-010/IS-011, WordNet-style synonym expansion and true lemmatization are required, not regex-only stems, per `docs/research/dmpi-pmhfe-prompt-injection-detection.md`. For IS-024–IS-029, adversarial robustness must include attack-specific defenses and calibration beyond normalization per `docs/research/bypassing-llm-guardrails-evasion.md`.

DMPI-PMHFE Architecture (DMPI-001–DMPI-006): The fusion pipeline must match the paper's dual-channel design before training (ML-001). Resolved: average pooling (DMPI-001), 2 FC layers (DMPI-002), 10 binary heuristic features with paper keyword sets (DMPI-003, DMPI-005), repetition threshold >=3 (DMPI-004). Remaining: `is_*` naming convention (DMPI-006). See Loop 12a and `docs/research/dmpi-pmhfe-prompt-injection-detection.md` for full specification. DMPI-006 is the remaining blocking prerequisite for ML-001 (fusion training).

Tool/Agent Security (AS): Tool boundary defenses must parse/sanitize with LLM-based extraction and CheckTool-style triggering detection, not heuristic filters, per `docs/research/defense-tool-result-parsing.md` and `docs/research/indirect-injection-firewalls.md`. Multi-agent defense requires an explicit coordinator + guard multi-pass architecture (and second opinion path) rather than a single-pass heuristic pipeline, per `docs/research/multi-agent-defense-pipeline.md`. Pattern enforcement must detect plan compliance and routing by trust level as defined in `docs/research/design-patterns-securing-agents.md`.

Output Security (OS): HaluGate-style token-level detection requires ModernBERT token classification and NLI explanation layer, not heuristic or sentence-only checks, per `docs/research/security-state-of-art-2026.md`. Streaming safety must use partial-sequence models and progressive confidence (SCM), not re-running full-text detectors, per `docs/research/security-state-of-art-2026.md`. CodeShield parity requires Semgrep integration and coverage beyond basic static rules, per `docs/research/security-state-of-art-2026.md`.

Privacy/Protocol/Multimodal (PR/AS/MM/SA): Membership inference, poisoning, MINJA, and protocol exploit defenses must match the threat models in `docs/research/prompt-injections-to-protocol-exploits.md`. Multimodal defenses must include OCR and modality-specific detectors as described in the same literature. Policy language and taint/blast-radius controls must align with `docs/research/llmtrace-defense-pipeline-design.md`.

Evaluation (EV): Benchmarks must implement the named suites with published dataset sizes and result formatting per `docs/research/benchmarks-and-tools-landscape.md` and `docs/research/wasp-web-agent-security-benchmark.md`.

Non-Functional Requirements (NFR): Security-critical detections must be deterministic and testable, with clear latency budgets where specified (e.g., HaluGate sentinel 12ms class, token-level detection 76–162ms) from `docs/research/security-state-of-art-2026.md`. Any ML integration must include reproducible model loading, configuration, and tests demonstrating expected metrics.

## Phase 1: Critical / Quick Wins

### Loop 1 — Unicode Evasion Defenses
> Close the 100% ASR emoji smuggling and upside-down text gaps

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| IS-020 | Emoji normalisation/stripping — 100% ASR, zero current defense | Low | ✅ `a62855b` |
| IS-021 | Upside-down text mapping — 100% jailbreak evasion | Low | ✅ `a62855b` |
| IS-022 | Unicode tag character stripping (U+E0001–U+E007F) | Low | ✅ `a62855b` |
| IS-031 | Diacritics-based evasion defense — accent marks | Low | ✅ `a62855b` |
| IS-015 | Braille encoding evasion defense | Low | ✅ `a62855b` |

### Loop 2 — NotInject Benchmark + 3D Evaluation
> Establish over-defense baseline and evaluation framework (current dataset: 210 samples, difficulty split 90/60/60)

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| IS-004 | NotInject-style over-defense benchmark dataset (339 samples, 3 difficulty levels) | Low | ✅ |
| IS-005 | Three-dimensional evaluation metrics (benign/malicious/over-defense) | Low | ✅ `33b3f55` |
| EV-002 | NotInject evaluation runner (dataset complete: 339 samples) | Low | ✅ |
| EV-010 | Paper-table output format for results | Low | ✅ `33b3f55` |

### Loop 3 — FPR-Aware Threshold Optimisation
> Evaluate at deployment-realistic FPR operating points

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| IS-006 | FPR-aware threshold optimisation — evaluate at 0.1%, 0.5%, 1% FPR | Medium | ✅ `fpr_monitor.rs` |
| IS-007 | Configurable operating points (high-precision / balanced / high-recall) | Low | ✅ (R8) |

### Loop 4 — Canary Token System
> Detect system prompt leakage in responses

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| SA-002 | Canary token injection and leakage detection | Low | ✅ `5b43d93` |

### Loop 5 — Tool Registry & Classification
> Foundation for agent security features

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| AS-008 | Tool registry with security classification (category, risk score, permissions) | Medium | ✅ `eae4ca3` |
| AS-015 | Action-type rate limiting | Low | ✅ `eae4ca3` |

### Loop 6 — Context Window Flooding Detection
> DoS prevention (OWASP LLM10)

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| IS-017 | Context window flooding detection | Low | ✅ `9997962` |

---

### Loop R0 — Scaffold the Workspace
> Create workspace, crates, and baseline repo hygiene

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL0-01 | Initialize Cargo workspace and required crates | Medium | ✅ |
| RL0-02 | Add root README, .gitignore, rustfmt config | Low | ✅ |
| RL0-03 | Ensure crates compile cleanly | Medium | ✅ |

### Loop R1 — Core Types & Traits
> Define foundational core types and traits

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL1-01 | Core types: TraceEvent, TraceSpan, TenantId, SecurityFinding, SecuritySeverity, LLMProvider, ProxyConfig | Medium | ✅ |
| RL1-02 | Core traits: StorageBackend (or successors), SecurityAnalyzer | Medium | ✅ |
| RL1-03 | Error types via thiserror, serde on public types, timestamp types | Medium | ✅ |
| RL1-04 | Serialization roundtrip tests | Medium | ✅ |

### Loop R2 — SQLite Storage Backend
> Implement SQLite storage backend

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL2-01 | Sqlite storage implementation with migrations | Medium | ✅ |
| RL2-02 | store/query/health_check for traces | Medium | ✅ |
| RL2-03 | Integration tests with temp DB | Medium | ✅ |

### Loop R3 — Basic Prompt Injection Detection
> Regex-based prompt injection detection

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL3-01 | RegexSecurityAnalyzer request/response scanning | Medium | ✅ |
| RL3-02 | Patterns: system override, role injection, base64, PII | Medium | ✅ |
| RL3-03 | Comprehensive tests for known attacks | Medium | ✅ |

### Loop R4 — Transparent Proxy Core
> Core proxy flow and async analysis

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL4-01 | HTTP proxy flow (accept, parse, forward, return) | High | ✅ |
| RL4-02 | Support OpenAI-compatible routes | Medium | ✅ |
| RL4-03 | Async trace capture + security analysis | Medium | ✅ |
| RL4-04 | Circuit breaker and health endpoint | Medium | ✅ |
| RL4-05 | YAML config loading | Medium | ✅ |

### Loop R5 — Streaming SSE Support
> Stream passthrough and token tracking

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL5-01 | Detect streaming requests and forward SSE | High | ✅ |
| RL5-02 | Incremental token/TTFT tracking | High | ✅ |
| RL5-03 | Integration tests with mock SSE upstream | Medium | ✅ |

### Loop R5.5 — Storage Layer Refactor
> Repository pattern split for traces/metadata/cache

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL5-501 | Split storage traits into trace/metadata/cache | High | ✅ |
| RL5-502 | Add tenant/config/audit types | Medium | ✅ |
| RL5-503 | Storage composite + profile factory | Medium | ✅ |
| RL5-504 | SQLite repos for traces + metadata, in-memory cache | High | ✅ |
| RL5-505 | Proxy integration with new storage profile config | High | ✅ |

### Loop R6 — Configuration & CLI
> CLI and config validation

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL6-01 | Clap CLI with proxy/validate subcommands | Medium | ✅ |
| RL6-02 | Example config + env var overrides | Medium | ✅ |
| RL6-03 | Structured logging | Low | ✅ |

### Loop R7 — Python Bindings
> PyO3 bindings and tests

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL7-01 | PyO3 crate setup + Python API | High | ✅ |
| RL7-02 | Python tests via maturin | Medium | ✅ |

### Loop R8 — Integration Test & Polish
> End-to-end proxy + docs

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL8-01 | Integration test with proxy + mock upstream | High | ✅ |
| RL8-02 | Top-level README, LICENSE | Low | ✅ |

## Phase 2: Major Features

### Loop 7 — Tool-Boundary Firewalling
> The "minimize & sanitize" approach — reported low ASR on paper benchmarks (scope-specific)

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| AS-001 | Tool-Input Firewall (Minimizer) — heuristic minimizer; no LLM-based minimization | High | 🔄 |
| AS-002 | Tool-Output Firewall (Sanitizer) — heuristic sanitizer; no LLM-based parsing | High | 🔄 |
| AS-003 | Tool context awareness — tool context defined but not used in minimizer/sanitizer | Medium | 🔄 |
| AS-004 | ParseData — extract minimal required data from tool outputs (LLM-based parsing not implemented) | High | 🔄 |
| AS-005 | Format constraint validation — heuristic rules only (no schema-driven parsing) | Medium | 🔄 |
| AS-006 | CheckTool — detect tool-output-triggered tool calls (heuristic only) | High | 🔄 |
| AS-007 | Tool output sanitization against injection triggers (heuristic only) | High | 🔄 |

### Loop 8 — Model Ensemble Diversification
> Replace single-model reliance with multi-architecture ensemble

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| ML-002 | InjecGuard model integration | Medium | ✅ `10a2369` |
| ML-003 | Meta Prompt Guard 2 integration (86M + 22M) | Medium | ✅ `10a2369` |
| ML-006 | Multi-model ensemble voting with diverse architectures — framework only, no default diverse set wired | Medium | 🔄 |
| ML-004 | PIGuard model integration | Medium | ⬜ |
| ML-007 | Model hot-swapping without proxy restart | Medium | ⬜ |

### Loop 9 — Action-Selector Pattern Enforcement
> Provable security patterns at proxy level

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| AS-010 | Action-Selector pattern — enforce action allowlists at proxy level | Medium | ✅ `89ba304` |
| AS-012 | Context-Minimization — strip unnecessary context | Medium | ✅ `89ba304` |
| AS-011 | Plan-then-execute pattern detection | High | ⬜ |
| AS-014 | Plan compliance monitoring for declared security patterns | High | ⬜ |
| AS-013 | Dual LLM routing for trusted/untrusted data | High | ⬜ |
| AS-016 | Trust-based routing by data source | High | ⬜ |

### Loop 10 — Multi-Agent Defense Coordination
> Coordinator + Guard architecture — reported low ASR on paper benchmarks (scope-specific)

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| AS-020 | Coordinator agent — pre-input classification (policy/heuristic pipeline only) | High | 🔄 |
| AS-021 | Guard agent — post-generation validation (policy/heuristic pipeline only) | High | 🔄 |
| AS-022 | Hierarchical coordinator pipeline (safe routing/refusal) | High | ⬜ |
| AS-023 | Second opinion pass for borderline cases (no true multi-agent LLM pass) | Medium | 🔄 |
| AS-024 | Policy store — centralised security rules (in-memory, not externalized) | Medium | 🔄 |
| AS-025 | Multi-step action correlation across requests | High | ✅ |
| AS-026 | Multi-turn persistence detection for gradual bypass attempts | High | ✅ |

### Loop 11 — MCP Protocol Monitoring
> First-mover in protocol-level security

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| AS-030 | MCP monitoring — detect manipulation and server-side attacks | High | ✅ `mcp_monitor.rs` |
| AS-035 | Toxic Agent Flow defense — GitHub MCP vulnerability (generic MCP scanning only) | Medium | 🔄 |
| AS-036 | ToolHijacker defense — tool selection manipulation (generic MCP scanning only) | High | 🔄 |

### Loop 12 — Advanced Prompt Injection Detection
> Synonym expansion, lemmatisation, P2SQL

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| IS-010 | Synonym expansion for attack patterns (manual synonym regex, not WordNet) | Medium | 🔄 |
| IS-011 | Lemmatisation before pattern matching (basic stemming, not true lemmatization) | Low | 🔄 |
| IS-012 | P2SQL injection detection (regex only, no structured SQL parsing) | Medium | 🔄 |
| IS-013 | Long-context jailbreak detection (position-aware sliding window) | High | ⬜ |
| IS-014 | Automated jailbreak defense (GPTFuzz-style genetic templates) | High | ⬜ |
| IS-016 | Multi-turn extraction detection (session-aware probing) | High | 🔄 |
| IS-040 | Data format coverage expansion (17 formats) | Medium | ⬜ |
| IS-041 | Multi-language trigger detection | High | ⬜ |
| IS-018 | "Important Messages" header attack hardening | Low | 🔄 |
| IS-050 | Perplexity-based anomaly detection for GCG-optimized strings in tool outputs | Medium | ⬜ |
| IS-051 | Adaptive monitoring scope (input-only vs hybrid) to control attack surface | Medium | ⬜ |
| IS-052 | Adversarial string propagation blocking in tool outputs (perplexity threshold) | High | ⬜ |

### Loop 12a — DMPI-PMHFE Architecture Alignment
> Resolve 6 architectural deviations between codebase and DMPI-PMHFE paper (arXiv 2506.06384). 5 resolved (DMPI-001, DMPI-002, DMPI-003, DMPI-004, DMPI-005), 1 remaining (DMPI-006).
> Must be completed before Loop 15 (Fusion Training Pipeline) to ensure trained weights match the paper.
> Reference: `docs/research/dmpi-pmhfe-prompt-injection-detection.md`

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| DMPI-001 | **Average pooling instead of CLS token** — Implemented `masked_mean_pool()` in `ml_detector.rs`. Added `PoolingStrategy` enum (Cls/MeanPool), defaulting to MeanPool. BERT and DeBERTa paths both use attention-mask-aware average pooling over all non-padding tokens, matching paper spec. `DebertaV2ContextPooler` is now optional (only loaded for Cls strategy). Architecture doc: `docs/architecture/DMPI_001_AVERAGE_POOLING.md`. | Medium | :white_check_mark: |
| DMPI-002 | **2 FC layers instead of 3** — Removed `HIDDEN_2` and `fc3`; collapsed to `fc1(783->256)->ReLU->fc2(256->2)->SoftMax` matching paper spec. Input dim changes from 783 to 778 once DMPI-003 is also applied (768 + 10 = 778). Architecture doc: `docs/architecture/DMPI_002_TWO_FC_LAYERS.md`. | Medium | :white_check_mark: |
| DMPI-003 | **10 binary features instead of 15 mixed** — Replaced 15-dim vector (8 binary + 7 numeric) with 10 binary features matching paper Appendix A. Removed all numeric features. Added keyword-based detection for `is_ignore`, `is_format_manipulation`, `is_immoral`. Reordered to paper spec. Architecture doc: `docs/architecture/DMPI_003_TEN_BINARY_FEATURES.md`. | High | :white_check_mark: |
| DMPI-004 | **Repetition threshold >=3 instead of >10** — Named constant `REPETITION_THRESHOLD = 3`. Word-level and phrase-level conditions changed to `>= REPETITION_THRESHOLD`. Expanded `COMMON_WORDS` (+37 words) and added `COMMON_PHRASES` exclusion list (29 common English bigrams) to control false positives at the lower threshold. | Low | :white_check_mark: |
| DMPI-005 | **Missing paper features: is_immoral, is_ignore, is_format_manipulation** — All 3 missing features now implemented as keyword-in-text checks in `feature_extraction.rs`. `is_ignore` (index 0): ignore, reveal, disregard, forget, overlook, regardless. `is_format_manipulation` (index 4): encode, disguising, morse, binary, hexadecimal. `is_immoral` (index 7): hitting, amoral, immoral, deceit, irresponsible, offensive, violent, unethical, smack, fake, illegal, biased. Resolved as part of DMPI-003. Architecture doc: `docs/architecture/DMPI_003_TEN_BINARY_FEATURES.md`. | Medium | :white_check_mark: |
| DMPI-006 | **Feature naming alignment to paper convention** — `feature_extraction.rs:41-50` uses `flattery_attack, urgency_attack, roleplay_attack, impersonation_attack, covert_attack, excuse_attack, many_shot_attack, repetition_attack`. Paper uses `is_ignore, is_urgent, is_incentive, is_covert, is_format_manipulation, is_hypothetical, is_systemic, is_immoral, is_shot_attack, is_repeated_token`. Zero occurrences of any `is_*` paper name exist in the codebase. Rename for traceability: `flattery_attack->is_incentive`, `urgency_attack->is_urgent`, `roleplay_attack->is_hypothetical`, `impersonation_attack->is_systemic`, `covert_attack->is_covert`, `excuse_attack->is_immoral`, `many_shot_attack->is_shot_attack`, `repetition_attack->is_repeated_token`. Downstream finding types in `lib.rs` pattern definitions and serialization code must be updated accordingly. | Low | ⬜ |

### Loop 13 — Hallucination Detection Upgrade
> HaluGate-style token-level detection

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| OS-001 | Token-level hallucination detection (ModernBERT) | High | ⬜ |
| OS-002 | NLI explanation layer for flagged spans | High | ⬜ |
| OS-003 | ModernBERT sentinel pre-classifier | Medium | ⬜ |
| OS-004 | Tool-call result as ground truth for fact-checking | Medium | ⬜ |
| OS-005 | Semantic entropy-based detection | High | ⬜ |
| OS-006 | Citation validation | High | ⬜ |
| ML-005 | ModernBERT support (for token/sentinel classifiers) | High | ⬜ |

### Loop 14 — Content Safety Expansion
> Llama Guard integration, bias detection

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| OS-022 | Llama Guard 3 integration (14 harm categories) | Medium | ⬜ |
| OS-021 | Bias detection in responses | Medium | ⬜ |
| OS-020 | Constitutional classifiers for output moderation | High | ⬜ |
| OS-023 | Language detection for unexpected output switches | Low | ⬜ |
| OS-024 | Sentiment analysis for manipulative content | Low | ⬜ |
| OS-030 | CodeShield-style code security expansion | High | 🔄 |
| OS-031 | Semgrep rule integration for code outputs | High | ⬜ |
| OS-032 | Supply chain security in code (typosquatting, confusion) | High | ⬜ |

### Loop 15 — Fusion Training Pipeline
> Train the fusion classifier with real data

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| ML-001 | Joint end-to-end training for fusion FC layer | High | ⬜ |
| ML-014 | Curated training dataset (61k benign + 16k injection) | Medium | ⬜ |
| IS-001 | Token-wise bias detection for over-defense | High | ⬜ |
| IS-002 | Adaptive debiasing data generation (1–3 token combos) | High | ⬜ |
| IS-003 | MOF retraining pipeline on debiased data | High | ⬜ |
| ML-010 | MOF training pipeline (token bias → debiasing → retraining) | High | ⬜ |
| ML-011 | Data-centric augmentation across 17 formats | Medium | ⬜ |
| ML-015 | GradSafe integration | High | ⬜ |
| ML-016 | GCG adversarial sample generation (Python/PyTorch tooling; shared with EV-017) | High | ⬜ |
| ML-020 | ONNX runtime support for inference | Medium | ⬜ |
| ML-021 | INT8/INT4 quantized model loading | Medium | ⬜ |
| ML-022 | Batched inference for GPU utilization | Medium | ⬜ |

### Loop 16 — Benchmark Evaluation Suite
> Evaluate against all major benchmarks

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| EV-001 | AgentDojo evaluation (97 environments) | Medium | ⬜ |
| EV-003 | InjecAgent evaluation | Medium | ⬜ |
| EV-004 | ASB evaluation | Medium | ⬜ |
| EV-005 | WASP evaluation | Medium | ⬜ |
| EV-006 | CyberSecEval 2 prompt injection evaluation (251 attack samples per DMPI-PMHFE [28]) | Medium | ⬜ |
| EV-007 | MLCommons AILuminate jailbreak benchmark | Medium | ⬜ |
| EV-008 | HPI_ATTACK_DATASET evaluation (400 instances) | Low | ⬜ |
| EV-009 | Automated CI-integrated benchmark runner | Medium | ⬜ |
| EV-011 | safeguard-v2 evaluation (1300 samples) | Low | ⬜ |
| EV-012 | deepset-v2 evaluation (354 samples) | Low | ⬜ |
| EV-013 | Ivanleomk-v2 evaluation (610 samples) | Low | ⬜ |
| EV-014 | BIPIA evaluation (86,250 test prompts, 5 scenarios, 50 attack types, 25-model ASR baseline) | Medium | ⬜ |
| EV-015 | HarmBench evaluation (standardized jailbreak/safety ASR measurement) | Medium | ⬜ |
| EV-016 | AgentDojo Slack suite adaptive attack evaluation (Agent-as-a-Proxy resilience, 89 samples) | High | ⬜ |
| EV-017 | Multi-objective GCG adversarial robustness red-team testing against LLMTrace ensemble | High | ⬜ |
| EV-018 | Cross-model transfer attack resistance testing across ensemble members | Medium | ⬜ |

---

### Loop R9 — REST Query API

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL9-01 | Trace/span query endpoints + pagination | High | ✅ |
| RL9-02 | Security findings endpoint | Medium | ✅ |
| RL9-03 | API tests | Medium | ✅ |

### Loop R10 — LLM Provider Auto-Detection

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL10-01 | Provider detection by path/header/host | Medium | ✅ |
| RL10-02 | Provider-specific response parsing | Medium | ✅ |
| RL10-03 | Provider detection tests | Medium | ✅ |

### Loop R11 — Cost Estimation Engine

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL11-01 | Pricing table + estimate_cost API | Medium | ✅ |
| RL11-02 | Custom pricing config | Medium | ✅ |
| RL11-03 | Tests for pricing | Medium | ✅ |

### Loop R12 — Alert Engine (Webhooks)

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL12-01 | Webhook alerting with thresholds + cooldown | Medium | ✅ |
| RL12-02 | Mock webhook tests | Medium | ✅ |

### Loop R13 — Tenant Management API

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL13-01 | Tenant CRUD endpoints + audit | High | ✅ |
| RL13-02 | Auto-create tenant on first request | Medium | ✅ |
| RL13-03 | API tests | Medium | ✅ |


### Loop R14 — ClickHouse TraceRepository

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL14-01 | ClickHouse TraceRepository implementation | High | ✅ |
| RL14-02 | Feature-gated ClickHouse tests | High | 🔄 |

### Loop R15 — PostgreSQL MetadataRepository

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL15-01 | Postgres MetadataRepository + migrations | High | ✅ |
| RL15-02 | Postgres integration tests | High | ⬜ |

### Loop R16 — Redis CacheLayer

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL16-01 | Redis CacheLayer implementation | Medium | ✅ |
| RL16-02 | Cache TTL and invalidation tests | Medium | ⬜ |

### Loop R17 — Data Retention & Purging

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL17-01 | Retention policies + purge job | Medium | 🔄 |
| RL17-02 | Purge audit logging | Medium | ⬜ |

### Loop R18 — Agent Action Analysis

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL18-01 | AgentAction model + auto-parse tool calls | High | ✅ |
| RL18-02 | Actions reporting API + query filters | High | ✅ |
| RL18-03 | Action security analysis + storage | High | ✅ |
| RL18-04 | Python SDK action reporting | Medium | ✅ |

## Phase 3: Research Frontier

### Loop 17 — Multimodal Security
| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| MM-001 | Image injection detection | High | ⬜ |
| MM-004 | OCR-based text extraction from images | Medium | ⬜ |
| MM-002 | Audio injection detection | High | ⬜ |
| MM-003 | Cross-modal consistency checking | High | ⬜ |
| MM-005 | Steganography detection (image/audio) | High | ⬜ |
| MM-006 | Video frame injection detection | High | ⬜ |

### Loop 18 — Protocol Security (A2A/ANP)
| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| AS-031 | A2A protocol security | High | ⬜ |
| AS-032 | ANP protocol security | High | ⬜ |
| AS-033 | Dynamic trust management | High | ⬜ |
| AS-034 | Inter-agent trust verification | High | ⬜ |

### Loop 19 — Streaming Content Monitor
| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| OS-010 | Purpose-built partial-sequence detection models | High | ⬜ |
| OS-011 | Training-inference gap mitigation (partial sequence training) | High | ⬜ |
| OS-012 | Token-level harm annotations | High | ⬜ |
| OS-013 | Progressive confidence scoring | Medium | ⬜ |

### Loop 20 — Advanced Privacy
| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| PR-001 | Membership inference defense | High | ⬜ |
| PR-002 | Data extraction prevention | High | ⬜ |
| PR-003 | Federated learning poisoning defense | High | ⬜ |
| PR-004 | Vector/embedding poisoning detection | High | ⬜ |
| PR-005 | RAG retrieval anomaly monitoring | Medium | ⬜ |
| PR-006 | Multi-language PII detection (non-Latin scripts) | High | 🔄 |
| PR-007 | Context-aware PII enhancement (lemma-based boosting) | Medium | 🔄 |
| PR-009 | Compliance mapping to GDPR/HIPAA/CCPA entities | Medium | 🔄 |
| PR-010 | Memory poisoning detection (MINJA) | High | ⬜ |
| PR-011 | Cross-session state integrity | High | ⬜ |
| PR-008 | Custom PII entity type plugins | Medium | ⬜ |
| PR-012 | Speculative side-channel defense | High | ⬜ |

### Loop 21 — Policy Language
| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| SA-001 | Declarative policy specification (Colang/OPA-style) | High | ⬜ |
| SA-003 | Taint tracking | High | ⬜ |
| SA-004 | Blast radius reduction for tool access | Medium | ⬜ |
| SA-005 | Backdoor detection (prompt/parameter level) | High | ⬜ |
| SA-006 | Composite backdoor detection (CBA-style) | High | ⬜ |
| SA-007 | Data poisoning detection (PoisonedRAG) | High | ⬜ |
| SA-008 | Social engineering simulation defense | High | ⬜ |
| SA-009 | Contagious recursive blocking defense | High | ⬜ |
| SA-010 | GuardReasoner integration | High | ⬜ |

### Loop 22 — Adversarial ML Robustness
| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| IS-024 | AML evasion resistance (TextFooler, BERT-Attack, BAE) — normalization only, no attack-specific defenses | High | 🔄 |
| IS-025 | Ensemble diversification against transferability — no transferability testing or training | High | 🔄 |
| IS-026 | Adversarial training integration (TextAttack samples) | High | ⬜ |
| IS-027 | Adaptive thresholding for evasion indicators | Medium | ⬜ |
| IS-028 | Multi-pass normalisation (aggressive + conservative + semantic-preserving) | Medium | 🔄 |
| ML-012 | Adversarial training on TextAttack samples | High | ⬜ (needs training pipeline) |
| ML-013 | Robust training with Unicode/character injection samples | High | ⬜ |
| IS-029 | Confidence calibration (Platt scaling) — temperature scaling only | Medium | 🔄 |
| IS-023 | Character smuggling variants (comprehensive unicode exploitation) | Medium | 🔄 |
| IS-030 | Word-importance transferability mitigation | High | ⬜ |

---

### Loop R19 — ML Prompt Injection Detection (Candle)

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL19-01 | Candle ML detector + ensemble integration | High | ✅ |
| RL19-02 | ML config wiring + fallback | Medium | ✅ |
| RL19-03 | Benchmark + tests | Medium | 🔄 |

### Loop R20 — OpenTelemetry Ingestion Gateway

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL20-01 | OTLP/HTTP endpoint + mapping | High | ✅ |
| RL20-02 | OTEL ingestion tests | Medium | ✅ |

### Loop R21 — Web Dashboard

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL21-01 | Next.js dashboard scaffolding + pages | High | ✅ |
| RL21-02 | API client + charts + Docker | High | ✅ |

### Loop R22 — CI/CD Pipeline

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL22-01 | CI workflow (fmt/clippy/test) | Medium | ⬜ |
| RL22-02 | Release workflow + image scan | Medium | ⬜ |

### Loop R23 — RBAC & Auth

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL23-01 | API keys + role enforcement | High | ✅ |
| RL23-02 | Tenant isolation | High | ✅ |

### Loop R24 — Compliance Reporting

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL24-01 | Report generator + API | High | ✅ |
| RL24-02 | Optional PDF export | Medium | ⬜ |

### Loop R25 — gRPC Ingestion Gateway

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL25-01 | gRPC ingestion server + proto | High | ✅ |
| RL25-02 | Streaming ingestion support | High | ✅ |

### Loop R26 — Kubernetes Operator + Helm

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL26-01 | Helm chart + deployment docs | High | ✅ |
| RL26-02 | Optional CRD operator | High | ⬜ |

### Loop R27 — WASM Bindings

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL27-01 | wasm-bindgen crate + JS API | Medium | ✅ |
| RL27-02 | WASM tests | Medium | ✅ |

### Loop R28 — Node.js Bindings

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL28-01 | napi-rs bindings + TS types | Medium | ✅ |
| RL28-02 | Node tests | Medium | ✅ |


### Loop R29 — Statistical Anomaly Detection

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL29-01 | Anomaly detector + config | High | ✅ |
| RL29-02 | Alert integration + tests | High | ✅ |

### Loop R30 — Real-time Streaming Security Analysis

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL30-01 | Streaming incremental analysis | High | ✅ |
| RL30-02 | Mid-stream alerting tests | High | ✅ |

### Loop R31 — Expanded PII Detection

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL31-01 | International PII patterns + suppression | High | ✅ |
| RL31-02 | PII redaction modes + tests | High | ✅ |

### Loop R32 — ML PII via NER

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL32-01 | NER model integration + ensemble | High | ✅ |
| RL32-02 | NER tests | Medium | ✅ |

### Loop R33 — ML Inference Monitoring + Warm-up

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL33-01 | Inference timing + preload | Medium | ✅ |
| RL33-02 | Warm-up tests | Medium | ✅ |

### Loop R34 — Multi-Channel Alerting

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL34-01 | Slack/PagerDuty/Email channels | High | 🔄 |
| RL34-02 | Escalation + deduplication tests | High | 🔄 |

### Loop R35 — Externalize Pricing + OWASP Tests

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL35-01 | Pricing config externalization | Medium | ✅ |
| RL35-02 | OWASP LLM Top 10 test suite | High | ✅ |


### Loop R36 — Graceful Shutdown + Signal Handling

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL36-01 | SIGTERM/SIGINT handling + task drain | High | ✅ |
| RL36-02 | Shutdown tests | Medium | ✅ |

### Loop R37 — Prometheus Metrics Endpoint

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL37-01 | Metrics endpoint + instrumentation | High | ✅ |
| RL37-02 | Metrics tests | Medium | ✅ |

### Loop R38 — Database Migration Management

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL38-01 | Migration tooling + CLI | High | ✅ |
| RL38-02 | Migration tests | Medium | 🔄 |

### Loop R39 — Secrets Hardening + Startup Probe

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL39-01 | Secrets hardening + startup probe | Medium | ✅ |

### Loop R40 — Integration Tests in CI + Container Scanning

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL40-01 | Compose-based integration tests in CI | High | ⬜ |
| RL40-02 | Container scanning in release | Medium | ⬜ |

### Loop R41 — Per-tenant Rate Limiting + Compliance Persistence

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| RL41-01 | Tenant rate limiting middleware | High | ✅ |
| RL41-02 | Compliance report persistence + API | High | ✅ |
## Quality Gates (enforced on every loop)

1. **cargo fmt --all --check** — zero diffs
2. **cargo clippy --workspace -- -D warnings** — zero warnings
3. **cargo test --workspace** — zero failures (pre-existing failures must be fixed)
4. **Lead engineer review** — diff reviewed before commit
5. **CI green** — verified after push

## Notes

- IS-007 (Configurable operating points) completed in R8 commit `41e219b`
- R11 (code_security module) completed in commit `b08dccc`, tests fixed in `aa9ab98`
- Each loop targets a coherent feature set that can be tested independently
- Phase 1 focuses on closing critical 100% ASR gaps and establishing evaluation baseline
- RALPH quality policy: no placeholders/mocks; if spec requires ML, implement real ML inference (regex fallback only when model weights unavailable).
- AS-004/AS-006/AS-007 are 🔄 because literature expects LLM-based parsing/sanitization for tool outputs; current implementation is heuristic only.
- AS-020/AS-021/AS-023/AS-024 are 🔄 because literature expects multi-agent LLM coordination; current implementation is heuristic/policy-only.
- IS-024/IS-027/IS-028/IS-029 are 🔄 because only normalization/temperature scaling exists (no attack-specific defenses or Platt scaling).
- PR-006 is 🔄 because full non-Latin PII coverage and a custom-entity plugin architecture are not fully implemented.
- Tool parsing expectations come from `docs/research/defense-tool-result-parsing.md` and `docs/research/indirect-injection-firewalls.md`.
- Multi-agent expectations come from `docs/research/multi-agent-defense-pipeline.md`.
- Adversarial robustness expectations come from `docs/research/bypassing-llm-guardrails-evasion.md`.
- Over-defense mitigation expectations come from `docs/research/injecguard-over-defense-mitigation.md`.
- Benchmark coverage expectations come from `docs/research/benchmarks-and-tools-landscape.md` and `docs/research/wasp-web-agent-security-benchmark.md`.
- CyberSecEval 2 benchmark expectations (EV-006) come from `docs/research/cyberseceval2-llm-security-benchmark.md`. The 251 attack sample count is sourced from DMPI-PMHFE (arXiv 2506.06384) which used the CyberSecEval 2 prompt injection dataset; the full paper covers additional suites (500 code interpreter abuse prompts, exploit generation, FRR).
- BIPIA benchmark expectations (EV-014) come from `docs/research/bipia-indirect-prompt-injection-benchmark.md`. First indirect prompt injection benchmark (KDD 2025, arXiv 2312.14197): 86,250 test prompts, 50 attack types, 25-model baseline. Boundary token defense (`<data>`/`</data>`) is most impactful intervention (1064% ASR increase without it) and is implementable at proxy level (relevant to AS-001/AS-002).
- Agent-as-a-Proxy attack implications (EV-016) come from `docs/research/agent-as-a-proxy-attacks.md`. Monitoring-based defenses (including LLMTrace proxy monitoring) are fundamentally fragile: 90%+ ASR via GCG-optimized adversarial strings. Validates that structural defenses (AS-001/AS-002 sanitization, boundary tokens) are more robust than observation-based monitoring. High-perplexity detection in tool outputs is a viable countermeasure.
- IS-050 -> IS-052 dependency: IS-052 (adversarial string propagation blocking) depends on IS-050 (perplexity-based anomaly detection) for surprisal scoring. IS-050 must be implemented first. IS-052 runs before AS-002 in the tool-output sanitization pipeline.
- IS-050 -> IS-051 implicit dependency: IS-051 (adaptive monitoring scope) auto-switches to input-only mode when IS-050 detects sustained high-perplexity anomalies in tool outputs (suggests active adaptive attack). IS-050 must be implemented first for auto-switching; manual override works independently.
- ML-016 and EV-017 share GCG Python/PyTorch offline tooling (`tools/gcg/` or `scripts/adversarial/`). Not part of the Rust proxy runtime.
- EV-016 and EV-001 share AgentDojo benchmark infrastructure. EV-016 focuses on Slack suite (89 samples) with adaptive (GCG) attacks; EV-001 covers the full 97 environments.
- EV-018 depends on ML-006 (ensemble must be wired before transfer resistance can be tested).
- ML-016 (GCG adversarial sample generation) is in Loop 15 (Fusion Training Pipeline). Requires Python/PyTorch offline tooling, not Rust proxy code. Shared with EV-017.
- DMPI-001–DMPI-006 (Loop 12a) are blocking prerequisites for ML-001 (Loop 15). The fusion classifier cannot be trained against the paper's architecture until pooling, layer count, feature vector, thresholds, and feature naming all match the DMPI-PMHFE specification. See `docs/research/dmpi-pmhfe-prompt-injection-detection.md` for the authoritative paper breakdown.
- DMPI-003 and DMPI-005 resolved together: feature vector is now 10 binary dimensions matching paper Appendix A. See `docs/architecture/DMPI_003_TEN_BINARY_FEATURES.md`.
- DMPI-006 (naming) should be done last since it touches all downstream finding types and serialization.
- EV-002 is ✅ because the NotInject dataset is 339 samples with equal difficulty tiers (113/113/113).
