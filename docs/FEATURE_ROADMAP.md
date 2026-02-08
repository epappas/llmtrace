# LLMTrace Feature Roadmap: State-of-the-Art Gap Analysis & Implementation Plan

**Version**: 1.0
**Date**: 2026-02-01
**Author**: LLMTrace Engineering
**Scope**: Comprehensive feature gap analysis across 16 research documents in `docs/research/`, competitive landscape, and phased implementation plan

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Current Capabilities](#2-current-capabilities)
3. [Feature Gap Analysis](#3-feature-gap-analysis)
   - [3.1 Input Security](#31-input-security)
   - [3.2 Output Security](#32-output-security)
   - [3.3 Agent Security](#33-agent-security)
   - [3.4 ML Pipeline & Architecture](#34-ml-pipeline--architecture)
   - [3.5 Multimodal Security](#35-multimodal-security)
   - [3.6 Privacy](#36-privacy)
   - [3.7 Evaluation & Benchmarking](#37-evaluation--benchmarking)
4. [Implementation Roadmap](#4-implementation-roadmap)
5. [Competitive Landscape](#5-competitive-landscape)
6. [Research Paper Reference Index](#6-research-paper-reference-index)

---

## 1. Executive Summary

### Where LLMTrace Stands Today

LLMTrace is a **Rust-native transparent security proxy** for LLM interactions. It operates at the HTTP proxy layer with zero-integration deployment, providing real-time security analysis using a hybrid approach: regex-based heuristic detection, DeBERTa-v3-base ML classification (via the Candle framework), BERT NER for PII detection, and an ensemble combination of multiple signal sources.

**Overall Assessment: 7/10** — LLMTrace has strong foundational architecture and is ahead of most open-source frameworks on performance and streaming analysis. However, significant gaps exist in advanced attack detection, agent/protocol security, multimodal threats, and over-defense mitigation.

### Key Strengths
- **Rust-native performance**: <1ms regex analysis, ~50-100ms ML inference — faster than any Python framework
- **True transparent proxy**: Zero-code integration deployment model
- **Streaming security**: Real-time SSE analysis with output-side monitoring and early stopping
- **Feature-level fusion**: Implemented (ADR-013) — DeBERTa average-pooled embedding concatenated with 10-dim binary heuristic vector through 2-layer FC classifier (random weights). **Note:** 1 architectural deviation from DMPI-PMHFE paper remains (DMPI-006): non-paper feature names. DMPI-001 (average pooling), DMPI-002 (2 FC layers), DMPI-003 (10 binary features), DMPI-004 (repetition threshold >=3), and DMPI-005 (missing features) resolved. See section 3.4.1.
- **Comprehensive input security**: 40+ regex patterns covering 8 attack categories (flattery, urgency, roleplay, impersonation, covert, excuse, many-shot, repetition)
- **Unicode normalisation**: NFKC + zero-width stripping + homoglyph mapping (Cyrillic, Greek)
- **Output safety**: Toxicity detection (BERT-based + keyword fallback), hallucination detection (cross-encoder + heuristic fallback)
- **Code security**: Static analysis for 7 vulnerability categories across 11 programming languages
- **PII with validation**: Checksum validation (Luhn, IBAN, SSN) + context-aware false-positive suppression
- **Secret scanning**: JWT, AWS keys, GitHub tokens, GCP, Slack, SSH keys

### Critical Gaps vs State-of-the-Art
1. **Over-defense mitigation** — No MOF training strategy; FPR at deployment-realistic thresholds unknown [Papers: InjecGuard, PromptShield]
2. **Protocol security** — No MCP/A2A/ANP protocol monitoring [Paper: Protocol Exploits]
3. **Tool-boundary firewalling** — No input minimisation or output sanitisation at tool boundaries [Papers: Indirect Injection Firewalls, Tool Result Parsing]
4. **Multimodal attacks** — No image/audio injection detection [Paper: Protocol Exploits]
5. **Adversarial ML robustness** — ProtectAI DeBERTa model has documented 20-95% ASR from TextAttack [Paper: Bypassing Guardrails]
6. **Multi-agent coordination** — Single-pass analysis vs multi-pass defence-in-depth [Paper: Multi-Agent Defense]
7. **Benchmark evaluation** — No evaluation against AgentDojo, NotInject, InjecAgent, WASP [Paper: Benchmarks & Tools]

### Audit Acceptance Criteria (Literature-Anchored)
All roadmap items can only be marked **✅ Implemented** if the implementation matches the behaviors and metrics described in the cited literature. Heuristic or partial substitutes must remain **⚠️ Partial**.

Functional Requirements: Input-security improvements must implement MOF training (token-wise bias detection, debiasing data generation, retraining) and calibrated FPR operating points as described in `docs/research/injecguard-over-defense-mitigation.md` and `docs/research/security-state-of-art-2026.md`. Tool-boundary defenses must implement LLM-based tool result parsing and CheckTool-style triggering detection per `docs/research/defense-tool-result-parsing.md` and `docs/research/indirect-injection-firewalls.md`. Multi-agent defense must be a multi-pass coordinator+guard architecture with a second-opinion path per `docs/research/multi-agent-defense-pipeline.md`. Output safety must implement HaluGate-style token-level detection, NLI explanation, and SCM streaming models per `docs/research/security-state-of-art-2026.md`.

DMPI-PMHFE Architecture (DMPI-001–DMPI-006): The fusion pipeline must match the paper's dual-channel design before training (ML-001). Required: average pooling over all token embeddings (not CLS) [DONE], exactly 2 FC layers (not 3) [DONE], exactly 10 binary heuristic features (not 15 mixed) [DONE], paper keyword sets for is_ignore/is_format_manipulation/is_immoral [DONE], paper's `is_*` naming convention [DMPI-006], and pattern thresholds of >=3 (not >10) [DMPI-004]. 4 of 6 deviations resolved; 2 remaining (DMPI-004, DMPI-006) are blocking prerequisites for ML-001. See `docs/research/dmpi-pmhfe-prompt-injection-detection.md` for full specification.

Non-Functional Requirements: Latency classes and streaming compatibility must meet literature expectations (e.g., sentinel-class latency, token-level detection ranges) from `docs/research/security-state-of-art-2026.md`. Implementations must be deterministic, testable, and include benchmark evidence where the literature reports metrics (e.g., ASR, FPR, F1) using datasets from `docs/research/benchmarks-and-tools-landscape.md` and `docs/research/wasp-web-agent-security-benchmark.md`.

---

## 2. Current Capabilities

### 2.1 Input Security

| Capability | Module | Description |
|-----------|--------|-------------|
| Prompt injection detection (regex) | `lib.rs` | 40+ patterns across system override, role injection, delimiter injection |
| Prompt injection detection (ML) | `ml_detector.rs` | DeBERTa-v3-base (`protectai/deberta-v3-base-prompt-injection-v2`) |
| Feature-level fusion | `fusion_classifier.rs` | 778-dim input (768 DeBERTa average-pooled + 10 binary heuristic) → FC(256) → ReLU → FC(2) → Softmax. DMPI-001 (pooling), DMPI-002 (2 FC layers), DMPI-003 (10 binary features), DMPI-005 (missing features) resolved. |
| Heuristic feature extraction | `feature_extraction.rs` | 10-dim binary vector matching paper Appendix A: 7 finding-based + 3 keyword-based features. DMPI-003 and DMPI-005 resolved. See DMPI-006 for naming alignment. |
| Flattery/incentive detection | `lib.rs` | 5 patterns: best_ai, reward, capable_ai, so_smart, tip |
| Urgency detection | `lib.rs` | 4 patterns: emergency, lives_depend, respond_immediately, time_sensitive |
| Roleplay/hypothetical detection | `lib.rs` | 5 patterns: pretend, game, hypothetical, dan_identity, act_as_if |
| Impersonation detection | `lib.rs` | 5 patterns: developer, admin_override, sysadmin, internal, creator |
| Covert/stealth detection | `lib.rs` | 5 patterns: dont_tell, between_us, secret_test, off_record, bypass |
| Excuse detection | `lib.rs` | 4 patterns: educational, researcher, novel, fictional. **Note:** paper's `is_immoral` feature (hitting, amoral, immoral, deceit, irresponsible, offensive, violent, unethical, smack, fake, illegal, biased) is entirely absent. See DMPI-005. |
| Many-shot attack detection | `lib.rs` | Q&A pair counting (threshold ≥ 3 pairs) |
| Repetition attack detection | `lib.rs` | Word-level (>=3 occurrences) and phrase-level (2-3 gram, >=3 occurrences) with common-word and common-phrase exclusion lists. Matches DMPI-PMHFE paper threshold (>=3). |
| Base64 encoding detection | `lib.rs` | Decode candidates and check for suspicious instruction phrases |
| Jailbreak detection (dedicated) | `jailbreak_detector.rs` | DAN, system prompt extraction, privilege escalation, encoding evasion |
| Encoding evasion detection | `jailbreak_detector.rs` | Base64, ROT13, leetspeak, reversed text decoding and analysis |
| Unicode normalisation | `normalise.rs` | NFKC normalisation + 18 zero-width character stripping + 30+ homoglyph mappings |
| Ensemble combination | `ensemble.rs` | Regex + ML + NER + Fusion, agreement boost (+0.1 confidence) |

### 2.2 Output Security

| Capability | Module | Description |
|-----------|--------|-------------|
| Toxicity detection (ML) | `toxicity_detector.rs` | `unitary/toxic-bert` 6-category multi-label: toxic, severe_toxic, obscene, threat, insult, identity_hate |
| Toxicity detection (fallback) | `toxicity_detector.rs` | Keyword-based detection with category-specific keyword sets |
| Hallucination detection (ML) | `hallucination_detector.rs` | Cross-encoder model (`vectara/hallucination_evaluation_model`) sentence-level scoring |
| Hallucination detection (fallback) | `hallucination_detector.rs` | Word-overlap heuristic + hedging language detection + specificity penalty |
| Two-stage hallucination pipeline | `hallucination_detector.rs` | Sentinel check (word-overlap gating) → sentence-level cross-encoder scoring |
| Output PII scanning | `output_analyzer.rs` | Same regex + NER PII patterns applied to response content |
| Output secret scanning | `output_analyzer.rs` | Response content scanned for JWT, AWS keys, GitHub tokens, etc. |
| Data leakage detection | `lib.rs` | System prompt leak, credential leak patterns in responses |
| Code security analysis | `code_security.rs` | SQL injection, command injection, path traversal, hardcoded credentials, insecure deserialization, XSS, insecure crypto |
| Streaming output analysis | Proxy layer | Output-side PII, secrets, leakage, toxicity during SSE streaming |
| Early stopping | Proxy config | `early_stop_on_critical` flag for halting generation on critical findings |

### 2.3 Agent Security

| Capability | Module | Description |
|-----------|--------|-------------|
| Command execution analysis | `lib.rs` | Destructive commands, pipe-to-shell, base64+exec, sensitive system commands |
| Web access analysis | `lib.rs` | IP-based URLs, suspicious domains (.onion, pastebin, transfer.sh) |
| File access analysis | `lib.rs` | Sensitive paths (/etc/passwd, .ssh/, .aws/credentials, .env, id_rsa) |
| Tool call tracking | `core/lib.rs` | `AgentAction` types: ToolCall, SkillInvocation, CommandExecution, WebAccess, FileAccess |
| Action result capture | `core/lib.rs` | Truncated to 4KB, stored with span |

### 2.4 Infrastructure

| Capability | Module | Description |
|-----------|--------|-------------|
| Multi-tenant isolation | Proxy + Core | `TenantId`, per-tenant config, RBAC (Admin/Operator/Viewer) |
| Rate limiting | `rate_limit.rs` | Per-tenant token bucket with Redis backend |
| Cost control | `cost_caps.rs` | Per-agent budget caps (hourly/daily/weekly/monthly), token caps |
| Anomaly detection | `anomaly.rs` | Moving-average sliding window with sigma thresholds (cost, token, velocity, latency) |
| Circuit breaker | `circuit_breaker.rs` | Failure threshold → open → half-open → closed cycle |
| Alert engine | `alerts.rs` | Multi-channel (webhook, Slack, PagerDuty), escalation, cooldown |
| Compliance reporting | `compliance.rs` | SOC2, GDPR, HIPAA report generation |
| Storage backends | `llmtrace-storage` | SQLite, PostgreSQL, ClickHouse, Redis cache, in-memory |
| gRPC ingestion | `grpc.rs` | Protobuf-based trace ingestion gateway |
| OTLP ingestion | `otel.rs` | OpenTelemetry OTLP/HTTP trace ingestion |
| PII redaction | `lib.rs` | Three modes: AlertOnly, AlertAndRedact, RedactSilent |
| Graceful shutdown | `shutdown.rs` | Configurable drain timeout for Kubernetes |

---

## 3. Feature Gap Analysis

### 3.1 Input Security

#### 3.1.1 Over-Defense Mitigation

| ID | Feature | Paper(s) | Priority | Complexity | Status |
|----|---------|----------|----------|------------|--------|
| IS-001 | **MOF (Mitigating Over-defense for Free) training strategy** | InjecGuard | P0 | High | ❌ Missing |
| IS-002 | **Token-wise bias detection** — test every vocabulary token individually for false positive bias | InjecGuard | P0 | Medium | ❌ Missing |
| IS-003 | **Adaptive debiasing data generation** — generate benign samples using combinations of biased tokens | InjecGuard | P1 | Medium | ❌ Missing |
| IS-004 | **NotInject-style over-defense benchmark** — 339 benign samples with trigger words at 3 difficulty levels | InjecGuard, Benchmarks | P0 | Low | ✅ Implemented |
| IS-005 | **Three-dimensional evaluation** — separate benign/malicious/over-defense accuracy tracking | InjecGuard | P1 | Low | ✅ Implemented |
| IS-006 | **FPR-aware threshold optimisation** — evaluate at 0.1%, 0.5%, 1% FPR operating points | SoA Report (PromptShield) | P0 | Medium | ✅ Implemented |
| IS-007 | **Configurable operating points** — high-precision / balanced / high-recall modes | SoA Report | P1 | Low | ✅ Implemented |

**Implementation Notes:**
- IS-001: The MOF strategy involves: (1) standard training on curated dataset, (2) token-wise bias detection — feed each vocabulary token individually and identify those predicted as "attack", (3) generate 1000 benign samples using combinations of 1-3 biased tokens via LLM, (4) retrain from scratch on combined data. InjecGuard achieved 87.32% over-defense accuracy vs ProtectAIv2's 56.64% (+54.17% improvement).
- IS-006: PromptShield (Jacob et al., ACM CODASPY 2025) showed that at 0.1% FPR, Meta PromptGuard detects only 9.4% of attacks. PromptShield achieved 65.3% TPR at 0.1% FPR. CyberSecEval 2 (arXiv 2404.13161) also introduces a False Refusal Rate (FRR) methodology using borderline cybersecurity-related prompts; most models achieved <15% FRR while CodeLlama-70B showed 70% FRR. See `docs/research/cyberseceval2-llm-security-benchmark.md`.

#### 3.1.2 Advanced Prompt Injection Detection

| ID | Feature | Paper(s) | Priority | Complexity | Status |
|----|---------|----------|----------|------------|--------|
| IS-010 | **Synonym expansion for attack patterns** — WordNet-style synonym sets for each attack category | SoA Report (DMPI-PMHFE) | P2 | Medium | ⚠️ Partial |
| IS-011 | **Lemmatisation before pattern matching** — spaCy equivalent (rust-stemmers) | SoA Report (DMPI-PMHFE) | P2 | Low | ⚠️ Partial |
| IS-012 | **P2SQL injection detection** — LangChain middleware SQL injection via prompt | Protocol Exploits | P1 | Medium | ⚠️ Partial |
| IS-013 | **Long-context jailbreak detection** — attacks exploiting extended context windows | Protocol Exploits | P2 | High | ❌ Missing |
| IS-014 | **Automated jailbreak defense** — defense against AutoDAN, GPTFuzz achieving >90% ASR | Protocol Exploits | P1 | High | ❌ Missing |
| IS-015 | **Braille encoding evasion defense** — bypasses GPT-4o-based sanitizers | Indirect Injection Firewalls | P2 | Low | ✅ Implemented |
| IS-016 | **Multi-turn extraction detection** — gradual/multi-turn system prompt extraction across sessions | SoA Report, Design Patterns | P1 | High | ⚠️ Partial |
| IS-017 | **Context window flooding detection** — DoS via oversized context (OWASP LLM10) | SoA Report | P2 | Low | ✅ Implemented |
| IS-018 | **"Important Messages" header attack detection** — high ASR attack vector | Tool Result Parsing | P1 | Low | ⚠️ Partial |

**Implementation Notes:**
- IS-010: DMPI-PMHFE uses WordNet to expand synonym sets for each of 8 semantic-based attack categories (is_ignore, is_urgent, is_incentive, is_covert, is_format_manipulation, is_hypothetical, is_systemic, is_immoral) plus 2 structure-based pattern matching features (is_shot_attack, is_repeated_token) — 10 binary features total. Each synonym feature like "is_ignore" expands keywords (ignore, reveal, disregard, forget, overlook, regardless) via WordNet. Pattern features use regex with threshold of 3 (e.g. >=3 Q&A pairs for many-shot detection). Input is tokenized and lemmatized via spaCy en_core_web_sm. See `docs/research/dmpi-pmhfe-prompt-injection-detection.md` for full feature table and keyword lists.
- IS-012: The Protocol Exploits paper describes P2SQL injection where attackers exploit LangChain middleware to inject malicious SQL queries through natural language prompts.
- IS-014: GPTFuzz achieves >90% ASR via genetic algorithm mutation of jailbreak templates. Defense requires adversarial training on mutated attack samples.

#### 3.1.3 Adversarial Robustness

| ID | Feature | Paper(s) | Priority | Complexity | Status |
|----|---------|----------|----------|------------|--------|
| IS-020 | **Emoji smuggling defense** — 100% ASR evasion, no current defense | Bypassing Guardrails | P0 | Low | ✅ Implemented |
| IS-021 | **Upside-down text defense** — 100% jailbreak evasion | Bypassing Guardrails | P1 | Low | ✅ Implemented |
| IS-022 | **Unicode tag character stripping** — \u{E0001}-\u{E007F} range | Bypassing Guardrails | P1 | Low | ✅ Implemented |
| IS-023 | **Character smuggling variants** — comprehensive Unicode exploitation defense | Bypassing Guardrails | P1 | Medium | ⚠️ Partial |
| IS-024 | **AML evasion resistance** — TextFooler (46-48% ASR), BERT-Attack (57% ASR), BAE (52% ASR) | Bypassing Guardrails | P1 | High | ⚠️ Partial |
| IS-025 | **Ensemble diversification** — multiple model architectures to resist transferability attacks | Bypassing Guardrails | P1 | High | ⚠️ Partial |
| IS-026 | **Adversarial training integration** — fine-tune on TextAttack-generated samples | Bypassing Guardrails | P2 | High | ❌ Missing |
| IS-027 | **Adaptive thresholding** — lower threshold when evasion indicators detected | Bypassing Guardrails | P2 | Medium | ❌ Missing |
| IS-028 | **Multi-pass normalisation** — aggressive + conservative + semantic-preserving passes | Bypassing Guardrails | P2 | Medium | ⚠️ Partial |
| IS-029 | **Confidence calibration** — Platt scaling to reduce transferability | Bypassing Guardrails | P3 | Medium | ⚠️ Partial |
| IS-030 | **Word importance transferability mitigation** — prevent white-box model rankings from improving black-box attacks | Bypassing Guardrails | P3 | High | ❌ Missing |
| IS-031 | **Diacritics-based evasion defense** — accent marks used to evade detection | Bypassing Guardrails | P2 | Low | ✅ Implemented |
| IS-050 | **Perplexity-based anomaly detection** — detect GCG-optimized adversarial strings in tool outputs and agent traces by scoring token-sequence perplexity | Agent-as-a-Proxy | P0 | Medium | ❌ Missing |
| IS-051 | **Adaptive monitoring scope** — configurable input-only vs hybrid (input+output) monitoring to control attack surface exposure per threat model | Agent-as-a-Proxy | P1 | Medium | ❌ Missing |
| IS-052 | **Adversarial string propagation blocking** — detect and strip high-perplexity token sequences from tool outputs before they can be repeated by agents in subsequent traces | Agent-as-a-Proxy, Indirect Injection Firewalls | P0 | High | ❌ Missing |

**Implementation Notes:**
- IS-020: Emoji smuggling achieved 100% ASR on both prompt injection and jailbreaks across all tested systems. Implementation: add emoji stripping/normalization as pre-processing step. Use Unicode character category detection to filter emoji code points.
- IS-024: The Bypassing Guardrails paper specifically tested our ProtectAI DeBERTa model. TextFooler achieved 95.18% ASR, BERT-Attack 67.87% ASR on ProtectAI v1. Even v2 had 20.26% ASR. Defense requires ensemble diversification + adversarial training.
- IS-025: Replace single-model reliance with ensemble of different architectures. Candidates: Meta Prompt Guard 2 (86M), InjecGuard model, PIGuard model.
- IS-050: GCG-optimized adversarial strings have characteristically high perplexity (they are gibberish tokens optimized via gradient descent). A lightweight surprisal scorer on tool outputs can flag these before the agent processes them. The Agent-as-a-Proxy paper (arXiv 2602.05066) identifies this as a viable countermeasure but does not implement it. **Tiered implementation:** (1) MVP: statistical per-token surprisal using n-gram language model or byte-level entropy -- no GPU required, runs in Rust proxy, latency <5ms; (2) Follow-up: causal LM-based surprisal (e.g., GPT-2 117M quantized via Candle) for higher accuracy -- adds ~20-50ms latency, requires model loading infrastructure. **False positive considerations:** code snippets, base64-encoded content, and non-English text naturally have high surprisal; must whitelist known high-entropy patterns (base64 regex, code block markers, CJK/Arabic Unicode ranges) or use a two-stage approach (entropy pre-filter -> LM verification). IS-052 depends on IS-050's scoring output. This complements AS-002 (sanitization) -- surprisal detection catches what pattern-based sanitization misses.
- IS-051: The Agent-as-a-Proxy paper demonstrates a "hybrid monitoring paradox": observing more agent traces (tool calls, outputs) is stronger against static attacks but *increases* attack surface for adaptive attacks (more insertion sites for adversarial strings). LLMTrace should support configurable monitoring scope: input-only mode (lower attack surface, less coverage) vs full hybrid mode (higher coverage, larger attack surface). Default to hybrid for most deployments, but allow switching to input-only when facing known adaptive adversaries. **Config mechanism:** per-tenant YAML field `monitoring_scope: hybrid | input_only | output_only` in existing tenant config (hot-reloadable via existing config watch). Switching trigger: automated when IS-050 detects sustained high-perplexity anomalies in tool outputs (suggests active adaptive attack), or manual operator override.
- IS-052: The core mechanism of the Agent-as-a-Proxy attack is that the agent repeats adversarial strings from tool outputs into its reasoning traces, which then manipulate the monitor. Blocking this propagation at the tool-output boundary (AS-002 sanitization) is the structural defense the paper validates. IS-052 specifically targets high-perplexity sequences: strip or replace token sequences that exceed surprisal threshold before returning tool outputs to the agent. This breaks the attack chain at its source. **Dependency:** IS-052 depends on IS-050's surprisal scoring output; IS-050 must be implemented first. **Execution order with AS-002:** IS-052 (perplexity-based stripping) runs as the first stage of the tool-output sanitization pipeline, before AS-002 (pattern-based sanitization). This ensures GCG strings are removed before pattern matching, and AS-002 catches anything IS-052 misses. **False positive mitigation:** code, base64, non-English text, and compressed data naturally have high byte-level entropy. Mitigations: (1) whitelist content within recognized code fences, base64 blocks, and known non-Latin script ranges; (2) use sliding window (e.g., 20-token window matching GCG optimization length) rather than whole-content scoring; (3) require both high surprisal AND low semantic coherence (GCG strings are high-entropy AND semantically meaningless, unlike code which is high-entropy but parseable). Differs from AS-002 (which sanitizes all suspicious content) in that IS-052 specifically targets gradient-optimized strings.

#### 3.1.4 Data Format Coverage

| ID | Feature | Paper(s) | Priority | Complexity | Status |
|----|---------|----------|----------|------------|--------|
| IS-040 | **17 data format detection** — Email, Document, Chat, JSON, Code, Markdown, HTML, URL, Base64, Table, XML, CSV, Config File, Log File, Image Link, Translation, Website | InjecGuard | P2 | Medium | ❌ Missing |
| IS-041 | **Multi-language trigger detection** — Chinese, Russian, other languages | InjecGuard | P2 | High | ❌ Missing |

**Audit Notes (Literature Alignment):**
- Over-defense/MOF expectations and data-format augmentation: `docs/research/injecguard-over-defense-mitigation.md`.
- Synonym/lemmatization expectations for IS-010/IS-011: `docs/research/dmpi-pmhfe-prompt-injection-detection.md`.
- DMPI-PMHFE architectural deviations (DMPI-001–DMPI-006) tracked in section 3.4.1. These are prerequisites for IS-010/IS-011 full compliance and for ML-001 training.
- Protocol exploit items (P2SQL, long-context, multi-turn extraction): `docs/research/prompt-injections-to-protocol-exploits.md`.
- Adversarial evasion and transferability requirements (IS-020–IS-031): `docs/research/bypassing-llm-guardrails-evasion.md`.
- Agent-as-a-Proxy defense requirements (IS-050–IS-052): `docs/research/agent-as-a-proxy-attacks.md`. Monitoring-based defenses are fundamentally fragile (90%+ ASR). IS-050 (perplexity detection) and IS-052 (propagation blocking) counter GCG-optimized strings. IS-051 (adaptive monitoring scope) addresses the hybrid monitoring paradox.

---

### 3.2 Output Security

#### 3.2.1 Advanced Hallucination Detection

| ID | Feature | Paper(s) | Priority | Complexity | Status |
|----|---------|----------|----------|------------|--------|
| OS-001 | **HaluGate-style token-level detection** — ModernBERT token classification identifying exactly which tokens are unsupported | SoA Report (HaluGate) | P1 | High | ❌ Missing |
| OS-002 | **NLI explanation layer** — classify flagged spans as CONTRADICTION, NEUTRAL, or ENTAILMENT | SoA Report (HaluGate) | P2 | High | ❌ Missing |
| OS-003 | **Sentinel pre-classifier** — ModernBERT classifier to determine if query needs fact-checking (96.4% accuracy, 12ms) | SoA Report (HaluGate) | P1 | Medium | ❌ Missing |
| OS-004 | **Tool-call result as ground truth** — use tool results visible in proxy traffic for fact-checking | SoA Report (HaluGate) | P1 | Medium | ❌ Missing |
| OS-005 | **Semantic entropy-based detection** — multi-sample uncertainty estimation | SoA Report (Nature 2024) | P3 | High | ❌ Missing |
| OS-006 | **Citation validation** — verify cited sources exist and support claims | SoA Report | P3 | High | ❌ Missing |

**Implementation Notes:**
- OS-001: HaluGate achieves 76-162ms latency (CPU) vs 2-5 seconds for LLM-as-judge. As a proxy, LLMTrace is perfectly positioned since we see both tool-call results and LLM responses.
- OS-003: Current sentinel uses word-overlap heuristic capped at 0.85. HaluGate uses ModernBERT-based sentinel with 96.4% accuracy at 12ms. Requires porting ModernBERT to Candle.

#### 3.2.2 Streaming Output Safety

| ID | Feature | Paper(s) | Priority | Complexity | Status |
|----|---------|----------|----------|------------|--------|
| OS-010 | **Streaming Content Monitor (SCM)** — purpose-built partial-sequence detection models | SoA Report (SCM, Li et al.) | P2 | High | ❌ Missing |
| OS-011 | **Training-inference gap mitigation** — train detectors on partial text sequences, not just complete text | SoA Report (SCM) | P2 | High | ❌ Missing |
| OS-012 | **Token-level harm annotations** — fine-grained labels for which tokens contribute to harm | SoA Report (SCM) | P3 | High | ❌ Missing |
| OS-013 | **Progressive confidence scoring** — confidence increases as more tokens arrive during streaming | SoA Report | P2 | Medium | ❌ Missing |

**Implementation Notes:**
- OS-010: SCM achieves 95%+ macro F1 by seeing only first 18% of tokens. Uses hierarchical consistency-aware learning for incomplete-sequence judgment. Our current streaming analysis re-runs full-text detectors on accumulated content — this is less efficient and less accurate than purpose-built streaming models.

#### 3.2.3 Content Safety

| ID | Feature | Paper(s) | Priority | Complexity | Status |
|----|---------|----------|----------|------------|--------|
| OS-020 | **Constitutional classifiers** — rules-defined safety classifiers for output moderation | SoA Report (Anthropic 2025) | P2 | High | ❌ Missing |
| OS-021 | **Bias detection** — detect biased or discriminatory content in responses | SoA Report | P2 | Medium | ❌ Missing |
| OS-022 | **Llama Guard 3 integration** — multi-label safety classifier covering 14 harm categories | SoA Report, Benchmarks | P1 | Medium | ❌ Missing |
| OS-023 | **Sentiment analysis** — detect negative or manipulative sentiment in outputs | Benchmarks (LLM Guard) | P3 | Low | ❌ Missing |
| OS-024 | **Language detection** — identify unexpected language switches (potential attack vector) | Benchmarks (LLM Guard) | P3 | Low | ❌ Missing |

#### 3.2.4 Code Security Enhancement

| ID | Feature | Paper(s) | Priority | Complexity | Status |
|----|---------|----------|----------|------------|--------|
| OS-030 | **CodeShield-style analysis** — Meta LlamaFirewall's code security component | SoA Report (LlamaFirewall) | P1 | Large | ⚠️ Partial |
| OS-031 | **Semgrep rule integration** — leverage existing Semgrep rule database | SoA Report | P2 | Medium | ❌ Missing |
| OS-032 | **Supply chain security** — detect dependency confusion, typosquatting in code | SoA Report (OWASP LLM03) | P3 | High | ❌ Missing |

**Audit Notes (Literature Alignment):**
- HaluGate-style token-level pipeline (OS-001–OS-004) and sentinel expectations: `docs/research/security-state-of-art-2026.md`.
- Streaming Content Monitor expectations (OS-010–OS-013): `docs/research/security-state-of-art-2026.md`.
- Content safety expectations (Llama Guard, bias, sentiment/language detection): `docs/research/security-state-of-art-2026.md`.
- CodeShield-level analysis requirements: `docs/research/security-state-of-art-2026.md`.

---

### 3.3 Agent Security

#### 3.3.1 Tool-Boundary Firewalling

| ID | Feature | Paper(s) | Priority | Complexity | Status |
|----|---------|----------|----------|------------|--------|
| AS-001 | **Tool-Input Firewall (Minimizer)** — filter sensitive info from tool call arguments before execution | Indirect Injection Firewalls | P0 | High | ⚠️ Partial |
| AS-002 | **Tool-Output Firewall (Sanitizer)** — remove malicious content from tool responses before returning to agent | Indirect Injection Firewalls | P0 | High | ⚠️ Partial |
| AS-003 | **Tool context awareness** — use user task + tool description for security decisions | Indirect Injection Firewalls, Tool Result Parsing | P1 | Medium | ⚠️ Partial |
| AS-004 | **Tool result parsing** — extract only essential data from tool results, discard excess content | Tool Result Parsing | P1 | High | ⚠️ Partial |
| AS-005 | **Format constraint validation** — enforce strict format/logic rules on tool outputs | Tool Result Parsing | P1 | Medium | ⚠️ Partial |
| AS-006 | **ParseData module** — LLM-based extraction of minimal required data from tool results | Tool Result Parsing | P2 | High | ⚠️ Partial |
| AS-007 | **CheckTool module** — detect if tool output content triggers unexpected tool calls | Tool Result Parsing | P2 | Medium | ⚠️ Partial |
| AS-008 | **Tool registry and classification** — categorise tools by security level and requirements | Indirect Injection Firewalls, Design Patterns | P1 | Medium | ✅ Implemented |

**Implementation Notes:**
- AS-001/AS-002: The "minimize & sanitize" approach achieves **0% ASR** across all benchmarks (AgentDojo, ASB, InjecAgent, Tau-Bench) with minimal utility degradation. Sanitizer alone achieves optimal security-utility tradeoff. BIPIA confirms boundary awareness is the critical defense: removing `<data>`/`</data>` tokens increases ASR by 1064% (see `docs/research/bipia-indirect-prompt-injection-benchmark.md`).
- AS-004: Tool Result Parsing achieves 10x lower ASR (0.19%) than DeBERTa classification (1.19%) and 51.84% utility vs 34.08% for DeBERTa. Key insight: "What data do I actually need?" > "Is this malicious?"
- AS-008: Define `ToolDefinition` with category (WebBrowsing, CodeExecution, FileSystem, Database, Communication, DataProcessing), risk score, permission requirements.

#### 3.3.2 Design Pattern Enforcement

| ID | Feature | Paper(s) | Priority | Complexity | Status |
|----|---------|----------|----------|------------|--------|
| AS-010 | **Action-Selector pattern enforcement** — enforce action allowlists at proxy level | Design Patterns | P1 | Medium | ✅ Implemented |
| AS-011 | **Plan-Then-Execute pattern detection** — detect plan deviations in request patterns | Design Patterns | P2 | High | ❌ Missing |
| AS-012 | **Context-Minimization** — strip unnecessary context from requests to reduce attack surface | Design Patterns | P1 | Medium | ✅ Implemented |
| AS-013 | **Dual LLM routing** — route trusted/untrusted data to different model endpoints | Design Patterns | P2 | High | ❌ Missing |
| AS-014 | **Pattern compliance monitoring** — detect when agents violate declared security patterns | Design Patterns | P2 | High | ❌ Missing |
| AS-015 | **Action-type rate limiting** — rate limit by action type, not just request volume | Design Patterns | P1 | Low | ✅ Implemented |
| AS-016 | **Trust-based routing** — classify data sources by trust level and route accordingly | Design Patterns | P2 | High | ❌ Missing |

**Implementation Notes:**
- AS-010: The Design Patterns paper presents 6 provable patterns. Action-Selector is most applicable to proxy layer: enforce that agents can only select from predefined action sets. Implementation: action allowlist in config, reject requests with unlisted tool calls.
- AS-012: Context-Minimization removes user prompt from context after action determination. At proxy level: strip context fields from forwarded requests when tool boundary detected.

#### 3.3.3 Multi-Agent Defense

| ID | Feature | Paper(s) | Priority | Complexity | Status |
|----|---------|----------|----------|------------|--------|
| AS-020 | **Coordinator agent** — pre-input classification and threat assessment before forwarding | Multi-Agent Defense | P1 | High | ⚠️ Partial |
| AS-021 | **Guard agent** — post-generation validation and output sanitization | Multi-Agent Defense | P1 | High | ⚠️ Partial |
| AS-022 | **Hierarchical coordinator pipeline** — route safe queries directly, detected threats to safe refusal | Multi-Agent Defense | P2 | High | ❌ Missing |
| AS-023 | **Second opinion pass for borderline cases** — multi-model consensus for uncertain scores | Multi-Agent Defense | P1 | Medium | ⚠️ Partial |
| AS-024 | **Policy store** — centralised security rules accessed by all agents/modules | Multi-Agent Defense, Design Patterns | P1 | Medium | ⚠️ Partial |
| AS-025 | **Multi-step action correlation** — detect multi-step attack sequences across requests | Multi-Agent Defense, SoA Report | P2 | High | ✅ Implemented |
| AS-026 | **Multi-turn persistence detection** — gradual bypass attempts across conversation turns | Multi-Agent Defense, Protocol Exploits | P1 | High | ✅ Implemented |

**Implementation Notes:**
- AS-020/AS-021: Multi-Agent Defense paper achieved **0% ASR** across 400 attack instances (vs 20-30% baseline). Architecture: Coordinator → [safe refusal | Domain LLM + Guard]. For LLMTrace: implement as optional multi-pass security engine within existing proxy.
- AS-023: When primary analysis yields score 0.6-0.8 (borderline), invoke specialist models for consensus. Target <200ms additional latency.

#### 3.3.4 Protocol Security

| ID | Feature | Paper(s) | Priority | Complexity | Status |
|----|---------|----------|----------|------------|--------|
| AS-030 | **MCP (Model Context Protocol) monitoring** — detect MCP manipulation and server-side attacks | Protocol Exploits | P0 | High | ✅ Implemented |
| AS-031 | **A2A (Agent-to-Agent) protocol security** — communication interception and manipulation detection | Protocol Exploits | P1 | High | ❌ Missing |
| AS-032 | **ANP (Agent Network Protocol) security** — peer-to-peer agent collaboration vulnerabilities | Protocol Exploits | P2 | High | ❌ Missing |
| AS-033 | **Dynamic trust management** — cryptographic provenance tracking for MCP deployments | Protocol Exploits | P2 | High | ❌ Missing |
| AS-034 | **Inter-agent trust verification** — validate agent identity and permissions | Protocol Exploits | P2 | High | ❌ Missing |
| AS-035 | **Toxic Agent Flow defense** — GitHub MCP server vulnerability enabling private data leakage | Protocol Exploits | P1 | Medium | ⚠️ Partial |
| AS-036 | **ToolHijacker defense** — tool selection manipulation in LLM agents (96.7% ASR against GPT-4o) | SoA Report (ToolHijacker) | P1 | High | ⚠️ Partial |

**Implementation Notes:**
- AS-030: The Protocol Exploits paper is the first to catalogue MCP/A2A/ANP vulnerabilities. MCP allows arbitrary tool server registration — need to validate server identity, monitor for suspicious tool registration patterns, and detect data exfiltration via MCP channels.
- AS-035: Toxic Agent Flow via GitHub MCP server enables private repo data leakage. Detection: monitor for MCP tool calls accessing private data sources and validate against user permissions.
- AS-036: ToolHijacker achieves 96.7% ASR against GPT-4o with 99.6% bypass of StruQ/SecAlign defenses. Defense requires tool-call validation beyond simple pattern matching.

**Audit Notes (Literature Alignment):**
- Tool-boundary firewalling and LLM-based tool parsing expectations: `docs/research/indirect-injection-firewalls.md` and `docs/research/defense-tool-result-parsing.md`.
- Design pattern enforcement expectations (Action-Selector, Plan-then-Execute, Context-Minimization): `docs/research/design-patterns-securing-agents.md`.
- Multi-agent coordination expectations (Coordinator + Guard + second opinion): `docs/research/multi-agent-defense-pipeline.md`.
- Protocol exploit expectations (MCP/A2A/ANP, ToolHijacker, Toxic Agent Flow): `docs/research/prompt-injections-to-protocol-exploits.md`.

---

### 3.4 ML Pipeline & Architecture

#### 3.4.1 Model Architecture

| ID | Feature | Paper(s) | Priority | Complexity | Status |
|----|---------|----------|----------|------------|--------|
| ML-001 | **Joint end-to-end training** — train fusion FC layer jointly with labelled data (blocked by DMPI-001–DMPI-006) | SoA Report (DMPI-PMHFE) | P1 | High | ❌ Missing |
| ML-002 | **InjecGuard model integration** — evaluate and integrate InjecGuard as alternative/ensemble member | InjecGuard, Benchmarks | P1 | Medium | ✅ Implemented |
| ML-003 | **Meta Prompt Guard 2 integration** — 86M and 22M variants as ensemble members | SoA Report, Benchmarks | P1 | Medium | ✅ Implemented |
| ML-004 | **PIGuard model integration** — DeBERTa + MOF training for reduced over-defense | SoA Report (PIGuard) | P1 | Medium | ❌ Missing |
| ML-005 | **ModernBERT support** — port ModernBERT to Candle for sentinel/token-level detection | SoA Report (HaluGate) | P2 | High | ❌ Missing |
| ML-006 | **Multi-model ensemble voting** — diverse architectures for robustness against AML | Bypassing Guardrails | P1 | Medium | ⚠️ Partial |
| ML-007 | **Model hot-swapping** — swap models without proxy restart | Design Patterns | P3 | Medium | ❌ Missing |

#### 3.4.1a DMPI-PMHFE Architecture Alignment (Prerequisites for ML-001)

6 architectural deviations between the current codebase and the DMPI-PMHFE paper (arXiv 2506.06384). 5 resolved (DMPI-001, DMPI-002, DMPI-003, DMPI-004, DMPI-005), 1 remaining (DMPI-006). All must be resolved before fusion training (ML-001) can produce paper-comparable results. Reference: `docs/research/dmpi-pmhfe-prompt-injection-detection.md`.

| ID | Feature | Paper(s) | Priority | Complexity | Status |
|----|---------|----------|----------|------------|--------|
| DMPI-001 | **Average pooling instead of CLS token** — Implemented `masked_mean_pool()` with `PoolingStrategy` enum (Cls/MeanPool). Both BERT and DeBERTa paths now default to attention-mask-aware average pooling. See `docs/architecture/DMPI_001_AVERAGE_POOLING.md`. | DMPI-PMHFE | P1 | Medium | :white_check_mark: Done |
| DMPI-002 | **2 FC layers instead of 3** — Removed `HIDDEN_2` and `fc3`; collapsed to `fc1(783->256)->ReLU->fc2(256->2)->SoftMax` matching paper spec. Input dim becomes 778 (768+10) once DMPI-003 is also applied. Architecture doc: `docs/architecture/DMPI_002_TWO_FC_LAYERS.md`. | DMPI-PMHFE | P1 | Medium | :white_check_mark: Done |
| DMPI-003 | **10 binary features instead of 15 mixed** — Replaced 15-dim vector (8 binary + 7 numeric) with 10 binary features matching paper Appendix A. Removed all numeric features. Added keyword-based detection for `is_ignore`, `is_format_manipulation`, `is_immoral`. Reordered to paper spec. `FUSION_INPUT_DIM` now 778 (768+10). Architecture doc: `docs/architecture/DMPI_003_TEN_BINARY_FEATURES.md`. | DMPI-PMHFE | P1 | High | :white_check_mark: Done |
| DMPI-004 | **Repetition threshold >=3 instead of >10** — Named constant `REPETITION_THRESHOLD = 3`. Word-level and phrase-level conditions changed to `>= REPETITION_THRESHOLD`. Expanded `COMMON_WORDS` list (+37 words) and added `COMMON_PHRASES` exclusion list (29 common English bigrams) to control false positives at the lower threshold. | DMPI-PMHFE | P1 | Low | :white_check_mark: Done |
| DMPI-005 | **Missing paper features: is_immoral, is_ignore, is_format_manipulation** — All 3 missing features now implemented as keyword-in-text checks in `feature_extraction.rs`. Resolved as part of DMPI-003. Architecture doc: `docs/architecture/DMPI_003_TEN_BINARY_FEATURES.md`. | DMPI-PMHFE | P1 | Medium | :white_check_mark: Done |
| DMPI-006 | **Feature naming alignment to paper convention** — `feature_extraction.rs:41-50` uses code-specific names (`flattery_attack`, `urgency_attack`, etc.). Paper uses `is_ignore`, `is_urgent`, `is_incentive`, `is_covert`, `is_format_manipulation`, `is_hypothetical`, `is_systemic`, `is_immoral`, `is_shot_attack`, `is_repeated_token`. Zero paper `is_*` names exist in codebase. Rename mapping: `flattery->is_incentive`, `urgency->is_urgent`, `roleplay->is_hypothetical`, `impersonation->is_systemic`, `covert->is_covert`, `excuse->is_immoral`, `many_shot->is_shot_attack`, `repetition->is_repeated_token`. | DMPI-PMHFE | P2 | Low | ❌ Missing |

**Implementation Notes:**
- ML-001: Current FusionClassifier uses random weights (`new_random`). Need training pipeline: (1) collect labeled prompt injection dataset, (2) extract DeBERTa embeddings via average pooling, (3) extract 10 binary heuristic features per paper spec, (4) concatenate and train 2-layer FC classifier. DMPI-PMHFE shows +6% F1 on hard datasets (deepset-v2: 84.21% -> 90.21%) with trained fusion. **Blocked by DMPI-006:** training on the wrong architecture will not reproduce paper results.
- ML-002: InjecGuard surpasses ProtectAIv2 by 30.8% on over-defense benchmark. Same DeBERTa architecture, different training strategy.
- DMPI-001 and DMPI-002 are independent and can be done in parallel.
- DMPI-003 and DMPI-005 are coupled: fixing feature dimension requires adding the 3 missing paper features and removing the 7 extra numeric features.
- DMPI-006 (naming) should be done last since it touches all downstream finding types and serialization.

#### 3.4.2 Training Strategies

| ID | Feature | Paper(s) | Priority | Complexity | Status |
|----|---------|----------|----------|------------|--------|
| ML-010 | **MOF training pipeline** — token-wise bias detection → adaptive data generation → retraining | InjecGuard | P0 | High | ❌ Missing |
| ML-011 | **Data-centric augmentation** — generate training samples across 17 formats | InjecGuard | P2 | Medium | ❌ Missing |
| ML-012 | **Adversarial training** — fine-tune on TextAttack-generated adversarial examples | Bypassing Guardrails | P1 | High | ❌ Missing |
| ML-013 | **Robust training with character injection variants** — train on Unicode evasion samples | Bypassing Guardrails | P2 | Medium | ❌ Missing |
| ML-014 | **Curated training dataset** — balanced dataset (InjecGuard: 61,089 benign + 15,666 injection) | InjecGuard | P1 | Medium | ❌ Missing |
| ML-015 | **GradSafe integration** — safety-critical gradient analysis for enhanced detection | Benchmarks | P3 | High | ❌ Missing |
| ML-016 | **GCG adversarial sample generation** — generate adversarial training samples using Greedy Coordinate Gradient to improve classifier resilience against gradient-optimized attacks | Agent-as-a-Proxy, Bypassing Guardrails | P1 | High | ❌ Missing |

#### 3.4.3 Inference Optimisation

| ID | Feature | Paper(s) | Priority | Complexity | Status |
|----|---------|----------|----------|------------|--------|
| ML-020 | **ONNX runtime support** — ONNX-optimised inference for production | Benchmarks (LLM Guard) | P2 | Medium | ❌ Missing |
| ML-021 | **Quantised model support** — INT8/INT4 quantisation for faster inference | SoA Report | P3 | Medium | ❌ Missing |
| ML-022 | **Batched inference** — batch multiple requests for GPU utilisation | SoA Report | P3 | Medium | ❌ Missing |

**Audit Notes (Literature Alignment):**
- InjecGuard MOF training and over-defense mitigation expectations: `docs/research/injecguard-over-defense-mitigation.md`.
- Ensemble diversification expectations and robustness claims: `docs/research/bypassing-llm-guardrails-evasion.md`.
- HaluGate/ModernBERT support expectations: `docs/research/security-state-of-art-2026.md`.
- ML-016: GCG adversarial samples complement ML-012 (TextAttack-based). GCG is more powerful (gradient-optimized vs heuristic perturbation) but requires white-box access to the detection model. The Agent-as-a-Proxy paper shows GCG achieves 90%+ ASR where TextAttack achieves 46-48%. Training on GCG samples provides robustness against the strongest known attack class. **Tooling dependency:** GCG optimization requires Python + PyTorch + `transformers` for gradient computation against the detection model. This is offline tooling (not in the Rust proxy runtime) -- lives in a `tools/gcg/` or `scripts/adversarial/` directory. Shared with EV-017 (red-team testing uses the same GCG pipeline to generate test samples). Parameters from paper: 20 initial tokens, 500 GCG steps, 512 candidates/iteration, top-k=256. See `docs/research/agent-as-a-proxy-attacks.md`.

---

### 3.5 Multimodal Security

| ID | Feature | Paper(s) | Priority | Complexity | Status |
|----|---------|----------|----------|------------|--------|
| MM-001 | **Image injection detection** — adversarial perturbations in images (LLaVA, PandaGPT attacks) | Protocol Exploits | P1 | High | ❌ Missing |
| MM-002 | **Audio injection detection** — hidden commands in audio inputs | Protocol Exploits | P2 | High | ❌ Missing |
| MM-003 | **Cross-modal consistency checks** — verify text and media inputs are consistent | Protocol Exploits | P2 | High | ❌ Missing |
| MM-004 | **OCR-based text extraction from images** — detect text-based injections embedded in images | Protocol Exploits | P1 | Medium | ❌ Missing |
| MM-005 | **Steganography detection** — detect hidden messages in images/audio | Protocol Exploits | P3 | High | ❌ Missing |
| MM-006 | **Video frame injection detection** — malicious frames in video inputs | Protocol Exploits | P3 | High | ❌ Missing |

**Implementation Notes:**
- MM-001: The Protocol Exploits survey documents adversarial perturbation attacks on multimodal models (LLaVA, PandaGPT). As a proxy, LLMTrace can intercept image/audio payloads in API requests and run secondary analysis. Initial approach: OCR on images → text analysis pipeline.
- MM-004: Most practical first step — extract text from images using OCR, then apply existing text-based injection detection. Many "visual injection" attacks embed readable text in images.

**Audit Notes (Literature Alignment):**
- Multimodal attack expectations (image/audio/stego/video): `docs/research/prompt-injections-to-protocol-exploits.md`.

---

### 3.6 Privacy

| ID | Feature | Paper(s) | Priority | Complexity | Status |
|----|---------|----------|----------|------------|--------|
| PR-001 | **Membership inference defense** — S2MIA protection for RAG databases | Protocol Exploits | P2 | High | ❌ Missing |
| PR-002 | **Data extraction prevention** — prevent model training data extraction via carefully crafted queries | Protocol Exploits | P2 | High | ❌ Missing |
| PR-003 | **Federated learning poisoning defense** — detection of local model manipulation | Protocol Exploits | P3 | High | ❌ Missing |
| PR-004 | **Vector/embedding poisoning detection** — OWASP LLM08 coverage | SoA Report | P2 | High | ❌ Missing |
| PR-005 | **RAG retrieval anomaly monitoring** — detect unusual similarity scores and retrieval patterns | SoA Report | P2 | Medium | ❌ Missing |
| PR-006 | **Multi-language PII detection** — CJK, Arabic, and other non-Latin scripts | SoA Report, InjecGuard | P2 | High | ⚠️ Partial |
| PR-007 | **Context-aware PII enhancement** — lemma-based context boosting (Presidio-style) | SoA Report | P2 | Medium | ⚠️ Partial |
| PR-008 | **Custom entity type plugins** — architecture for user-defined PII patterns | SoA Report (Presidio) | P2 | Medium | ❌ Missing |
| PR-009 | **Compliance mapping** — automatic GDPR/HIPAA/CCPA entity classification | SoA Report (IBM OneShield) | P2 | Medium | ⚠️ Partial |
| PR-010 | **Memory poisoning detection** — MINJA-style memory injection in agent memory banks | Protocol Exploits | P2 | High | ❌ Missing |
| PR-011 | **Cross-session state integrity** — detect persistent state manipulation | Protocol Exploits | P2 | High | ❌ Missing |
| PR-012 | **Speculative side-channel defense** — network packet timing attack protection | Protocol Exploits | P3 | High | ❌ Missing |

**Implementation Notes:**
- PR-001: S2MIA (Semantic Similarity Membership Inference Attack) exploits RAG databases. Defense: add noise to similarity scores, monitor for systematic probing patterns.
- PR-010: MINJA injects malicious records into agent memory banks. As a proxy, LLMTrace can monitor for memory/context injection patterns across sessions.

**Audit Notes (Literature Alignment):**
- Privacy and protocol exploit expectations (membership inference, poisoning, MINJA): `docs/research/prompt-injections-to-protocol-exploits.md`.
- PII expansion and compliance mapping expectations: `docs/research/security-state-of-art-2026.md`.

---

### 3.7 Evaluation & Benchmarking

| ID | Feature | Paper(s) | Priority | Complexity | Status |
|----|---------|----------|----------|------------|--------|
| EV-001 | **AgentDojo evaluation** — 97 environments testing tool misuse, injection resilience | Benchmarks | P0 | Medium | ❌ Missing |
| EV-002 | **NotInject evaluation** — 339 benign samples with trigger words (3 difficulty levels) | InjecGuard, Benchmarks | P0 | Low | ✅ Implemented |
| EV-003 | **InjecAgent evaluation** — indirect injection in agents, 8 defense mechanisms | Benchmarks | P1 | Medium | ❌ Missing |
| EV-004 | **Agent Security Bench (ASB) evaluation** — comprehensive multi-domain agent security | Benchmarks | P2 | Medium | ❌ Missing |
| EV-005 | **WASP evaluation** — web agent security benchmark | Benchmarks | P2 | Medium | ❌ Missing |
| EV-006 | **CyberSecEval 2 evaluation** — 251 prompt injection attack samples (per DMPI-PMHFE [28]); full paper also covers code interpreter abuse (500 prompts), exploit generation, and FRR | SoA Report, CyberSecEval 2 Breakdown | P2 | Low | ❌ Missing |
| EV-007 | **MLCommons AILuminate Jailbreak Benchmark** — industry-standard jailbreak evaluation | SoA Report | P2 | Medium | ❌ Missing |
| EV-008 | **HPI_ATTACK_DATASET evaluation** — 55 unique attacks, 8 categories, 400 instances | Multi-Agent Defense | P1 | Low | ❌ Missing |
| EV-009 | **Automated benchmark runner** — CI-integrated evaluation pipeline | All papers | P1 | Medium | ❌ Missing |
| EV-010 | **Paper-table output format** — results formatted for academic paper tables | All papers | P2 | Low | ✅ Implemented |
| EV-011 | **safeguard-v2 evaluation** — 1,300 test samples from DMPI-PMHFE | SoA Report | P1 | Low | ❌ Missing |
| EV-012 | **deepset-v2 evaluation** — 354 challenging external validation samples | SoA Report (DMPI-PMHFE) | P1 | Low | ❌ Missing |
| EV-013 | **Ivanleomk-v2 evaluation** — 610 external validation samples from `ivanleomk/prompt_injection_password` | SoA Report (DMPI-PMHFE) | P1 | Low | ❌ Missing |
| EV-014 | **BIPIA evaluation** — indirect prompt injection benchmark: 86,250 test prompts across 5 scenarios (email QA, web QA, table QA, summarization, code QA), 50 attack types (30 text + 20 code). 25-model ASR baseline available. | BIPIA Breakdown, Benchmarks, Indirect Injection Firewalls | P1 | Medium | ❌ Missing |
| EV-015 | **HarmBench evaluation** — standardized jailbreak/safety ASR measurement across violence, illegal activity, hate speech categories | Benchmarks, Bypassing Guardrails, SoA Report | P1 | Medium | ❌ Missing |
| EV-016 | **AgentDojo Slack suite adaptive attack evaluation** — Agent-as-a-Proxy attack resilience on Slack suite (89 samples after filtering). Measure detection rate for both static and GCG-optimized adaptive attacks. | Agent-as-a-Proxy, Benchmarks | P0 | High | ❌ Missing |
| EV-017 | **Multi-objective GCG adversarial robustness testing** — generate adversarial strings optimized to simultaneously bypass LLMTrace's regex + ML ensemble using multi-objective GCG. Red-team evaluation. | Agent-as-a-Proxy | P1 | High | ❌ Missing |
| EV-018 | **Cross-model transfer attack resistance** — test whether adversarial strings optimized against one detection model (e.g., DeBERTa) transfer to bypass LLMTrace's full ensemble. Evaluate ensemble diversity as transfer resistance. | Agent-as-a-Proxy, Bypassing Guardrails | P1 | Medium | ❌ Missing |

**Audit Notes (Literature Alignment):**
- Benchmark suite expectations (AgentDojo, ASB, InjecAgent, WASP, etc.): `docs/research/benchmarks-and-tools-landscape.md`.
- WASP benchmark specifics: `docs/research/wasp-web-agent-security-benchmark.md`.
- CyberSecEval 2 benchmark details (EV-006): `docs/research/cyberseceval2-llm-security-benchmark.md`. The 251 prompt injection sample count is cross-referenced from DMPI-PMHFE (arXiv 2506.06384, Table reference [28]). The paper also introduces FRR methodology relevant to IS-006/IS-007.
- BIPIA benchmark (EV-014): `docs/research/bipia-indirect-prompt-injection-benchmark.md`. First systematic indirect prompt injection benchmark (KDD 2025, arXiv 2312.14197). 86,250 test prompts, 50 attack types, 25-model vulnerability baseline (GPT-4: 31% ASR, average: 11.8%). Proposes boundary token injection (`<data>`/`</data>`) and explicit reminder injection as proxy-level defenses relevant to AS-001/AS-002. Key finding: more capable models are more vulnerable (r=0.6423). Also cited in `benchmarks-and-tools-landscape.md`, `injecguard-over-defense-mitigation.md`, `indirect-injection-firewalls.md`.
- HarmBench benchmark (EV-015): cited in 3 research docs (`benchmarks-and-tools-landscape.md`, `bypassing-llm-guardrails-evasion.md`, `security-state-of-art-2026.md`). Foundational jailbreak/safety benchmark that newer benchmarks build upon. Measures ASR across harmful content categories.
- Agent-as-a-Proxy attacks (EV-016, EV-017, EV-018): `docs/research/agent-as-a-proxy-attacks.md`. Demonstrates monitoring-based defenses (including proxy-level monitoring like LLMTrace) are fundamentally fragile: 90%+ ASR via GCG-optimized adversarial strings that agents repeat in their traces. Validates structural defenses (AS-001/AS-002 sanitization, BIPIA boundary tokens) over pure monitoring. High-perplexity string detection identified as viable countermeasure. **Dependencies:** EV-016 shares AgentDojo infrastructure with EV-001 (both use AgentDojo benchmark; EV-001 covers 97 environments, EV-016 focuses on Slack suite 89 samples with adaptive attacks). EV-017 depends on ML-016 (shared GCG Python/PyTorch tooling for adversarial string generation). EV-018 depends on ML-006 (ensemble must be wired before transfer testing). All three require Python/PyTorch offline tooling, not Rust proxy changes.

---

### 3.8 System & Architecture Gaps

| ID | Feature | Paper(s) | Priority | Complexity | Status |
|----|---------|----------|----------|------------|--------|
| SA-001 | **Policy/rules language** — declarative policy specification (Colang-like or OPA-style) | SoA Report (NeMo, OneShield) | P2 | High | ❌ Missing |
| SA-002 | **Canary token system** — inject canary tokens in prompts, detect leakage in responses | Benchmarks (tldrsec) | P1 | Low | ✅ Implemented |
| SA-003 | **Taint tracking** — track untrusted data flow through LLM pipeline | Benchmarks (tldrsec), Design Patterns | P2 | High | ❌ Missing |
| SA-004 | **Blast radius reduction** — least-privilege enforcement for LLM tool access | Benchmarks (tldrsec), Design Patterns | P2 | Medium | ❌ Missing |
| SA-005 | **Backdoor detection** — prompt-level and parameter-level backdoor detection (BadPrompt, DemonAgent) | Protocol Exploits | P2 | High | ❌ Missing |
| SA-006 | **Composite backdoor detection** — CBA-style distributed trigger patterns across prompt components | Protocol Exploits | P3 | High | ❌ Missing |
| SA-007 | **Data poisoning detection** — PoisonedRAG knowledge corruption patterns | Protocol Exploits | P2 | High | ❌ Missing |
| SA-008 | **Social engineering simulation defense** — SE-VSim-style human manipulation tactic detection | Protocol Exploits | P3 | High | ❌ Missing |
| SA-009 | **Contagious recursive blocking defense** — Corba attacks on multi-agent systems | Protocol Exploits | P3 | High | ❌ Missing |
| SA-010 | **GuardReasoner integration** — reasoning-based safeguards with explanation | Benchmarks | P3 | High | ❌ Missing |

**Audit Notes (Literature Alignment):**
- Policy language and orchestration expectations: `docs/research/llmtrace-defense-pipeline-design.md`.
- Backdoor/poisoning and protocol exploit expectations: `docs/research/prompt-injections-to-protocol-exploits.md`.

---

## 4. Implementation Roadmap

### Phase 1: Critical / Quick Wins (Weeks 1-6)

Focus: Close critical security gaps and establish evaluation baseline.

| Week | Feature IDs | Description | Effort |
|------|------------|-------------|--------|
| 1-2 | IS-020, IS-021, IS-022 | **Emoji normalisation**, upside-down text mapping, Unicode tag stripping | Small |
| 1-2 | IS-004, EV-002 | **NotInject benchmark dataset** creation + evaluation framework | Small |
| 2-3 | IS-006, IS-007 | **FPR-aware threshold optimisation** with configurable operating points | Medium |
| 3-4 | IS-005 | **Three-dimensional evaluation** (benign/malicious/over-defense metrics) | Low |
| 4-5 | SA-002 | **Canary token system** for prompt leakage detection | Low |
| 5-6 | AS-008 | **Tool registry** with security classification | Medium |

**Phase 1 Target Metrics:**
- Over-defense accuracy: Measured (currently unknown) → Target >70%
- FPR at 0.1%: Measured (currently unknown) → Establish baseline
- Unicode evasion: Close 100% ASR emoji smuggling gap

### Phase 2: Major Features (Weeks 7-18)

Focus: Agent security, model diversification, advanced detection.

| Week | Feature IDs | Description | Effort |
|------|------------|-------------|--------|
| 7-9 | AS-001, AS-002 | **Tool-boundary firewalling** — input minimiser + output sanitiser | High |
| 7-9 | IS-050, IS-052 | **Perplexity-based anomaly detection** + adversarial string propagation blocking in tool outputs (Agent-as-a-Proxy defense) | Medium |
| 7-9 | ML-002, ML-003, ML-006 | **Model ensemble diversification** — InjecGuard + Meta Prompt Guard | Medium |
| 9-11 | AS-010, AS-015 | **Action-Selector pattern enforcement** + action-type rate limiting | Medium |
| 9-11 | EV-016 | **AgentDojo Slack suite adaptive attack evaluation** — Agent-as-a-Proxy resilience testing | High |
| 10-12 | ML-001, ML-014 | **Joint fusion training pipeline** with curated dataset (blocked by DMPI-001–006; see §3.4.1a) | High |
| 11-13 | ML-010, ML-012 | **MOF training** + adversarial training integration | High |
| 12-14 | AS-020, AS-021, AS-023 | **Multi-agent defense** — coordinator + guard + second opinion | High |
| 14-16 | AS-030, AS-035 | **MCP protocol monitoring** + Toxic Agent Flow defense | High |
| 14-16 | IS-051, ML-016 | **Adaptive monitoring scope** + GCG adversarial sample generation (Python/PyTorch offline tooling) | High |
| 16-18 | EV-017, EV-018 | **GCG adversarial robustness testing** + cross-model transfer attack resistance | High |
| 16-18 | OS-001, OS-003, ML-005 | **HaluGate-style token-level hallucination detection** | High |

**Phase 2 Target Metrics:**
- Over-defense accuracy: >85% (approaching InjecGuard's 87.32%)
- Ensemble F1 on deepset-v2: >90% (approaching DMPI-PMHFE's 90.21%)
- Tool-boundary ASR: <1% (approaching firewall paper's 0%)
- Multi-agent ASR: <5% (approaching paper's 0%)

### Phase 3: Research Frontier (Weeks 19-30+)

Focus: Cutting-edge capabilities, multimodal, advanced protocols.

| Week | Feature IDs | Description | Effort |
|------|------------|-------------|--------|
| 19-21 | MM-001, MM-004 | **Multimodal security** — image injection detection, OCR pipeline | High |
| 21-23 | AS-031, AS-032, AS-033 | **A2A/ANP protocol security** with dynamic trust management | High |
| 23-25 | OS-010, OS-011 | **Streaming Content Monitor** — purpose-built partial-sequence models | High |
| 25-27 | SA-001 | **Policy/rules language** — declarative security policy specification | High |
| 27-29 | SA-003, SA-004 | **Taint tracking** + blast radius reduction | High |
| 29-30+ | PR-001, PR-010, SA-005 | **Advanced privacy** — membership inference, memory poisoning, backdoor detection | High |

**Phase 3 Target Metrics:**
- Multimodal attack detection: >80% of image-based injection vectors
- Protocol attack detection: Monitor all MCP/A2A tool calls
- Streaming detection: 95%+ F1 at 18% token visibility (matching SCM)

---

## 5. Competitive Landscape

### 5.1 Feature Comparison Matrix

| Capability | LLMTrace | InjecGuard | LLM Guard | Lakera Guard | NeMo Guardrails | LlamaFirewall | IBM OneShield | Guardrails AI |
|-----------|----------|------------|-----------|-------------|-----------------|---------------|---------------|--------------|
| **Architecture** | Rust proxy | Python classifier | Python library | SaaS API | Python DSL | Python framework | Enterprise | Python validators |
| **Deployment** | Transparent proxy | Model only | SDK integration | API call | SDK integration | SDK integration | Platform | SDK integration |
| **Prompt injection** | ✅ Ensemble | ✅ MOF-trained | ✅ DeBERTa | ✅ Proprietary | ✅ LLM-based | ✅ PromptGuard2 | ✅ Policy-driven | ✅ LLM-based |
| **Over-defense mitigation** | ❌ | ✅ MOF | ❌ | Unknown | ❌ | ❌ | ❌ | ❌ |
| **Jailbreak detection** | ✅ Dedicated | ⚠️ General | ⚠️ General | ✅ | ✅ | ✅ PromptGuard2 | ✅ | ✅ |
| **Feature-level fusion** | ⚠️ (random weights; 2 architectural deviations from DMPI-PMHFE remain — see §3.4.1a) | ❌ | ❌ | Unknown | ❌ | ❌ | ❌ | ❌ |
| **Unicode normalisation** | ✅ Comprehensive | ❌ | ❌ | Unknown | ❌ | ❌ | Unknown | ❌ |
| **Toxicity detection** | ✅ BERT + fallback | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ |
| **Hallucination detection** | ✅ Cross-encoder | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Code security** | ✅ 7 categories | ❌ | ✅ | ❌ | ❌ | ✅ CodeShield | ❌ | ❌ |
| **PII detection** | ✅ Regex+NER+Checksum | ❌ | ✅ Presidio | ✅ | ❌ | ❌ | ✅ | ✅ Presidio |
| **PII redaction** | ✅ 3 modes | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ |
| **Secret scanning** | ✅ 9 patterns | ❌ | ✅ | Unknown | ❌ | ❌ | Unknown | ❌ |
| **Streaming analysis** | ✅ Input+Output | ❌ | ❌ | ✅ | ❌ | ❌ | ⚠️ | ❌ |
| **Early stopping** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Agent action analysis** | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ Agent Alignment | ❌ | ❌ |
| **Tool-boundary firewalling** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **MCP/A2A protocol security** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Multi-agent defense** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Policy language** | ❌ YAML config | ❌ | ❌ | ❌ | ✅ Colang | ❌ | ✅ | ✅ RAIL XML |
| **Multimodal** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Multi-tenant** | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ✅ | ❌ |
| **Cost control** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Anomaly detection** | ✅ | ❌ | ❌ | Unknown | ❌ | ❌ | ❌ | ❌ |
| **Compliance** | ✅ SOC2/GDPR/HIPAA | ❌ | ❌ | ✅ | ❌ | ❌ | ✅ | ❌ |
| **Open source** | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ |
| **Language** | Rust | Python | Python | N/A | Python | Python | Java | Python |
| **Latency (p50)** | <100ms | ~15ms | ~200ms | ~50ms | ~500ms | ~200ms | Unknown | ~1s |

### 5.2 LLMTrace Unique Differentiators

1. **Only Rust-native LLM security proxy** — performance advantage is structural
2. **Only system with feature-level fusion architecture** — DMPI-PMHFE-inspired, but 1 architectural deviation (DMPI-006) must be resolved before trained weights can match paper SOTA; DMPI-001 (average pooling), DMPI-002 (2 FC layers), DMPI-003 (10 binary features), DMPI-004 (repetition threshold >=3), and DMPI-005 (missing features) resolved (see §3.4.1a)
3. **Only system combining streaming analysis + early stopping + output safety** — no competitor has all three
4. **Only system with integrated cost control + security** — single deployment for both concerns
5. **Most comprehensive Unicode normalisation** — 30+ homoglyph mappings + 18 zero-width chars
6. **Only system with code security + toxicity + hallucination in one proxy** — others require multiple tools

### 5.3 Key Competitive Gaps to Close

1. **InjecGuard's MOF training** — only open-source solution for over-defense mitigation
2. **NeMo's Colang policy language** — declarative guardrails are the future
3. **LlamaFirewall's Agent Alignment Checker** — multi-step agentic operation monitoring
4. **Lakera Guard's commercial maturity** — production-grade at scale
5. **IBM OneShield's compliance depth** — enterprise compliance automation

---

## 6. Research Paper Reference Index

All features in this roadmap are traceable to specific research papers:

| Short Name | Full Title | Year | Key Contributions |
|-----------|-----------|------|-------------------|
| **SoA Report** | Security State-of-the-Art Research Report & Gap Analysis | 2026 | Comprehensive survey: DMPI-PMHFE validation, PromptShield FPR analysis, HaluGate, SCM, OWASP 2025, framework comparison |
| **Bypassing Guardrails** | Bypassing Prompt Injection and Jailbreak Detection in LLM Guardrails (Mindgard/ACL LLMSEC 2025) | 2025 | 12 character injection techniques (100% ASR emoji/upside-down), 8 AML evasion techniques (TextFooler 46-48% ASR), ProtectAI model vulnerability documented |
| **InjecGuard** | InjecGuard: Benchmarking and Mitigating Over-defense in Prompt Injection Guardrail Models | 2024 | NotInject benchmark (339 samples), MOF training strategy (+54% over-defense improvement), token-wise bias detection, 17 format augmentation |
| **Indirect Injection Firewalls** | Indirect Prompt Injections: Are Firewalls All You Need? (ServiceNow/Mila) | 2025 | Tool-Input Firewall (Minimizer), Tool-Output Firewall (Sanitizer), 0% ASR across 4 benchmarks, exposed AgentDojo/ASB/InjecAgent flaws |
| **Tool Result Parsing** | Defense Against Indirect Prompt Injection via Tool Result Parsing (HIT) | 2025 | ParseData + CheckTool modules, 10x lower ASR vs DeBERTa (0.19% vs 1.19%), proactive sanitisation > reactive classification |
| **Design Patterns** | Design Patterns for Securing LLM Agents against Prompt Injections (IBM/EPFL/ETH/Google/Microsoft) | 2025 | 6 provable design patterns (Action-Selector, Plan-Then-Execute, Map-Reduce, Dual LLM, Code-Then-Execute, Context-Minimization), 10 case studies |
| **Multi-Agent Defense** | A Multi-Agent LLM Defense Pipeline Against Prompt Injection Attacks | 2024 | Coordinator + Guard architecture, 0% ASR across 400 attacks (8 categories), HPI_ATTACK_DATASET |
| **Protocol Exploits** | From Prompt Injections to Protocol Exploits: Threats in LLM-Powered AI Agents Workflows | 2025 | 30+ attack techniques across 4 domains, MCP/A2A/ANP vulnerabilities, multimodal attacks, composite backdoors (100% ASR), MINJA memory poisoning |
| **Benchmarks & Tools** | Benchmarks and Tools Landscape Analysis | 2026 | AgentDojo, InjecAgent, ASB, NotInject, WASP, CyberSecEval 2 benchmarks; LLM Guard, NeMo, InjecGuard, Prompt Guard, Llama Guard, Granite Guardian tools; tldrsec defense taxonomy |
| **CyberSecEval 2** | CyberSecEval 2: A Wide-Ranging Cybersecurity Evaluation Suite for Large Language Models (Meta, arXiv 2404.13161) | 2024 | 251 prompt injection tests across 15 attack categories (26-41% ASR), code interpreter abuse (500 prompts, 5 categories), exploit generation (4 CTF-style categories), False Refusal Rate methodology, v1-vs-v2 cyberattack helpfulness comparison (52%->28% compliance). Breakdown: `docs/research/cyberseceval2-llm-security-benchmark.md` |
| **BIPIA** | Benchmarking and Defending Against Indirect Prompt Injection Attacks on Large Language Models (USTC/HKUST/Microsoft, arXiv 2312.14197, KDD 2025) | 2023 | First indirect prompt injection benchmark: 86,250 test prompts, 5 scenarios, 50 attack types. 25-model evaluation (GPT-4: 31% ASR, avg 11.8%). Boundary token (`<data>`/`</data>`) + explicit reminder defenses. White-box: near-zero ASR (0.47-0.53%). Key finding: more capable models more vulnerable (r=0.6423). Breakdown: `docs/research/bipia-indirect-prompt-injection-benchmark.md` |
| **DMPI-PMHFE** | Detection Method for Prompt Injection by Integrating Pre-trained Model and Heuristic Feature Engineering (Zhengzhou University, arXiv 2506.06384) | 2025 | Dual-channel feature fusion: DeBERTa-v3-base + 10 heuristic features, SOTA F1 across 3 benchmarks (98.29% safeguard-v2, 96.03% Ivanleomk-v2, 89.55% deepset-v2). ~6% F1 gain over score-level ensemble. LLMTrace fusion architecture directly based on this paper. Breakdown: `docs/research/dmpi-pmhfe-prompt-injection-detection.md` |
| **WASP** | WASP: Benchmarking Web Agent Security Against Prompt Injection Attacks (arXiv 2504.18575) | 2024 | Web agent prompt injection benchmark with realistic browsing workflows. Evaluates task success alongside attack success. Strong LLM agents remain vulnerable to practical web-based injection. Breakdown: `docs/research/wasp-web-agent-security-benchmark.md` |
| **Self-Distillation** | Self-Distillation Enables Continual Learning (arXiv 2601.19897) | 2025 | SDFT method for on-policy learning from demonstrations without catastrophic forgetting. Applicable to MOF training pipeline (ML-010), adversarial training (ML-012), and robust training (ML-013). Breakdown: `docs/research/self-distillation-continual-learning.md` |
| **Agent-as-a-Proxy** | Bypassing AI Control Protocols via Agent-as-a-Proxy Attacks (arXiv 2602.05066) | 2026 | Demonstrates monitoring-based defenses are fundamentally fragile: 90%+ ASR against AlignmentCheck/LlamaFirewall/Extract-and-Evaluate. Hybrid monitoring paradox (more observation = more attack surface). No capability gap needed (GPT-4o mini bypasses Qwen2.5-72B). 88-90% cross-model transferability. Validates structural defenses (sanitization, boundary tokens) over monitoring. Breakdown: `docs/research/agent-as-a-proxy-attacks.md` |
| **Defense Pipeline Design** | LLMTrace Defense Pipeline Design | 2026 | Internal architecture doc: staged defense pipeline with 5 core capabilities (hook points, detector/guard plugin interface, policy engine, PII-safe data model, metrics/tracing). Defines policy actions (allow/block/redact/rewrite/confirm/downgrade/disable). Source for SA-001 policy language requirements. File: `docs/research/llmtrace-defense-pipeline-design.md` |

---

## Appendix A: OWASP LLM Top 10 2025 Coverage Matrix

| ID | Category | LLMTrace Status | Gap IDs | Target Phase |
|----|----------|-----------------|---------|-------------|
| LLM01 | Prompt Injection | ✅ Covered (ensemble) | IS-001 through IS-031 | Phase 1-2 |
| LLM02 | Sensitive Information Disclosure | ✅ Covered (PII+NER) | PR-006 through PR-009 | Phase 2-3 |
| LLM03 | Supply Chain | ⬜ N/A (CI/CD) | OS-032 | Phase 3 |
| LLM04 | Data and Model Poisoning | ⬜ N/A (runtime) | SA-005 through SA-007 | Phase 3 |
| LLM05 | Improper Output Handling | ✅ Covered (toxicity+code) | OS-020 through OS-031 | Phase 2 |
| LLM06 | Excessive Agency | ✅ Covered (agent actions) | AS-010 through AS-016 | Phase 2 |
| LLM07 | System Prompt Leakage | ⚠️ Partial | SA-002, IS-016 | Phase 1-2 |
| LLM08 | Vector/Embedding Weaknesses | ❌ Not covered | PR-004, PR-005 | Phase 3 |
| LLM09 | Misinformation | ✅ Covered (hallucination) | OS-001 through OS-006 | Phase 2-3 |
| LLM10 | Unbounded Consumption | ✅ Covered (rate+cost) | IS-017 | Phase 1 |

## Appendix B: Attack Success Rate Summary from Papers

| Attack Technique | ASR (reported) | Paper | LLMTrace Defense | Gap Severity |
|-----------------|---------------|-------|-----------------|-------------|
| Emoji smuggling | 100% | Bypassing Guardrails | ❌ None | **Critical** |
| Upside-down text (jailbreak) | 100% | Bypassing Guardrails | ❌ None | **Critical** |
| Unicode tags | 90.15% PI / 81.79% JB | Bypassing Guardrails | ⚠️ Partial | High |
| Bidirectional text | 78.69% PI / 99.23% JB | Bypassing Guardrails | ✅ Stripped | Low |
| TextFooler (AML) | 46-48% ASR | Bypassing Guardrails | ❌ No defense | **High** |
| BERT-Attack (AML) | 57.57% PI / 23.85% JB | Bypassing Guardrails | ❌ No defense | **High** |
| ToolHijacker | 96.7% vs GPT-4o | SoA Report | ❌ No defense | **Critical** |
| Composite backdoors (CBA) | 100% ASR, <2% false trigger | Protocol Exploits | ❌ No defense | High |
| Environment injection (mobile) | 93% ASR | Protocol Exploits | ❌ No defense | Medium |
| Adaptive jailbreaks (GPTFuzz) | >90% ASR | Protocol Exploits | ❌ No defense | **High** |
| DemonAgent (dynamic encryption) | High ASR | Protocol Exploits | ❌ No defense | High |
| Indirect injection via tools | Variable | Indirect Injection Firewalls | ⚠️ Partial (detection only) | **High** |
| "Important Messages" header | High ASR | Tool Result Parsing | ⚠️ Partial | Medium |
| Multi-turn persistence | Variable | Multi-Agent Defense | ❌ No defense | High |
| Braille encoding bypass | Bypasses GPT-4o sanitizer | Indirect Injection Firewalls | ❌ No defense | Medium |
| Prompt injection (direct, 15 categories) | 26-41% ASR (model-dependent) | CyberSecEval 2 | ⚠️ Partial (ensemble detection) | Medium |
| Code interpreter abuse (5 categories) | 13-47% compliance (model-dependent) | CyberSecEval 2 | ❌ No defense | Medium |
| Indirect injection (5 scenarios, 50 types) | 5.3-31% ASR (GPT-4 highest at 31%) | BIPIA | ⚠️ Partial (detection only, no boundary tokens) | **High** |
| Indirect injection via summarization | 19.7% avg ASR (highest text task) | BIPIA | ⚠️ Partial | Medium |
| Indirect injection via code | 24.1% avg ASR (code attacks) | BIPIA | ⚠️ Partial | Medium |
| Agent-as-a-Proxy (monitor bypass) | 90%+ ASR against hybrid monitors | Agent-as-a-Proxy | ⚠️ Partial (monitoring-based; structural defenses needed) | **Critical** |
| Multi-objective GCG (multi-layer bypass) | 99% ASR bypassing PromptGuard 2 + AlignmentCheck | Agent-as-a-Proxy | ❌ No adversarial robustness testing | **High** |
| Cross-model transfer attacks | 88-90% ASR transfers 8B -> 405B | Agent-as-a-Proxy | ❌ No transfer resistance testing | **High** |

## Appendix C: Model Comparison for Ensemble

| Model | Params | Latency (CPU) | License | Over-defense | Candle Support | Priority |
|-------|--------|---------------|---------|-------------|---------------|----------|
| protectai/deberta-v3-base-prompt-injection-v2 | 86M | ~50-100ms | Apache 2.0 | 56.64% | ✅ In use | Current |
| InjecGuard (DeBERTa-v3-base + MOF) | 86M | ~15ms | Open | 87.32% | ✅ DeBERTa | P1 |
| meta-llama/Llama-Prompt-Guard-2-86M | 86M | ~60-110ms | Llama | Unknown | Likely ✅ | P1 |
| meta-llama/Llama-Prompt-Guard-2-22M | 22M | ~15-30ms | Llama | Unknown | Likely ✅ | P1 |
| PIGuard (DeBERTa + MOF) | ~86M | Similar | Open | SOTA | ✅ DeBERTa | P1 |
| answerdotai/ModernBERT-base | 149M | ~20-50ms | Apache 2.0 | N/A | ⚠️ Needs port | P2 |
| unitary/toxic-bert | 110M | ~50-80ms | Apache 2.0 | N/A | ✅ In use | Current |
| vectara/hallucination_evaluation_model | ~110M | ~60-100ms | Apache 2.0 | N/A | ✅ In use | Current |
| cross-encoder/nli-deberta-v3-base | 86M | ~60-100ms | Apache 2.0 | N/A | ✅ DeBERTa | P2 |

---

*This document covers findings from all 16 research documents in `docs/research/` (13 external papers + 3 internal analysis docs). Every feature, technique, attack vector, and defense mechanism mentioned across all papers is catalogued with unique IDs, paper references, priority levels, and implementation notes. This roadmap will serve as the basis for development planning and academic paper preparation.*
