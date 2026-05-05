# LLMTrace System Architecture Report: OWASP GenAI Threat Model Alignment

**Date**: 2026-03-07
**Version**: 1.0
**Scope**: System architecture analysis mapping LLMTrace capabilities to the OWASP Top 10 for LLM Applications (2025)
**Perspectives**: AI Engineering, MLOps, Security Engineering
**Context**: LLMTrace is a Rust-based transparent LLM proxy with integrated security analysis


## Table of Contents

- [Executive Summary](#1-executive-summary)
- [LLMTrace Architecture Overview](#2-llmtrace-architecture-overview)
- [OWASP GenAI Top 10 Coverage Analysis](#3-owasp-genai-top-10-coverage-analysis)
- [AI Engineering Perspective](#4-ai-engineering-perspective)
- [MLOps Engineering Perspective](#5-mlops-engineering-perspective)
- [Security Engineering Perspective](#6-security-engineering-perspective)
- [Cross-Cutting Concerns](#7-cross-cutting-concerns)
- [Gap Analysis and Roadmap](#8-gap-analysis-and-roadmap)
- [References](#9-references)


## Executive Summary

LLMTrace occupies a unique architectural position in the GenAI security landscape: a transparent proxy that mediates all traffic between LLM clients and providers. This position enables inspection and enforcement at every trust boundary -- request ingress, tool-call gates, response egress, and streaming channels.

**Current OWASP Coverage Assessment**:

| Coverage Level | Categories | Count |
|---------------|------------|-------|
| Strong (7-9/10) | LLM01, LLM02, LLM06, LLM10 | 4 |
| Partial (4-6/10) | LLM05, LLM07 | 2 |
| Monitoring only (2-3/10) | LLM03, LLM04 | 2 |
| Gap (0-1/10) | LLM08, LLM09 | 2 |

**Key Finding**: LLMTrace provides strong defence-in-depth for injection-class attacks (LLM01) and information disclosure (LLM02), with a comprehensive multi-model ensemble pipeline. The primary gaps are in RAG/embedding security (LLM08) and misinformation/hallucination detection (LLM09), both of which are addressable from the proxy vantage point.

**Architecture Strengths**:
- Rust-native performance: sub-millisecond regex analysis, ~50-100ms ML inference
- True transparent proxy: zero-integration deployment
- Multi-model ensemble: DeBERTa + InjecGuard + PIGuard + PromptGuard + regex heuristics
- Feature-level fusion classifier for improved detection accuracy
- Streaming security analysis during SSE for real-time detection
- Tool firewall with schema validation and allowlisting
- MCP protocol monitoring
- Multi-agent defence pipeline with trust levels


## LLMTrace Architecture Overview

### 1 Crate Structure

```
llmtrace/
  crates/
    llmtrace-proxy/       # HTTP proxy, routing, streaming, enforcement
    llmtrace-security/    # Detection engines, ML models, policy
    llmtrace-storage/     # ClickHouse, Postgres, SQLite, Redis
    llmtrace-core/        # Shared types, traits, error handling
    llmtrace-sdk/         # Client SDK
    llmtrace-nodejs/      # Node.js bindings
    llmtrace-python/      # Python bindings
    llmtrace-wasm/        # WebAssembly module
  benchmarks/             # Performance and accuracy benchmarks
  dashboard/              # Next.js monitoring UI
```

### 2 Security Crate Components

The `llmtrace-security` crate is the core defence engine, containing:

**Detection Engines**:
- `ensemble.rs` -- Combines regex + ML with majority voting and confidence boosting
- `ml_detector.rs` -- DeBERTa-v3-base prompt injection classifier via Candle
- `feature_extraction.rs` -- Heuristic feature extraction (synonym matching, pattern detection)
- `fusion_classifier.rs` -- Feature-level fusion (DeBERTa embeddings + heuristic features)
- `injecguard.rs` -- InjecGuard model for over-defence-aware detection
- `piguard.rs` -- PIGuard model with MOF (Mitigating Over-defence for Free)
- `prompt_guard.rs` -- Meta PromptGuard integration
- `jailbreak_detector.rs` -- Dedicated jailbreak detection
- `ner_detector.rs` -- BERT NER for PII entity detection
- `toxicity_detector.rs` -- Output toxicity classification
- `hallucination_detector.rs` -- Hallucination detection pipeline
- `output_analyzer.rs` -- Response content safety analysis

**Defence Infrastructure**:
- `tool_firewall.rs` -- Schema validation, input minimization, output sanitization
- `tool_registry.rs` -- Tool allowlisting, categorization, rate limiting
- `mcp_monitor.rs` -- Model Context Protocol security monitoring
- `action_correlator.rs` -- Multi-step action sequence correlation
- `action_policy.rs` -- Policy engine with enforcement modes
- `multi_agent.rs` -- Multi-agent defence pipeline with trust levels
- `session_analyzer.rs` -- Cross-request session analysis
- `canary.rs` -- Canary token injection and detection
- `adversarial_defense.rs` -- Multi-pass normalization, perturbation detection
- `normalise.rs` -- Unicode NFKC normalization, zero-width character stripping
- `code_security.rs` -- LLM-generated code security analysis

**Calibration and Monitoring**:
- `fpr_calibration.rs` -- False positive rate threshold optimisation
- `fpr_monitor.rs` -- Runtime FPR drift detection and alerting
- `inference_stats.rs` -- Model inference latency and throughput tracking
- `thresholds.rs` -- Per-category confidence thresholds
- `pii_validation.rs` -- PII checksum validation (Luhn, IBAN)
- `result_parser.rs` -- Multi-detector result aggregation

### 3 Proxy Pipeline

```
Client Request
    |
    v
[Proxy Layer] -- proxy.rs
    |-- Request canonicalization
    |-- Accept-Encoding stripping (prevent gzip from upstream)
    |-- Role prefix stripping (messages_to_analysis_text)
    |
    v
[Pre-Request Analysis] -- enforcement.rs
    |-- Regex security analysis (sub-ms)
    |-- ML ensemble analysis (~50-100ms)
    |-- FPR-calibrated thresholds
    |-- Policy evaluation (allow/block/flag/redact)
    |
    v
[Upstream Forward] --> LLM Provider
    |
    v
[Response Analysis] -- streaming.rs, output_analyzer.rs
    |-- Streaming SSE token analysis
    |-- Output safety (toxicity, leakage)
    |-- PII detection in responses
    |
    v
[Storage & Telemetry] -- storage crate
    |-- ClickHouse (analytics)
    |-- Postgres (structured data)
    |-- Redis (caching)
    |
    v
Client Response
```

### 4 Ensemble Architecture

The detection pipeline uses a layered ensemble:

**Primary Pair** (majority voting):
- Regex heuristics -- 13+ pattern categories
- DeBERTa-v3-base -- ProtectAI prompt injection classifier

**Auxiliary Detectors** (additive-only, no voting participation):
- InjecGuard -- Over-defence-aware, capped at confidence 0.60 unless corroborated
- PIGuard -- MOF-trained, same capping strategy

**Fusion Path** (when enabled):
- DeBERTa embeddings (768-dim) + heuristic features (16-dim) concatenated
- Trained FC classifier on the 784-dim combined representation
- Provides ~6% F1 improvement over score-level ensemble on hard datasets


## OWASP GenAI Top 10 Coverage Analysis

### 1 LLM01: Prompt Injection -- Coverage: 8/10

**Current Implementation**:

LLMTrace provides the most comprehensive coverage for this category, which aligns with its core mission.

| Component | Implementation | Code Reference |
|-----------|---------------|----------------|
| Regex heuristics | 13+ pattern categories for known injection signatures | `lib.rs` (RegexSecurityAnalyzer) |
| DeBERTa classifier | ProtectAI deberta-v3-base-prompt-injection-v2 | `ml_detector.rs` |
| InjecGuard | Over-defence-aware auxiliary detector | `injecguard.rs` |
| PIGuard | MOF-trained auxiliary detector | `piguard.rs` |
| PromptGuard | Meta's 86M param classifier | `prompt_guard.rs` |
| Feature fusion | DeBERTa embeddings + heuristic features | `fusion_classifier.rs` |
| Ensemble voting | Majority voting with confidence boosting | `ensemble.rs` |
| Unicode normalization | NFKC + zero-width stripping | `normalise.rs` |
| Adversarial defence | Multi-pass normalization, perturbation detection | `adversarial_defense.rs` |
| FPR calibration | Threshold optimisation at target FPR rates | `fpr_calibration.rs` |
| Streaming analysis | Real-time injection detection during SSE | `streaming.rs` |
| Jailbreak detection | Dedicated jailbreak classifier | `jailbreak_detector.rs` |

**Proxy Advantage**: LLMTrace sees both direct user prompts and indirect content from tool outputs/RAG retrieval, enabling detection of both direct and indirect prompt injection at the traffic boundary.

**Gaps**:
- No multi-turn injection sequence detection across conversation turns
- Limited adversarial robustness testing against GCG-optimised attacks (per Agent-as-a-Proxy research)
- No boundary token injection defence (highest-impact per BIPIA ablation)

**Key References**:
- HouYi (Liu et al., 2023): 31/36 real-world apps susceptible -- validates need for proxy-level detection
- GCG attacks (Zou et al., 2023): transferable adversarial suffixes bypass safety alignments
- Inject My PDF (Greshake, 2023): invisible text in documents exploits RAG pipelines
- ChatGPT plugin vulnerabilities (Embrace The Red, 2023): confused deputy via OAuth plugins

### 2 LLM02: Sensitive Information Disclosure -- Coverage: 8/10

**Current Implementation**:

| Component | Implementation | Code Reference |
|-----------|---------------|----------------|
| NER-based PII | BERT NER for entity detection | `ner_detector.rs` |
| Regex PII | Credit cards, SSNs, emails, phones, credentials | `lib.rs` |
| PII validation | Luhn checksum, IBAN validation | `pii_validation.rs` |
| Canary tokens | Injected markers for leakage detection | `canary.rs` |
| Output analysis | Response content scanning for sensitive data | `output_analyzer.rs` |
| System prompt leak detection | Pattern matching in responses | `lib.rs` |

**Proxy Advantage**: LLMTrace inspects both request and response content, detecting PII flowing in both directions. Canary tokens enable active leakage detection.

**Gaps**:
- No context-aware confidence boosting (Presidio-style lemma context enhancement)
- Limited multi-language PII support (CJK, Arabic patterns)
- No LLM-specific output patterns (e.g., memorized training data regurgitation)

**Key References**:
- Samsung ChatGPT leak (2023): employees leaked proprietary code, meeting notes, hardware specs
- AVID-2023-v009: cataloged ChatGPT training data extraction vulnerability

### 3 LLM03: Supply Chain Vulnerabilities -- Coverage: 3/10

**Current Implementation**:

LLM03 is primarily outside the proxy runtime scope, but LLMTrace has some relevant controls:

| Component | Implementation | Code Reference |
|-----------|---------------|----------------|
| Model hash verification | SHA256 verification of LLMTrace's own ML models | Config-level |
| Model cache directory | Configurable cache with env var override | `LLMTRACE_ML_CACHE_DIR` |
| Docker hardening | Non-root container, minimal base image | Dockerfile |

**Proxy Advantage**: Limited. Supply chain attacks target build-time and distribution, not runtime. However, LLMTrace can detect behavioural anomalies that may indicate a compromised upstream model.

**Gaps**:
- No model provenance verification for proxied LLM providers
- No plugin/extension integrity checking
- No behavioural drift detection for upstream model changes

**Key References**:
- Silent Sabotage (HiddenLayer): Hugging Face Safetensors conversion service weaponized
- PoisonGPT (Mithril Security): ROME-edited GPT-J-6B with only 0.1% accuracy difference on benchmarks
- JFrog research: ~100 confirmed malicious models on Hugging Face using pickle deserialization
- Anthropic Sleeper Agents: deceptive behaviours persist through standard safety training

### 4 LLM04: Data and Model Poisoning -- Coverage: 2/10

**Current Implementation**:

| Component | Implementation | Code Reference |
|-----------|---------------|----------------|
| Anomaly detection | Basic response pattern monitoring | `anomaly.rs` |
| Model integrity | Hash verification for LLMTrace's own models | Config-level |

**Proxy Advantage**: LLMTrace observes all model outputs over time, creating a statistical baseline. Behavioural shifts (e.g., a poisoned model producing systematically different outputs for trigger phrases) could be detected through response distribution monitoring.

**Gaps**:
- No trigger pattern detection in upstream model responses
- No statistical baseline for normal model behaviour
- No training data validation (out of proxy scope)

**Key References**:
- Wan et al. (ICML 2023): 100 poisoned examples suffice to manipulate models; larger models more vulnerable
- Sleeper Agents (Anthropic, 2024): backdoor behaviours survive SFT, RLHF, adversarial training
- Cobalt: clean label attacks insert backdoors without obvious data tampering

### 5 LLM05: Improper Output Handling -- Coverage: 6/10

**Current Implementation**:

| Component | Implementation | Code Reference |
|-----------|---------------|----------------|
| Output analysis | Response content safety scanning | `output_analyzer.rs` |
| Toxicity detection | Toxicity classifier on response content | `toxicity_detector.rs` |
| Code security | Static analysis of LLM-generated code | `code_security.rs` |
| Agent action analysis | Dangerous command/URL/file detection | `action_policy.rs` |
| Streaming output | Token-level analysis during SSE | `streaming.rs` |

**Proxy Advantage**: LLMTrace is the last checkpoint before LLM output reaches downstream systems. Response analysis can prevent XSS, command injection, and SSRF payloads from propagating.

**Gaps**:
- Output encoding/escaping is application-dependent (proxy cannot know the consumer context)
- No SSRF detection for URLs in LLM responses
- Limited code injection pattern detection beyond basic analysis

**Key References**:
- LangChain CVE-2023-29374: arbitrary code execution via unsafe evaluation
- OWASP ASVS V5: validation, sanitization, and encoding requirements at trust boundaries
- Embrace The Red: output impact varies by deployment context (XSS, SQLi, OS commands)

### 6 LLM06: Excessive Agency -- Coverage: 7/10

**Current Implementation**:

| Component | Implementation | Code Reference |
|-----------|---------------|----------------|
| Tool firewall | Schema validation, allowlists, input minimization | `tool_firewall.rs` |
| Tool registry | Categorization, rate limiting per tool | `tool_registry.rs` |
| Action policy | Policy engine with enforcement modes | `action_policy.rs` |
| Action correlator | Multi-step action sequence correlation | `action_correlator.rs` |
| MCP monitor | Model Context Protocol security monitoring | `mcp_monitor.rs` |
| Multi-agent pipeline | Trust levels, agent profiling | `multi_agent.rs` |

**Proxy Advantage**: LLMTrace intercepts tool calls at the proxy boundary, enabling enforcement of least-privilege before tools execute. The tool firewall validates schemas and sanitizes arguments before they reach external services.

**Gaps**:
- No dynamic capability adjustment based on conversation risk level
- Limited tool output taint tracking across multi-step chains
- No privilege escalation detection across agent handoffs

**Key References**:
- Slack AI data exfiltration (PromptArmor, 2024): indirect injection via public channels exfiltrated private data
- Dual LLM pattern (Willison, 2023): privileged/quarantined model separation with controller
- NeMo Guardrails: programmable action restrictions via Colang DSL

### 7 LLM07: System Prompt Leakage -- Coverage: 5/10

**Current Implementation**:

| Component | Implementation | Code Reference |
|-----------|---------------|----------------|
| Response leakage detection | Pattern matching for system prompt content in outputs | `lib.rs` |
| Canary tokens | Marker detection in responses | `canary.rs` |

**Proxy Advantage**: LLMTrace sees both the system prompt (in the request) and the response. It can detect when system prompt content appears in outputs by comparing response text against known system prompt patterns.

**Gaps**:
- No proactive extraction attempt detection (multi-turn, encoded, role-play extraction)
- No system prompt fingerprinting for cross-request leakage correlation
- No adversarial extraction pattern library (base64 encode, summarize, repeat verbatim)

### 8 LLM08: Vector and Embedding Weaknesses -- Coverage: 1/10

**Current Implementation**:

Minimal direct coverage. This is the newest OWASP category and represents a significant gap.

**Proxy Advantage**: LLMTrace can observe embedding API calls and RAG retrieval patterns in proxied traffic. This creates opportunities for:
- Monitoring similarity score distributions for anomalies
- Detecting poisoned retrieval content that contains injection patterns
- Tracking retrieval quality metrics (context relevance, groundedness)

**Gaps**:
- No embedding API call monitoring
- No retrieval anomaly detection
- No RAG Triad evaluation integration (context relevance, groundedness, answer relevance)
- No vector database integrity monitoring

**Key References**:
- Astute RAG (Wang et al., 2024): imperfect retrieval is inevitable; knowledge conflicts require adaptive reconciliation
- RAG Triad (TruEra/TruLens): three-component evaluation (context relevance, groundedness, answer relevance)

### 9 LLM09: Misinformation -- Coverage: 2/10

**Current Implementation**:

| Component | Implementation | Code Reference |
|-----------|---------------|----------------|
| Hallucination detector | Initial pipeline (feature-gated) | `hallucination_detector.rs` |

**Proxy Advantage**: LLMTrace sees both tool-call results (ground truth) and LLM responses, making it ideally positioned for HaluGate-style hallucination detection that compares response claims against retrieved evidence.

**Gaps**:
- Hallucination detection is early-stage
- No factual claim verification pipeline
- No citation validation
- No NLI (Natural Language Inference) for entailment/contradiction analysis
- No streaming hallucination detection

**Key References**:
- Code security (Khoury et al., 2023): ChatGPT generates vulnerable code despite security awareness
- ThreatGPT (Gupta et al., 2023): dual-use concerns for GenAI in cybersecurity

### 10 LLM10: Unbounded Consumption -- Coverage: 7/10

**Current Implementation**:

| Component | Implementation | Code Reference |
|-----------|---------------|----------------|
| Rate limiting | Per-tenant, configurable RPS and burst | `rate_limit.rs` |
| Cost caps | Budget enforcement with configurable limits | `cost_caps.rs` |
| Cost tracking | Token usage and dollar-amount accounting | `cost.rs` |
| Circuit breaker | Degradation to pass-through on repeated failures | `circuit_breaker.rs` |
| Connection limits | Maximum concurrent connection enforcement | Config-level |
| Request size limits | Maximum request body size | Config-level |

**Proxy Advantage**: As the traffic gateway, LLMTrace controls all resource consumption. Rate limiting and cost caps prevent denial-of-wallet attacks. The circuit breaker ensures proxy resilience under attack.

**Gaps**:
- No sponge-example detection (crafted inputs maximizing compute)
- No context window flooding analysis
- No per-model resource accounting for multi-provider deployments
- No adaptive rate limiting based on anomaly detection

**Key References**:
- Model extraction (Carlini et al., 2024): complete projection matrices extracted from OpenAI models for under $20
- Sponge Examples (Shumailov et al., 2021): 10-200x energy consumption increase via crafted inputs


## AI Engineering Perspective

### 1 Detection Pipeline Architecture

LLMTrace's multi-model ensemble is architecturally sound but can be strengthened:

**Current Ensemble**:
```
Request Text
    |
    +---> Regex Heuristics (sub-ms)
    |         |
    +---> DeBERTa Classifier (~50-100ms)
    |         |
    +---> InjecGuard (auxiliary, ~80ms)
    |         |
    +---> PIGuard (auxiliary, ~80ms)
    |         |
    v
Ensemble Combiner (majority voting + confidence boost)
    |
    v
FPR Calibration + Thresholds
    |
    v
Security Finding
```

**Recommended Enhancement -- Tiered Inference**:
```
Request Text
    |
    v
[Tier 0] Unicode Normalization + Regex (sub-ms)
    |-- If HIGH confidence: fast-path decision
    |-- If MEDIUM: proceed to Tier 1
    |-- If LOW: allow, skip ML
    |
    v
[Tier 1] DeBERTa Feature Extraction + Fusion Classifier (~60ms)
    |-- Feature-level fusion (768-dim embeddings + 16-dim heuristics)
    |-- Single trained FC classifier
    |-- If confident: decision
    |-- If uncertain: proceed to Tier 2
    |
    v
[Tier 2] Multi-Model Ensemble (~150ms)
    |-- InjecGuard + PIGuard + PromptGuard
    |-- Weighted combination with diversity bonus
    |-- Final decision with full evidence
```

This tiered approach reduces average latency (most requests resolved at Tier 0/1) while maintaining high accuracy for ambiguous cases.

### 2 Model Serving Optimisation

**Current State**: Models are loaded via Candle framework with configurable device selection (CPU/CUDA) and model caching via `LLMTRACE_ML_CACHE_DIR`.

**Recommendations**:

**Batched inference**: Group concurrent requests for batch processing on GPU. Current implementation processes requests individually.


**Model quantization**: INT8 quantization for DeBERTa reduces memory by ~4x with <1% accuracy loss. Candle supports GGUF/GGML quantized formats.


**Model warmup**: Pre-run inference on startup to populate CPU caches and JIT-compile CUDA kernels. The `ml_preload` config flag handles model loading but not inference warmup.


**Async model loading**: Load auxiliary models (InjecGuard, PIGuard) asynchronously after primary model is ready, allowing the proxy to start serving with partial detection capability.


### 3 Feature-Level Fusion Strategy

The `fusion_classifier.rs` implements the DMPI-PMHFE approach (feature-level fusion vs. score-level ensemble). Key considerations:

- Feature-level fusion provides ~6% F1 improvement on hard datasets (deepset-v2: 83.75% to 90.21%)
- Recall improvement is the primary gain: 75.32% to 84.31%
- Requires offline training of the FC classifier on labeled data
- Training pipeline exists in `benchmarks/src/training/`
- Models are shipped as static weights alongside the DeBERTa checkpoint

### 4 Streaming Analysis Enhancement

The proxy already performs incremental security analysis during SSE streaming. Enhancements:

**Output-side streaming**: Extend streaming analysis to monitor response tokens (not just request content)


**Progressive confidence**: Accumulate confidence across token batches; trigger action when threshold crossed


**Early termination**: Ability to halt upstream generation when critical finding detected mid-stream


**Token-level annotations**: Mark specific tokens/spans as flagged rather than entire responses



## MLOps Engineering Perspective

### 1 Model Lifecycle Management

**Current State**: Models are downloaded from Hugging Face on first use and cached locally. No version pinning, no rollback capability, no A/B testing.

**Recommended Model Lifecycle**:

```
[Model Selection] -> [Benchmark Evaluation] -> [FPR Calibration]
                                                      |
                                                      v
                                                [Staged Rollout]
                                                      |
                              +-- Canary (5% traffic) -+
                              |                        |
                              +-- Production (95%) ----+
                                                      |
                                                      v
                                               [Monitoring]
                                                      |
                                          +-- Drift Alert --> [Rollback]
                                          |
                                          +-- Stable --> [Promote]
```
**Version pinning**: Lock model versions by SHA256 hash, not just name. Prevent silent upstream changes.


**Benchmark gates**: Automated evaluation on CyberSecEval2 and NotInject before promotion.


**FPR calibration**: Run `ThresholdCalibrator` on representative production traffic samples before deployment.


**Canary deployment**: Route subset of traffic through new model version; compare FPR/FNR against baseline.


**Rollback**: Instant model swap to previous version on drift detection.


### 2 Model Supply Chain Security

Directly relevant to LLM03 (Supply Chain Vulnerabilities).

**Critical Finding (MLOps Analysis)**: The highest-priority supply chain gap is unpinned, unverified model downloads. A compromised HuggingFace repository or man-in-the-middle attack could substitute a backdoored model that deliberately misclassifies specific injection patterns, effectively disabling the security pipeline for targeted attacks while passing all other tests.

Recommendations:

**Hash verification**: Verify SHA256 of all model files on load. Store expected hashes in a `model-manifest.json`. Reject tampered models.


**Pin Candle dependencies**: Change `Cargo.toml` from `git = "..."` to `git = "...", rev = "<specific-sha>"`. Current unpinned git HEAD resolution means any compromised commit would inject malicious code.


**Pre-bake models in Docker**: Download and verify model weights at image build time, embedding them in the container. Eliminate runtime downloads for both security and latency.


**SBOM generation**: Produce Software Bill of Materials during build. Run `cargo audit` in CI to flag known CVEs.


**Signed models**: Use GPG/Sigstore signatures for model provenance.


**Sandboxed inference**: Run model inference in restricted process with no network access.


**Architecture validation**: Verify model structure (layer count, hidden size, label count) matches expectations after loading to detect backdoor insertion.


### 3 Model Monitoring and Drift Detection

The `fpr_monitor.rs` provides runtime FPR drift detection. Extend to:

**Prediction distribution monitoring**: Track score distributions over time. Alert on shifts that indicate model degradation or data drift.


**Latency monitoring**: `inference_stats.rs` tracks per-model latency. Set SLOs (e.g., p99 < 200ms) with alerting.


**Throughput tracking**: Monitor inference queue depth and batch utilization.


**Calibration drift**: Periodically re-evaluate FPR calibration against fresh traffic samples.


**Feature drift**: Track heuristic feature distributions; flag when input characteristics change significantly.


### 4 Continuous Improvement Data Pipeline

```
[Production Traffic] --> [Sampling] --> [Labeling Queue]
                                              |
                                              v
                                    [Human Review/Labels]
                                              |
                                              v
                                    [Training Dataset Update]
                                              |
                                              v
                                    [Retrain + Evaluate]
                                              |
                                              v
                                    [Staged Rollout]
```

Key design decisions:
- Sample edge cases (scores near threshold) for maximum labeling value
- Privacy-preserving: store hashed/redacted samples, not raw content
- Feedback loops from false positive/negative reports
- Automated retraining triggered by drift alerts

### 5 Resource Management

For LLM10 (Unbounded Consumption) from the MLOps perspective:

**Model memory budgets**: Set per-model memory limits. Monitor RSS growth.


**Inference timeout**: Hard timeout on ML inference to prevent sponge-example attacks on LLMTrace's own models.


**Queue management**: Bounded inference queue with backpressure. Reject requests when overloaded.


**GPU memory management**: Share GPU across models with explicit allocation. Candle supports device selection.



## Security Engineering Perspective

### 1 Threat Model: LLMTrace as a Security Control

LLMTrace functions as a **network-layer security control** analogous to a Web Application Firewall (WAF) but specialized for LLM API traffic. Its threat model:

**What LLMTrace Controls**:
- All API traffic between clients and LLM providers
- Tool-call arguments and responses
- System prompts and conversation context
- Resource consumption and cost

**What LLMTrace Does Not Control**:
- LLM provider behaviour (model weights, safety mechanisms)
- Client-side behaviour (application logic, UI rendering)
- Training data and model provenance (upstream supply chain)
- Vector database content and retrieval logic

**Trust Boundaries**:
```
[Untrusted]        [Controlled]        [Partially Trusted]
Client/User  --->  LLMTrace Proxy  --->  LLM Provider
                       |
                       +--->  Tool/RAG Services [Untrusted]
```

### 2 Defence-in-Depth Architecture

LLMTrace implements defence-in-depth through layered controls at each pipeline stage:

**Layer 1 -- Network Controls**:
- Rate limiting (`rate_limit.rs`)
- Connection limits
- Request size limits
- TLS termination

**Layer 2 -- Input Sanitization**:
- Unicode NFKC normalization (`normalise.rs`)
- Zero-width character stripping
- Encoding detection and decoding (`encoding.rs`)
- Base64/hex payload detection

**Layer 3 -- Detection**:
- Regex heuristics (sub-ms, high precision for known patterns)
- ML classifiers (DeBERTa, InjecGuard, PIGuard, PromptGuard)
- Feature-level fusion classifier
- Jailbreak-specific detection

**Layer 4 -- Policy Enforcement**:
- Configurable enforcement modes (log/block/flag)
- Per-category severity and confidence thresholds
- Tool firewall with schema validation
- Action policy with multi-step correlation

**Layer 5 -- Output Safety**:
- Response content analysis
- Toxicity detection
- PII/credential scanning in outputs
- System prompt leakage detection
- Canary token monitoring

**Layer 6 -- Monitoring and Response**:
- FPR drift monitoring
- Session-level analysis
- Audit logging with evidence capture
- Metrics and alerting via dashboard

### 3 Per-Category Security Recommendations

**LLM01 (Prompt Injection) -- Strengthen**:
- Implement boundary token injection (`<data>`/`</data>`) as a proxy-level defence. BIPIA research shows 1064% ASR increase without boundary tokens.
- Add adversarial robustness testing against GCG-optimised attacks. The Agent-as-a-Proxy paper demonstrates 90%+ ASR against monitoring-based defences.
- Implement structural defences (sanitization, boundary tokens) as primary controls; ML detection as secondary. Structural defences are validated as more robust against adaptive attacks.

**LLM02 (Sensitive Info) -- Enhance**:
- Add context-aware PII confidence boosting. A "customer ID" near a 10-digit number should boost PII confidence; a random number in code should suppress.
- Implement secret scanning for JWT tokens, AWS access keys, GCP service accounts, GitHub tokens, SSH private keys.
- Add data classification labels for different PII tiers (public, internal, confidential, restricted).

**LLM03 (Supply Chain) -- Monitor**:
- Implement behavioural fingerprinting for upstream models. Track response distributions; alert on significant shifts that could indicate model replacement or compromise.
- Verify model version headers in provider API responses.
- Monitor for unexpected capability changes (new tools, changed function signatures).

**LLM05 (Output Handling) -- Extend**:
- Add URL reputation checking for links in LLM responses.
- Implement code output scanning for common vulnerability patterns (SQL injection, command injection, path traversal).
- Add markdown injection detection (image/link-based data exfiltration).

**LLM06 (Excessive Agency) -- Harden**:
- Implement dynamic capability restriction based on conversation risk score. As injection confidence increases, reduce available tools.
- Add taint tracking for untrusted data flowing through tool chains.
- Implement confirmation requirements for high-risk tool actions (file write, network access, code execution).

**LLM07 (System Prompt Leakage) -- Expand**:
- Build an adversarial extraction attempt library: base64/rot13 encoding requests, summarization requests, role-play extraction, multi-turn gradual extraction.
- Implement system prompt fingerprinting: hash the system prompt and detect any significant overlap in response content.
- Add response similarity scoring against known system prompt content.

**LLM08 (Vector/Embedding) -- Build**:
- Monitor embedding API calls for anomalous patterns (unusual query distributions, repeated similar queries).
- Detect injection patterns in retrieved content (text from vector DB results that matches injection signatures).
- Track retrieval quality metrics when visible in traffic (relevance scores, retrieval counts).

**LLM09 (Misinformation) -- Build**:
- Implement HaluGate-style detection leveraging proxy position: compare tool-call results (ground truth visible to proxy) against LLM response claims.
- Add citation validation: verify that URLs and references in responses are legitimate.
- Implement factual consistency checking across conversation turns.

**LLM10 (Unbounded Consumption) -- Extend**:
- Add context window flooding detection: alert when prompts approach model token limits.
- Implement adaptive rate limiting: tighten limits for clients with high risk scores.
- Add sponge-example detection: flag inputs with anomalous tokenization patterns or excessive repetition.

### 4 Attack Surface of LLMTrace Itself

LLMTrace, as a security control, is itself an attack target:

| Attack Vector | Risk | Mitigation |
|--------------|------|------------|
| Proxy bypass | Clients connect directly to LLM provider, skipping proxy | Network policy enforcement (only proxy IP can reach provider) |
| Model evasion | Adversarial inputs crafted to bypass detection | Multi-model ensemble, adversarial training, structural defences |
| Denial of service | Overwhelm proxy to force circuit-breaker bypass | Rate limiting, connection limits, graceful degradation |
| Model poisoning | Compromise LLMTrace's own ML models | Hash verification, signed models, isolated download |
| Configuration tampering | Modify config to disable detection | File integrity monitoring, RBAC on config files |
| Log injection | Inject misleading data into audit logs | Input validation on stored evidence, structured logging |
| Side-channel | Infer system prompt content from proxy timing/behaviour | Constant-time operations for security-critical paths |

**Security-Engineer Critical Findings**:
- TLS is disabled by default in `config.yaml` -- must be mandatory in production deployments
- ML model weights are downloaded from HuggingFace Hub without integrity verification at load time
- API keys have no expiration or automated rotation mechanism
- Storage credentials are in plaintext config files rather than a secrets manager

### 5 Compliance Mapping

| Framework | Relevant Controls | LLMTrace Contribution |
|-----------|------------------|----------------------|
| **SOC 2** | CC6.1 (Logical access), CC6.6 (System boundaries) | API access control, tool firewall, audit logging |
| **GDPR** | Art. 25 (Data protection by design), Art. 32 (Security of processing) | PII detection and redaction, data minimization, retention controls |
| **EU AI Act** | Art. 9 (Risk management), Art. 14 (Human oversight) | Risk scoring, enforcement modes, audit trail, dashboard |
| **NIST AI RMF** | MAP, MEASURE, MANAGE functions | Threat detection, metrics, policy enforcement |
| **ISO 27001** | A.8 (Asset management), A.12 (Operations security) | Data classification, monitoring, incident detection |

### 6 Red Team Testing Recommendations

To validate LLMTrace's effectiveness, conduct red team exercises targeting:

**Evasion testing**: Use GCG-generated adversarial suffixes, Unicode homoglyphs, encoding tricks, and multi-turn extraction to test detection bypass.


**Throughput testing**: Generate high-volume benign traffic mixed with low-rate attacks to test detection under load.


**Tool chain exploitation**: Craft multi-step tool-call sequences that individually appear benign but compose into data exfiltration.


**Model extraction**: Attempt to extract LLMTrace's detection model behaviour through systematic probing.


**Configuration weakness**: Test default configurations for security gaps (disabled enforcement, permissive thresholds).



## Cross-Cutting Concerns

### 1 Latency Budget

The proxy must operate within strict latency budgets to avoid degrading user experience:

| Stage | Budget | Current | Target |
|-------|--------|---------|--------|
| Regex analysis | <1ms | ~0.5ms | Maintained |
| Unicode normalization | <1ms | ~0.2ms | Maintained |
| DeBERTa inference | <150ms | ~50-100ms | <80ms (quantized) |
| Auxiliary models | <200ms | ~80ms each | Parallel execution |
| Policy evaluation | <1ms | ~0.1ms | Maintained |
| Total pre-request | <200ms | ~150ms | <150ms |
| Output analysis | <100ms | ~50ms | <80ms |

Strategies to meet budgets:
- Tiered inference (fast-path for clear cases)
- Parallel model execution on separate threads
- Model quantization (INT8/INT4)
- Result caching for repeated/similar inputs

### 2 Observability

LLMTrace produces security observability through:

**Security metrics**: Finding counts by category, severity distribution, FPR/FNR estimates


**Model metrics**: Inference latency (p50/p95/p99), throughput, cache hit rates


**Traffic metrics**: Request volume, token counts, cost per tenant


**Audit trail**: Every security finding with evidence spans, detector attributions, policy decisions


**Dashboard**: Next.js UI for real-time monitoring and historical analysis


### 3 Privacy and Data Handling

LLMTrace handles sensitive data and must follow privacy-by-design:

**Minimize storage**: Hash sensitive content before storage; store evidence spans, not full payloads


**Configurable retention**: Per-tenant retention policies with automatic expiry


**PII redaction**: Apply redaction before storage, not after


**Access control**: RBAC on dashboard and API access to traces


**Encryption**: TLS for all network communication; encryption at rest for stored data



## Gap Analysis and Roadmap

### 1 Priority Matrix

| Priority | Gap | OWASP Category | Effort | Impact |
|----------|-----|----------------|--------|--------|
| P0 | Boundary token injection defence | LLM01 | Small | High (1064% ASR increase without) |
| P0 | Adversarial robustness testing | LLM01 | Medium | High (validates detection) |
| P1 | Embedding/RAG security monitoring | LLM08 | Medium | High (new OWASP category) |
| P1 | Hallucination detection pipeline | LLM09 | Large | High (new OWASP category) |
| P1 | System prompt extraction detection | LLM07 | Medium | Medium |
| P2 | Dynamic capability restriction | LLM06 | Medium | Medium |
| P2 | Model behavioural fingerprinting | LLM03, LLM04 | Medium | Medium |
| P2 | Sponge-example detection | LLM10 | Small | Low |
| P3 | Context-aware PII boosting | LLM02 | Small | Low |
| P3 | Code output vulnerability scanning | LLM05 | Medium | Medium |

### 2 Implementation Phases

**Phase 1: Immediate (Q1 2026)** -- Strengthen existing coverage
- Implement boundary token injection as proxy-level rewrite
- Add adversarial extraction pattern library for LLM07
- Extend secret scanning patterns (JWT, AWS, GCP, SSH)
- Run CyberSecEval2 and NotInject benchmarks for baseline measurement

**Phase 2: Near-term (Q2 2026)** -- Address new OWASP categories
- Build RAG/embedding security monitoring (LLM08)
- Implement HaluGate-style hallucination detection leveraging proxy traffic (LLM09)
- Add dynamic capability restriction based on risk score (LLM06)
- Implement model behavioural fingerprinting for supply chain detection (LLM03/04)

**Phase 3: Medium-term (Q3 2026)** -- Advanced capabilities
- Full taint tracking across tool chains
- Citation validation and factual consistency checking
- Streaming output moderation with early termination
- A/B testing framework for detection model evaluation

**Phase 4: Long-term (Q4 2026)** -- Research-driven
- Adversarial training against GCG-optimised attacks
- Multi-turn attack sequence detection
- Cross-session threat correlation
- Policy language for custom security rules

### 3 Coverage Target

| OWASP Category | Current | Phase 1 | Phase 2 | Phase 3 |
|---------------|---------|---------|---------|---------|
| LLM01 Prompt Injection | 8/10 | 9/10 | 9/10 | 9/10 |
| LLM02 Sensitive Info | 8/10 | 8/10 | 8/10 | 9/10 |
| LLM03 Supply Chain | 3/10 | 3/10 | 5/10 | 6/10 |
| LLM04 Data Poisoning | 2/10 | 2/10 | 4/10 | 5/10 |
| LLM05 Output Handling | 6/10 | 6/10 | 7/10 | 8/10 |
| LLM06 Excessive Agency | 7/10 | 7/10 | 8/10 | 9/10 |
| LLM07 Prompt Leakage | 5/10 | 7/10 | 7/10 | 8/10 |
| LLM08 Vector/Embedding | 1/10 | 1/10 | 5/10 | 7/10 |
| LLM09 Misinformation | 2/10 | 2/10 | 5/10 | 7/10 |
| LLM10 Consumption | 7/10 | 7/10 | 8/10 | 8/10 |
| **Overall** | **4.9/10** | **5.2/10** | **6.6/10** | **7.6/10** |


## References

### OWASP GenAI Project
- OWASP Top 10 for LLM Applications (2025): https://genai.owasp.org/llm-top-10/
- OWASP LLM Project: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- Secure MCP Server Development Guide: https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/
- AI Red Teaming Vendor Evaluation: https://genai.owasp.org/resource/owasp-vendor-evaluation-criteria-for-ai-red-teaming-providers-tooling-v1-0/

### Academic Papers
- Liu et al. (2023). "Prompt Injection attack against LLM-integrated Applications" (HouYi). arXiv:2306.05499
- Zou et al. (2023). "Universal and Transferable Adversarial Attacks on Aligned Language Models" (GCG). arXiv:2307.15043
- Liu et al. (2024). "A Survey of Attacks on Large Vision-Language Models". arXiv:2407.07403
- Gupta et al. (2023). "From ChatGPT to ThreatGPT". arXiv:2307.00691
- Wan et al. (2023). "Poisoning Language Models During Instruction Tuning". ICML 2023. arXiv:2305.00944
- Khoury et al. (2023). "How Secure is Code Generated by ChatGPT?". arXiv:2304.09655
- Wang et al. (2024). "Astute RAG: Overcoming Imperfect Retrieval Augmentation". arXiv:2410.07176
- Carlini et al. (2024). "Stealing Part of a Production Language Model". arXiv:2403.06634
- Shumailov et al. (2021). "Sponge Examples: Energy-Latency Attacks on Neural Networks". arXiv:2006.03463
- Wei et al. (2018). "Power Side-Channel Attack on CNN Accelerators". arXiv:1803.05847

### Industry Research
- Greshake (2023). "Inject My PDF". https://kai-greshake.de/posts/inject-my-pdf/
- Embrace The Red (2023). "ChatGPT Plugin Vulnerabilities". https://embracethered.com/blog/posts/2023/chatgpt-plugin-vulns-chat-with-code/
- Embrace The Red (2023). "AI Injections: Context Matters". https://embracethered.com/blog/posts/2023/ai-injections-threats-context-matters/
- PromptArmor (2024). "Slack AI Data Exfiltration". https://promptarmor.substack.com/p/slack-ai-data-exfiltration-from-private
- Willison (2023). "The Dual LLM Pattern". https://simonwillison.net/2023/Apr/25/dual-llm-pattern/
- HiddenLayer (2024). "Silent Sabotage". https://www.hiddenlayer.com/research/silent-sabotage
- Mithril Security (2023). "PoisonGPT". https://blog.mithrilsecurity.io/poisongpt-how-we-hid-a-lobotomized-llm-on-hugging-face-to-spread-fake-news/
- JFrog (2024). "Malicious Hugging Face ML Models". https://jfrog.com/blog/data-scientists-targeted-by-malicious-hugging-face-ml-models-with-silent-backdoor/
- Anthropic (2024). "Sleeper Agents". https://www.anthropic.com/news/sleeper-agents-training-deceptive-llms-that-persist-through-safety-training
- Cobalt (2024). "Backdoor Attacks on AI Models". https://www.cobalt.io/blog/backdoor-attacks-on-ai-models
- TruEra. "RAG Triad". https://truera.com/ai-quality-education/generative-ai-rags/what-is-the-rag-triad/
- TruLens. "RAG Triad". https://www.trulens.org/getting_started/core_concepts/rag_triad/

### Vulnerability Databases
- CVE-2023-29374: LangChain Arbitrary Code Execution. https://security.snyk.io/vuln/SNYK-PYTHON-LANGCHAIN-5411357
- AVID-2023-v009: AI Vulnerability Database. https://avidml.org/database/avid-2023-v009/

### Standards
- OWASP ASVS V5: Validation, Sanitization and Encoding. https://owasp-aasvs4.readthedocs.io/en/latest/V5.html
- NVIDIA NeMo Guardrails Security Guidelines. https://github.com/NVIDIA-NeMo/Guardrails/blob/main/docs/security/guidelines.md

### LLMTrace Internal Research
- `docs/research/security-state-of-art-2026.md` -- Comprehensive security literature survey and gap analysis
- `docs/research/benchmarks-and-tools-landscape.md` -- Benchmark evaluation and tool comparison
- `docs/research/llmtrace-defence-pipeline-design.md` -- Defence pipeline architecture specification
- `docs/research/owasp-genai-top10-2025-references.md` -- OWASP Top 10 reference catalog
- `docs/security/OWASP_GENAI_TOP10_2025_ARCHITECTURE.md` -- Security-engineer detailed code-level analysis with 40+ specific code references
