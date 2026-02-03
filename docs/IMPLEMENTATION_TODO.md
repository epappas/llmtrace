# LLMTrace Implementation TODO — RALPH Loops

**Generated from:** `docs/FEATURE_ROADMAP.md` gap analysis  
**Date:** 2026-02-02  
**Methodology:** RALPH loops — each loop is a self-contained deliverable, spawned to a coding agent, reviewed by Rust engineer agent before merge.

---

## ⚠️ MANDATORY QUALITY POLICY

Every loop must adhere to:
1. **TODO checklist first** — write down all sub-tasks before coding
2. **Verify before claiming done** — run actual commands, paste actual output
3. **ZERO TOLERANCE** — no placeholders, TODOs, mocks, stubs, or fake code
4. **DRY / SOLID / KISS** — clean, robust, simple
5. **NEVER LIE** — no fabricated results
6. **Quality gates**: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test --workspace`

---

## Status Legend

- ⬜ Not started
- 🔄 In progress
- ✅ Done
- 🔍 Under review
- ❌ Blocked

---

## Phase 1: Input Security Hardening

### Loop R-IS-01: FPR-Aware Threshold Calibration (IS-006)
**Priority:** P0 | **Complexity:** Medium
**Deps:** R8 thresholds.rs (done)

**Tasks:**
1. Implement threshold calibration module that takes labeled data (benign + malicious samples) and computes optimal thresholds for target FPR rates (0.1%, 0.5%, 1%)
2. Add binary search / grid search algorithm to find threshold that achieves target FPR on a calibration dataset
3. Integrate with existing `ResolvedThresholds` and `OperatingPoint` system
4. Add evaluation output showing TPR at each FPR operating point
5. Unit tests with synthetic labeled data demonstrating calibration correctness

**Status:** ✅ Done — `fpr_monitor.rs` (909 lines)

---

### Loop R-IS-02: Over-Defense Mitigation — MOF Training Pipeline (IS-001, IS-002, IS-003)
**Priority:** P0 | **Complexity:** High  
**Deps:** ML pipeline, Candle DeBERTa

**Tasks:**
1. Implement token-wise bias detection: feed each vocabulary token individually through the DeBERTa model, identify tokens with false-positive bias
2. Implement adaptive debiasing data generation: generate benign samples using combinations of 1-3 biased tokens
3. Implement MOF (Mitigating Over-defense for Free) retraining pipeline: train from scratch on combined original + debiasing data
4. Integration with existing ensemble analyzer
5. Tests validating bias detection identifies known problematic tokens

**Status:** ⬜

---

### Loop R-IS-03: Multi-Turn Extraction Detection (IS-016)
**Priority:** P1 | **Complexity:** High

**Tasks:**
1. Implement session-aware analysis that tracks conversation patterns across requests
2. Detect gradual system prompt extraction attempts (small information gain per turn)
3. Add conversation state tracking with configurable window size
4. Implement progressive confidence scoring across turns
5. Tests with multi-turn extraction attack scenarios

**Status:** ✅ Done — `session_analyzer.rs` (1,090 lines)

---

### Loop R-IS-04: Automated Jailbreak Defense (IS-014)
**Priority:** P1 | **Complexity:** High

**Tasks:**
1. Implement genetic algorithm-based jailbreak template detection (GPTFuzz-style defense)
2. Add mutation-aware pattern matching that detects template variations
3. Implement template similarity scoring against known jailbreak templates
4. Add configurable jailbreak template database
5. Tests with known jailbreak mutations and edge cases

**Status:** ⬜

---

### Loop R-IS-05: Long-Context Jailbreak Detection (IS-013)
**Priority:** P2 | **Complexity:** High

**Tasks:**
1. Implement context-length-aware analysis that detects attacks exploiting extended context windows
2. Add position-aware injection detection (attacks hidden deep in long prompts)
3. Implement sliding window analysis for long contexts
4. Tests with attacks at various positions in long contexts

**Status:** ⬜

---

### Loop R-IS-06: Multi-Language Trigger Detection (IS-041)
**Priority:** P2 | **Complexity:** High

**Tasks:**
1. Add trigger patterns for Chinese, Russian, Arabic, and other languages
2. Implement language detection for input text
3. Route to appropriate language-specific pattern set
4. Tests with multilingual injection attempts

**Status:** ⬜

---

### Loop R-IS-07: Data Format Coverage Expansion (IS-040)
**Priority:** P2 | **Complexity:** Medium

**Tasks:**
1. Implement detection for all 17 data formats (Email, Document, Chat, JSON, Code, Markdown, HTML, URL, Base64, Table, XML, CSV, Config File, Log File, Image Link, Translation, Website)
2. Add format-aware injection detection (injection patterns specific to each format)
3. Tests for each format type

**Status:** ⬜

---

### Loop R-IS-08: Adversarial ML Robustness (IS-024, IS-025, IS-026, IS-027, IS-028, IS-029)
**Priority:** P1 | **Complexity:** High

**Tasks:**
1. Implement TextFooler/BERT-Attack/BAE evasion resistance through input normalisation
2. Add adaptive thresholding that lowers threshold when evasion indicators are detected
3. Implement multi-pass normalisation: aggressive + conservative + semantic-preserving passes
4. Add confidence calibration via Platt scaling
5. Tests with adversarial text attack variants

**Status:** ✅ Done — `adversarial_defense.rs` (1,437 lines)

---

## Phase 2: Output Security

### Loop R-OS-01: HaluGate-Style Token-Level Hallucination Detection (OS-001, OS-003, OS-004)
**Priority:** P1 | **Complexity:** High

**Tasks:**
1. Implement token-level hallucination detection using ModernBERT token classification
2. Add NLI explanation layer classifying flagged spans (CONTRADICTION/NEUTRAL/ENTAILMENT)
3. Upgrade sentinel pre-classifier from heuristic to ML-based (ModernBERT)
4. Implement tool-call result as ground truth for fact-checking (leverage proxy position)
5. Tests with known hallucination examples

**Status:** ⬜

---

### Loop R-OS-02: Content Safety — Llama Guard 3 + Bias Detection (OS-021, OS-022)
**Priority:** P1 | **Complexity:** Medium

**Tasks:**
1. Integrate Llama Guard 3 as multi-label safety classifier (14 harm categories)
2. Implement bias detection for discriminatory content in responses
3. Add configurable harm category filtering
4. Tests for each harm category

**Status:** ⬜

---

### Loop R-OS-03: Streaming Content Monitor (OS-010, OS-013)
**Priority:** P2 | **Complexity:** High

**Tasks:**
1. Implement purpose-built partial-sequence detection for streaming (not just re-running full-text)
2. Add progressive confidence scoring that increases as more tokens arrive
3. Implement hierarchical consistency-aware learning for incomplete-sequence judgment
4. Tests with streaming token sequences at various completion percentages

**Status:** ⬜

---

### Loop R-OS-04: Code Security Enhancement — CodeShield-Style (OS-030, OS-031)
**Priority:** P1 | **Complexity:** Large

**Tasks:**
1. Expand code_security.rs to CodeShield-level analysis depth
2. Add Semgrep rule integration for leveraging existing rule database
3. Improve language coverage and detection accuracy
4. Tests with real-world vulnerable code patterns

**Status:** ⬜

---

### Loop R-OS-05: Language & Sentiment Detection (OS-023, OS-024)
**Priority:** P3 | **Complexity:** Low

**Tasks:**
1. Implement language detection for unexpected language switches in outputs
2. Add sentiment analysis for negative/manipulative sentiment detection
3. Tests with multilingual outputs and manipulative content

**Status:** ⬜

---

## Phase 3: Agent Security

### Loop R-AS-01: Tool Result Parsing — ParseData + CheckTool (AS-004, AS-006, AS-007)
**Priority:** P1 | **Complexity:** High

**Tasks:**
1. Implement ParseData module for extracting minimal required data from tool results
2. Implement CheckTool module detecting if tool output triggers unexpected tool calls
3. Add format constraint validation for tool outputs
4. Integrate with existing tool-boundary firewalling
5. Tests with real tool output scenarios

**Status:** ✅ Done — `result_parser.rs` (1,123 lines)

---

### Loop R-AS-02: Plan-Then-Execute Pattern Detection (AS-011, AS-014)
**Priority:** P2 | **Complexity:** High

**Tasks:**
1. Implement plan deviation detection in request patterns
2. Add pattern compliance monitoring for declared security patterns
3. Tests with plan-then-execute sequences and deviations

**Status:** ⬜

---

### Loop R-AS-03: Dual LLM Routing + Trust-Based Routing (AS-013, AS-016)
**Priority:** P2 | **Complexity:** High

**Tasks:**
1. Implement dual LLM routing for trusted/untrusted data to different endpoints
2. Add trust classification for data sources
3. Implement routing logic based on trust levels
4. Tests with mixed trust-level inputs

**Status:** ⬜

---

### Loop R-AS-04: Multi-Agent Defense — Coordinator + Guard (AS-020, AS-021, AS-023, AS-024)
**Priority:** P1 | **Complexity:** High

**Tasks:**
1. Implement Coordinator agent for pre-input classification and threat assessment
2. Implement Guard agent for post-generation validation and output sanitisation
3. Add second opinion pass for borderline cases (score 0.6-0.8)
4. Implement centralised policy store accessed by all modules
5. Tests achieving <5% ASR on attack scenarios

**Status:** ✅ Done — `multi_agent.rs` (1,560 lines)

---

### Loop R-AS-05: Multi-Step Action Correlation + Multi-Turn Persistence (AS-025, AS-026)
**Priority:** P1-P2 | **Complexity:** High

**Tasks:**
1. Implement multi-step attack sequence detection across requests
2. Add multi-turn persistence detection for gradual bypass attempts
3. Implement cross-request state tracking
4. Tests with multi-step attack scenarios

**Status:** ✅ Done — `action_correlator.rs` (1,674 lines)

---

### Loop R-AS-06: MCP Protocol Monitoring (AS-030, AS-035, AS-036)
**Priority:** P0-P1 | **Complexity:** High

**Tasks:**
1. Implement MCP protocol monitoring for manipulation and server-side attacks
2. Add Toxic Agent Flow defense for GitHub MCP vulnerability
3. Implement ToolHijacker defense for tool selection manipulation
4. Validate MCP server identity, monitor suspicious tool registrations
5. Tests with MCP attack scenarios

**Status:** ✅ Done — `mcp_monitor.rs` (1,145 lines)

---

### Loop R-AS-07: A2A/ANP Protocol Security (AS-031, AS-032, AS-033, AS-034)
**Priority:** P1-P2 | **Complexity:** High

**Tasks:**
1. Implement A2A protocol security monitoring
2. Add ANP protocol vulnerability detection
3. Implement dynamic trust management with cryptographic provenance
4. Add inter-agent trust verification
5. Tests with protocol attack scenarios

**Status:** ⬜

---

## Phase 4: ML Pipeline & Architecture

### Loop R-ML-01: Model Ensemble Diversification (ML-002, ML-003, ML-006)
**Priority:** P1 | **Complexity:** Medium

**Tasks:**
1. Integrate InjecGuard model (DeBERTa-v3-base + MOF architecture)
2. Integrate Meta Prompt Guard 2 (86M and 22M variants)
3. Implement multi-model ensemble voting (majority vote, weighted average, max-severity)
4. Make models independently loadable/optional
5. Tests for ensemble voting strategies

**Status:** ✅ Done — commit `10a2369`

---

### Loop R-ML-02: Joint End-to-End Fusion Training (ML-001, ML-014)
**Priority:** P1 | **Complexity:** High

**Tasks:**
1. Implement training pipeline for fusion FC layer with labeled data
2. Curate training dataset (target: 61k benign + 16k injection samples)
3. Extract DeBERTa embeddings + heuristic features → train FC layers
4. Replace random-weight FusionClassifier with trained version
5. Evaluation showing >6% F1 improvement on hard datasets

**Status:** ⬜

---

### Loop R-ML-03: Adversarial Training Integration (ML-012, ML-013)
**Priority:** P1 | **Complexity:** High

**Tasks:**
1. Implement fine-tuning pipeline on TextAttack-generated adversarial examples
2. Add robust training with character injection variants (Unicode evasion samples)
3. Evaluate ASR reduction post-adversarial training
4. Tests validating improved robustness

**Status:** ⬜

---

### Loop R-ML-04: ONNX Runtime + Quantisation Support (ML-020, ML-021, ML-022)
**Priority:** P2-P3 | **Complexity:** Medium

**Tasks:**
1. Add ONNX runtime support for optimised inference
2. Implement INT8/INT4 quantised model loading
3. Add batched inference for GPU utilisation
4. Benchmarks comparing Candle vs ONNX latency

**Status:** ⬜

---

### Loop R-ML-05: PIGuard + Model Hot-Swapping (ML-004, ML-007)
**Priority:** P1-P3 | **Complexity:** Medium

**Tasks:**
1. Integrate PIGuard model (DeBERTa + MOF training)
2. Implement model hot-swapping without proxy restart
3. Tests for hot-swap correctness under load

**Status:** ⬜

---

## Phase 5: Multimodal Security

### Loop R-MM-01: Image Injection Detection + OCR Pipeline (MM-001, MM-004)
**Priority:** P1 | **Complexity:** High

**Tasks:**
1. Implement OCR-based text extraction from images in API requests
2. Route extracted text through existing injection detection pipeline
3. Add image adversarial perturbation detection
4. Tests with text-in-image injection samples

**Status:** ⬜

---

### Loop R-MM-02: Audio + Cross-Modal Security (MM-002, MM-003, MM-005)
**Priority:** P2-P3 | **Complexity:** High

**Tasks:**
1. Implement audio injection detection for hidden commands
2. Add cross-modal consistency checking
3. Implement steganography detection for images/audio
4. Tests with multi-modal attack vectors

**Status:** ⬜

---

## Phase 6: Privacy & Data Protection

### Loop R-PR-01: Advanced PII — Multi-Language + Custom Entities (PR-006, PR-008)
**Priority:** P2 | **Complexity:** High

**Tasks:**
1. Extend PII detection to CJK, Arabic, and other non-Latin scripts
2. Implement architecture for user-defined PII entity type plugins
3. Tests with multi-language PII samples

**Status:** ⬜

---

### Loop R-PR-02: RAG Security — Membership Inference + Poisoning (PR-001, PR-004, PR-005, PR-010)
**Priority:** P2 | **Complexity:** High

**Tasks:**
1. Implement S2MIA defense for RAG databases (noise injection in similarity scores)
2. Add vector/embedding poisoning detection
3. Implement RAG retrieval anomaly monitoring
4. Add memory poisoning detection (MINJA-style)
5. Tests with RAG attack scenarios

**Status:** ⬜

---

### Loop R-PR-03: Cross-Session State Integrity (PR-011)
**Priority:** P2 | **Complexity:** High

**Tasks:**
1. Implement persistent state manipulation detection across sessions
2. Add session integrity verification
3. Tests with cross-session attack scenarios

**Status:** ⬜

---

## Phase 7: Evaluation & Benchmarking

### Loop R-EV-01: AgentDojo + InjecAgent Evaluation (EV-001, EV-003)
**Priority:** P0-P1 | **Complexity:** Medium

**Tasks:**
1. Implement AgentDojo evaluation runner (97 environments)
2. Implement InjecAgent evaluation runner
3. Add results formatting and comparison tables
4. Baseline evaluation of current LLMTrace

**Status:** ⬜

---

### Loop R-EV-02: Comprehensive Benchmark Suite (EV-004, EV-005, EV-006, EV-007, EV-008, EV-011, EV-012)
**Priority:** P1-P2 | **Complexity:** Medium

**Tasks:**
1. Implement ASB evaluation runner
2. Implement WASP evaluation runner
3. Implement CyberSecEval 2 evaluation (251 samples)
4. Implement HPI_ATTACK_DATASET evaluation (400 instances)
5. Implement safeguard-v2 (1300 samples) and deepset-v2 (354 samples) evaluation
6. Add MLCommons AILuminate Jailbreak Benchmark
7. CI-integrated automated benchmark runner (EV-009)

**Status:** ⬜

---

## Phase 8: System Architecture

### Loop R-SA-01: Policy/Rules Language (SA-001)
**Priority:** P2 | **Complexity:** High

**Tasks:**
1. Design and implement declarative policy specification language (Colang/OPA-style)
2. Add policy parser and runtime evaluator
3. Integration with existing configuration system
4. Tests with complex policy scenarios

**Status:** ⬜

---

### Loop R-SA-02: Taint Tracking + Blast Radius Reduction (SA-003, SA-004)
**Priority:** P2 | **Complexity:** High

**Tasks:**
1. Implement taint tracking for untrusted data flow through LLM pipeline
2. Add least-privilege enforcement for LLM tool access
3. Tests with data flow scenarios

**Status:** ⬜

---

### Loop R-SA-03: Backdoor + Data Poisoning Detection (SA-005, SA-006, SA-007)
**Priority:** P2 | **Complexity:** High

**Tasks:**
1. Implement prompt-level and parameter-level backdoor detection
2. Add composite backdoor detection (CBA-style distributed triggers)
3. Implement PoisonedRAG data poisoning pattern detection
4. Tests with backdoor and poisoning scenarios

**Status:** ⬜

---

### Loop R-SA-04: Social Engineering + Contagious Blocking Defense (SA-008, SA-009)
**Priority:** P3 | **Complexity:** High

**Tasks:**
1. Implement social engineering tactic detection (SE-VSim-style)
2. Add contagious recursive blocking defense (Corba attacks)
3. Tests with social engineering and recursive blocking scenarios

**Status:** ⬜

---

## Execution Order (Priority-Based)

### Batch 1 — P0 Critical (Now)
1. ✅ R-IS-01: FPR-Aware Threshold Calibration — `fpr_monitor.rs`
2. ✅ R-ML-01: Model Ensemble Diversification — commit `10a2369`
3. R-IS-02: MOF Training Pipeline
4. ✅ R-AS-06: MCP Protocol Monitoring — `mcp_monitor.rs`
5. R-EV-01: AgentDojo + InjecAgent Evaluation

### Batch 2 — P1 High Priority
6. ✅ R-IS-03: Multi-Turn Extraction Detection — `session_analyzer.rs`
7. R-IS-04: Automated Jailbreak Defense
8. ✅ R-IS-08: Adversarial ML Robustness — `adversarial_defense.rs`
9. R-OS-01: HaluGate Token-Level Hallucination
10. R-OS-02: Llama Guard 3 + Bias Detection
11. R-OS-04: CodeShield-Style Code Security
12. ✅ R-AS-01: Tool Result Parsing — `result_parser.rs`
13. ✅ R-AS-04: Multi-Agent Defense — `multi_agent.rs`
14. ✅ R-AS-05: Multi-Step Correlation — `action_correlator.rs`
15. R-ML-02: Joint Fusion Training
16. R-ML-03: Adversarial Training
17. R-ML-05: PIGuard + Hot-Swap
18. R-MM-01: Image Injection + OCR
19. R-EV-02: Comprehensive Benchmarks

### Batch 3 — P2 Medium Priority
20. R-IS-05: Long-Context Jailbreak
21. R-IS-06: Multi-Language Triggers
22. R-IS-07: Data Format Coverage
23. R-OS-03: Streaming Content Monitor
24. R-AS-02: Plan-Then-Execute
25. R-AS-03: Dual LLM Routing
26. R-AS-07: A2A/ANP Protocol Security
27. R-ML-04: ONNX + Quantisation
28. R-MM-02: Audio + Cross-Modal
29. R-PR-01: Multi-Language PII
30. R-PR-02: RAG Security
31. R-PR-03: Cross-Session Integrity
32. R-SA-01: Policy Language
33. R-SA-02: Taint Tracking

### Batch 4 — P3 Low Priority
34. R-OS-05: Language & Sentiment
35. R-SA-03: Backdoor Detection
36. R-SA-04: Social Engineering Defense

---

## Metrics Tracking

| Metric | Current | Phase 1 Target | Phase 2 Target | Phase 3 Target |
|--------|---------|----------------|----------------|----------------|
| Over-defense accuracy | Unknown | Measured | >85% | >90% |
| FPR at 0.1% | Unknown | Baseline | <5% miss rate | <2% miss rate |
| Emoji smuggling ASR | ✅ Closed | ✅ 0% | ✅ 0% | ✅ 0% |
| TextFooler evasion ASR | ~46% | Measured | <10% | <5% |
| Tool-boundary ASR | N/A | N/A | <1% | <0.5% |
| Multi-agent ASR | N/A | N/A | <5% | <1% |
| Ensemble F1 (deepset-v2) | Unknown | Baseline | >90% | >93% |
