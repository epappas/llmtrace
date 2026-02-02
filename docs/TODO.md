# LLMTrace Implementation TODO

**Generated from:** `docs/FEATURE_ROADMAP.md`  
**Updated:** 2026-02-02  
**Methodology:** RALPH loops — each loop spawns a Claude Code agent with strict quality gates, reviewed by lead engineer before merge.

---

## Status Legend
- ⬜ Not started
- 🔄 In progress
- ✅ Done
- ❌ Blocked

---

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
> Establish over-defense baseline and evaluation framework

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| IS-004 | NotInject-style over-defense benchmark dataset (339 samples, 3 difficulty levels) | Low | ✅ `33b3f55` |
| IS-005 | Three-dimensional evaluation metrics (benign/malicious/over-defense) | Low | ✅ `33b3f55` |
| EV-002 | NotInject evaluation runner | Low | ✅ `33b3f55` |
| EV-010 | Paper-table output format for results | Low | ✅ `33b3f55` |

### Loop 3 — FPR-Aware Threshold Optimisation
> Evaluate at deployment-realistic FPR operating points

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| IS-006 | FPR-aware threshold optimisation — evaluate at 0.1%, 0.5%, 1% FPR | Medium | ⬜ |
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
| IS-017 | Context window flooding detection | Low | ⬜ |

---

## Phase 2: Major Features

### Loop 7 — Tool-Boundary Firewalling
> The "minimize & sanitize" approach — 0% ASR in papers

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| AS-001 | Tool-Input Firewall (Minimizer) — filter sensitive info from tool args | High | ⬜ |
| AS-002 | Tool-Output Firewall (Sanitizer) — remove malicious content from tool responses | High | ⬜ |
| AS-003 | Tool context awareness — user task + tool description for security decisions | Medium | ⬜ |
| AS-005 | Format constraint validation — enforce format/logic rules on tool outputs | Medium | ⬜ |

### Loop 8 — Model Ensemble Diversification
> Replace single-model reliance with multi-architecture ensemble

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| ML-002 | InjecGuard model integration | Medium | ⬜ |
| ML-003 | Meta Prompt Guard 2 integration (86M + 22M) | Medium | ⬜ |
| ML-006 | Multi-model ensemble voting with diverse architectures | Medium | ⬜ |

### Loop 9 — Action-Selector Pattern Enforcement
> Provable security patterns at proxy level

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| AS-010 | Action-Selector pattern — enforce action allowlists at proxy level | Medium | ⬜ |
| AS-012 | Context-Minimization — strip unnecessary context | Medium | ⬜ |

### Loop 10 — Multi-Agent Defense Coordination
> Coordinator + Guard architecture for 0% ASR

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| AS-020 | Coordinator agent — pre-input classification | High | ⬜ |
| AS-021 | Guard agent — post-generation validation | High | ⬜ |
| AS-023 | Second opinion pass for borderline cases | Medium | ⬜ |
| AS-024 | Policy store — centralised security rules | Medium | ⬜ |

### Loop 11 — MCP Protocol Monitoring
> First-mover in protocol-level security

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| AS-030 | MCP monitoring — detect manipulation and server-side attacks | High | ⬜ |
| AS-035 | Toxic Agent Flow defense — GitHub MCP vulnerability | Medium | ⬜ |
| AS-036 | ToolHijacker defense — tool selection manipulation | High | ⬜ |

### Loop 12 — Advanced Prompt Injection Detection
> Synonym expansion, lemmatisation, P2SQL

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| IS-010 | Synonym expansion for attack patterns (WordNet-style) | Medium | ⬜ |
| IS-011 | Lemmatisation before pattern matching | Low | ⬜ |
| IS-012 | P2SQL injection detection | Medium | ⬜ |
| IS-018 | "Important Messages" header attack hardening | Low | ⬜ |

### Loop 13 — Hallucination Detection Upgrade
> HaluGate-style token-level detection

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| OS-001 | Token-level hallucination detection (ModernBERT) | High | ⬜ |
| OS-003 | ModernBERT sentinel pre-classifier | Medium | ⬜ |
| OS-004 | Tool-call result as ground truth for fact-checking | Medium | ⬜ |

### Loop 14 — Content Safety Expansion
> Llama Guard integration, bias detection

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| OS-022 | Llama Guard 3 integration (14 harm categories) | Medium | ⬜ |
| OS-021 | Bias detection in responses | Medium | ⬜ |

### Loop 15 — Fusion Training Pipeline
> Train the fusion classifier with real data

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| ML-001 | Joint end-to-end training for fusion FC layer | High | ⬜ |
| ML-014 | Curated training dataset (61k benign + 16k injection) | Medium | ⬜ |

### Loop 16 — Benchmark Evaluation Suite
> Evaluate against all major benchmarks

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| EV-001 | AgentDojo evaluation (97 environments) | Medium | ⬜ |
| EV-003 | InjecAgent evaluation | Medium | ⬜ |
| EV-008 | HPI_ATTACK_DATASET evaluation (400 instances) | Low | ⬜ |
| EV-009 | Automated CI-integrated benchmark runner | Medium | ⬜ |
| EV-011 | safeguard-v2 evaluation (1300 samples) | Low | ⬜ |
| EV-012 | deepset-v2 evaluation (354 samples) | Low | ⬜ |

---

## Phase 3: Research Frontier

### Loop 17 — Multimodal Security
| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| MM-001 | Image injection detection | High | ⬜ |
| MM-004 | OCR-based text extraction from images | Medium | ⬜ |

### Loop 18 — Protocol Security (A2A/ANP)
| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| AS-031 | A2A protocol security | High | ⬜ |
| AS-032 | ANP protocol security | High | ⬜ |
| AS-033 | Dynamic trust management | High | ⬜ |

### Loop 19 — Streaming Content Monitor
| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| OS-010 | Purpose-built partial-sequence detection models | High | ⬜ |
| OS-013 | Progressive confidence scoring | Medium | ⬜ |

### Loop 20 — Advanced Privacy
| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| PR-001 | Membership inference defense | High | ⬜ |
| PR-010 | Memory poisoning detection (MINJA) | High | ⬜ |
| PR-011 | Cross-session state integrity | High | ⬜ |

### Loop 21 — Policy Language
| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| SA-001 | Declarative policy specification (Colang/OPA-style) | High | ⬜ |
| SA-003 | Taint tracking | High | ⬜ |

### Loop 22 — Adversarial ML Robustness
| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| IS-024 | AML evasion resistance (TextFooler, BERT-Attack, BAE) | High | ⬜ |
| IS-025 | Ensemble diversification against transferability | High | ⬜ |
| ML-012 | Adversarial training on TextAttack samples | High | ⬜ |
| IS-029 | Confidence calibration (Platt scaling) | Medium | ⬜ |

---

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
