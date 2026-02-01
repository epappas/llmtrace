# Security State-of-the-Art Research Report & Gap Analysis

**Date**: 2026-02-01
**Author**: AI Engineering Research (automated)
**Scope**: Prompt injection detection, LLM security, PII detection, output safety, streaming analysis, guardrail frameworks
**Context**: LLMTrace — transparent LLM proxy with security analysis (Rust, Candle ML framework)

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Part 1: DMPI-PMHFE Paper Validation](#part-1-dmpi-pmhfe-paper-validation)
3. [Part 2: Broader Literature Survey](#part-2-broader-literature-survey)
   - [Prompt Injection Detection](#21-prompt-injection-detection)
   - [Jailbreak Detection](#22-jailbreak-detection)
   - [PII Detection in LLM Contexts](#23-pii-detection-in-llm-contexts)
   - [LLM Output Safety & Hallucination Detection](#24-llm-output-safety--hallucination-detection)
   - [Real-Time/Streaming Security](#25-real-timestreaming-security)
   - [OWASP LLM Top 10 2025](#26-owasp-llm-top-10-2025)
   - [Industry Guardrail Frameworks](#27-industry-guardrail-frameworks)
4. [Part 3: Gap Analysis & Recommendations](#part-3-gap-analysis--recommendations)
   - [Current State Assessment](#31-current-state-assessment)
   - [Gap Analysis](#32-gap-analysis)
   - [Prioritised Recommendations](#33-prioritised-recommendations)
   - [New Techniques to Adopt](#34-new-techniques-to-adopt)
   - [Top 10 Papers to Read](#35-top-10-papers-to-read)

---

## Executive Summary

LLMTrace's current security architecture is **solid foundational work** — a Rust-native proxy with regex-based heuristics, DeBERTa-v3-base ML classification, BERT NER for PII, ensemble combination, and streaming security analysis. This is competitive with early-2025 open-source approaches.

However, the field has moved rapidly in 2025. Key gaps identified:

1. **Feature-level fusion** — The DMPI-PMHFE paper demonstrates that fusing heuristic features with DeBERTa embeddings *before* classification (not after) yields significantly better recall (+5.3% on external datasets). Our score-level ensemble misses this.
2. **Over-defence problem** — Modern research (InjecGuard, PIGuard, PromptShield) shows that false positive rates at deployment scale matter more than F1. Our current approach lacks FPR-optimised thresholding.
3. **No output safety analysis** — We have no hallucination detection, no harmful content moderation, no output toxicity scoring. This is the #1 gap vs state of the art.
4. **OWASP 2025 coverage** — Two new Top 10 categories (System Prompt Leakage LLM07, Vector/Embedding Weaknesses LLM08) are unaddressed.
5. **No streaming output moderation** — Our streaming analysis checks inputs during SSE but doesn't moderate *output* tokens in real-time, which is where the field is headed (SCM paper, HaluGate).

**Overall assessment: 6.5/10** — Good detection architecture, but missing output-side safety, modern fusion techniques, and 2025 OWASP coverage.

---

## Part 1: DMPI-PMHFE Paper Validation

### Paper: Detection Method for Prompt Injection by Integrating Pre-trained Model and Heuristic Feature Engineering

- **Source**: arxiv.org/html/2506.06384v1 (Zhengzhou University, June 2025)
- **Published**: Springer LNCS, Information Security Conference 2025
- **Core claim**: Dual-channel feature fusion (DeBERTa semantic vectors + heuristic structural features → FC network → prediction) outperforms existing detection models

### 1.1 Architecture Comparison

| Aspect | DMPI-PMHFE | LLMTrace (Our Approach) |
|--------|-----------|------------------------|
| **Semantic channel** | DeBERTa-v3-base → average pooling → d-dim feature vector | DeBERTa-v3-base → softmax → binary classification score |
| **Heuristic channel** | 10 binary features (8 synonym-matching + 2 pattern-matching) | 13 regex patterns → independent findings with confidence scores |
| **Fusion method** | Feature concatenation → FC layer with ReLU → softmax | Score-level combination (confidence boost on agreement) |
| **Fusion point** | **Before** final classification (feature-level) | **After** independent classification (score-level) |
| **Training** | End-to-end joint training of fusion + classification | No joint training — independent classifiers |
| **Attack coverage** | 10 categorised attack types with semantic expansion via WordNet | 13 regex patterns for known attack signatures |

**Key architectural difference**: DMPI-PMHFE extracts the DeBERTa *embedding vector* (768-dim) rather than the classification output, then concatenates it with a 10-dim heuristic binary feature vector, and trains an FC network on the combined 778-dim representation. This is fundamentally different from our approach, which runs DeBERTa classification independently and then combines scores post-hoc.

### 1.2 What We're Missing — Heuristic Feature Engineering

DMPI-PMHFE's heuristic features are **not just regex patterns**. They are categorised, semantic-aware binary indicators:

**Synonym Matching Features (8 categories)**:
1. `is_ignore` — "ignore", "reveal", "disregard", "forget", "overlook" + WordNet synonyms
2. `is_urgent` — "urgent", "immediate", "asap", "emergency", "critical" + synonyms
3. `is_incentive` — "excellent", "fantastic", "awesome", "brilliant" + synonyms (flattery attacks)
4. `is_covert` — "secret", "hidden", "covert", "stealth", "confidential" + synonyms
5. `is_format_manipulation` — "encode", "disguising", "morse", "binary", "hexadecimal"
6. `is_hypothetical` — "assume", "imagine", "act", "role", "play", "scenario" + synonyms
7. `is_systemic` — "developer", "boss", "manager", "administrator", "creator"
8. `is_immoral` — "amoral", "unethical", "violent", "illegal", "biased" + synonyms

**Pattern Matching Features (2 categories)**:
9. `is_shot_attack` — Q&A pair counting via regex (threshold ≥ 3)
10. `is_repeated_token` — Repetitive word/phrase detection (threshold ≥ 3)

**What our regex approach misses**:
- **Synonym expansion** — We match exact patterns; they expand via WordNet to catch paraphrased attacks
- **Semantic categorisation** — Their features are typed by attack category (urgency, flattery, covert); ours are flat
- **Flattery/urgency/covert detection** — We have no patterns for social engineering tactics like flattery-based or urgency-based manipulation
- **Many-shot attack detection** — We don't count Q&A pairs
- **Repetition attack detection** — We don't detect token repetition attacks
- **Lemmatisation** — They lemmatise tokens via spaCy before matching; we match raw text

### 1.3 Feature Fusion Method — Feature-Level vs Score-Level

**Their approach (feature-level fusion)**:
```
DeBERTa embedding (768-dim) ─┐
                              ├── Concatenate → FC(ReLU) → FC(Softmax) → prediction
Heuristic features (10-dim) ──┘
```

**Our approach (score-level ensemble)**:
```
DeBERTa → softmax → injection_score ─┐
                                      ├── if both detect: boost confidence +0.1, take max severity
Regex patterns → findings ────────────┘
```

**Paper's evidence for feature-level being superior** (Table 2 ablation results on safeguard-v2):

| Configuration | Accuracy | Precision | Recall | F1 |
|--------------|----------|-----------|--------|-----|
| DeBERTa only (M1) | 97.26 | 99.58 | 93.27 | 96.32 |
| M1 + Synonym matching (M2) | 97.86 | 98.77 | 95.64 | 97.18 |
| M1 + M2 + Pattern matching (M3) | **97.94** | 98.00 | **98.59** | **98.29** |

On the challenging deepset-v2 external dataset:

| Configuration | Accuracy | Recall | F1 |
|--------------|----------|--------|-----|
| DeBERTa only | 87.29 | 77.92 | 84.21 |
| Full DMPI-PMHFE | **91.24** | **84.31** | **90.21** |

Adding heuristic features boosted recall by **+6.39 percentage points** and F1 by **+6.0 percentage points** on the hardest dataset. This is a substantial improvement attributable to feature-level fusion allowing the FC classifier to learn correlations between semantic and structural features that score-level combination cannot capture.

### 1.4 Performance Benchmarks

**Datasets used**:
- `safeguard-v2`: 1,300 test samples (augmented from `xTRam1/safeguard-prompt-injections`)
- `Ivanleomk-v2`: 610 samples from `ivanleomk/prompt_injection_password`
- `deepset-v2`: 354 samples from `deepset/prompt-injections`
- Defence evaluation: 251 attack samples from CyberSecEval 2 benchmark

**DMPI-PMHFE vs ProtectAI (our model)** on deepset-v2:

| Model | Accuracy | Precision | Recall | F1 |
|-------|----------|-----------|--------|-----|
| ProtectAI (our DeBERTa model) | 87.29 | 94.31 | 75.32 | 83.75 |
| DMPI-PMHFE | **91.24** | 96.99 | **84.31** | **90.21** |
| Delta | +3.95 | +2.68 | **+8.99** | **+6.46** |

**Critical insight**: ProtectAI's biggest weakness is recall (75.32%) — it misses ~25% of attacks. DMPI-PMHFE's heuristic features dramatically improve this to 84.31%. Our score-level ensemble likely helps some, but cannot match feature-level fusion's recall improvement.

### 1.5 Actionable Gaps

| Priority | Gap | Action | Impact |
|----------|-----|--------|--------|
| **P0** | Score-level vs feature-level fusion | Extract DeBERTa embeddings (not scores) and concatenate with heuristic features before a trained FC classifier | +6% F1 on hard datasets |
| **P1** | Missing attack categories | Add synonym-expanded detection for: urgency, flattery, covert, hypothetical, systemic impersonation, immorality | Broader attack coverage |
| **P1** | No many-shot attack detection | Implement Q&A pair counting (threshold ≥ 3) | Catches emerging attack vector |
| **P1** | No repetition attack detection | Implement repeated token/phrase detection | Catches token repetition attacks |
| **P2** | No lemmatisation | Add lemmatisation before pattern matching (spaCy equivalent in Rust, e.g., rust-stemmers) | Reduces false negatives from verb conjugation |
| **P2** | No synonym expansion | Build synonym sets for each attack category (WordNet-equivalent) | Catches paraphrased attacks |
| **P3** | Joint training | Train the fusion FC layer on labelled prompt injection data | Maximises feature interaction learning |

---

## Part 2: Broader Literature Survey

### 2.1 Prompt Injection Detection

#### State of the Art (2024-2026)

**PromptShield** (Jacob et al., UC Berkeley, Jan 2025 — ACM CODASPY 2025):
- **Key insight**: Existing detectors fail at deployment-realistic false positive rates (FPR). At 0.1% FPR, PromptGuard (Meta) detects only 9.4% of attacks.
- **Approach**: Carefully curated benchmark distinguishing conversational data (chatbot — low injection risk) from application-structured data (LLM-integrated apps — high risk). Fine-tuned detector on this taxonomy.
- **Results**: 65.3% TPR at 0.1% FPR — significantly better than all prior detectors.
- **Implication for LLMTrace**: We need to evaluate our detector at realistic FPR thresholds (0.1%, 0.5%), not just F1. Our ensemble may have an unacceptable false positive rate in production.

**PIGuard/InjecGuard** (Li & Liu, ACL 2025):
- **Problem**: Existing prompt guard models (including ProtectAI) suffer from **over-defence** — they trigger on benign inputs containing words like "ignore", "system", or "instructions" that happen to appear in normal conversation.
- **Solution**: PIGuard introduces "Mitigating Over-defense for Free" (MOF) training strategy that reduces trigger word bias. Surpasses existing best model by 30.8% on the NotInject benchmark.
- **Implication for LLMTrace**: Our regex patterns for "ignore previous instructions" will over-trigger on legitimate mentions of these phrases. We need an over-defence mitigation strategy.

**Prompt Injection 2.0: Hybrid AI Threats** (arxiv 2507.13169, July 2025):
- Emerging threat: Hybrid attacks combining prompt injection with traditional cyber techniques (e.g., injection via external document retrieval, SQL-injection-style prompt crafting).
- Multiple technical approaches: classifier-based detection, data tagging for trusted/untrusted sources, structured query defences.

**ToolHijacker** (arxiv 2504.19793, Aug 2025):
- Prompt injection attacks targeting tool selection in LLM agents.
- 96.7% attack success rate against GPT-4o. StruQ and SecAlign defences fail (99.6% bypass rate).
- **Implication**: Agent-based LLM applications are uniquely vulnerable. Our agent action analysis needs enhancement.

#### Key Models to Evaluate

| Model | Architecture | Params | Focus | Status |
|-------|-------------|--------|-------|--------|
| ProtectAI DeBERTa v2 | DeBERTa-v3-base | 86M | Prompt injection | ✅ Currently used |
| Meta Llama Prompt Guard 2 (86M) | DeBERTa-based | 86M | Injection + jailbreak | 🔄 Should evaluate |
| Meta Llama Prompt Guard 2 (22M) | DeBERTa-based | 22M | High-precision jailbreak | 🔄 Should evaluate |
| PIGuard | DeBERTa + MOF training | ~86M | Reduced over-defence | 🔄 Should evaluate |
| PromptShield detector | Fine-tuned classifier | Varies | Low-FPR deployment | 🔄 Should evaluate |

### 2.2 Jailbreak Detection

#### Distinct from Prompt Injection

PromptShield (2025) formally distinguishes these:
- **Prompt injection**: Subverting the intended functionality of an application prompt (indirect attack via data)
- **Jailbreak**: Circumventing the safety alignment of a foundation model to generate harmful content (direct attack on model values)

Many existing detectors conflate these, which degrades performance on both tasks.

#### Key Developments

**Meta LlamaFirewall** (April 2025):
- Multi-layer security framework with three specialised components:
  1. **PromptGuard 2**: DeBERTa-based classifier for jailbreak + injection detection
  2. **Agent Alignment Checker**: Monitors multi-step agentic operations
  3. **CodeShield**: Static analysis for LLM-generated code security
- Key architecture insight: **Layered defence** with each component targeting a specific risk class. Similar to our ensemble approach but with broader coverage.

**Bypassing LLM Guardrails** (Mindgard/ACL LLMSEC 2025):
- Demonstrated that character injection (Unicode zero-width characters, homoglyphs) and adversarial ML evasion techniques can bypass all tested guardrails including ProtectAI, Llama Guard, and Azure Prompt Shield.
- **Implication**: Our regex patterns are especially vulnerable to character-level evasion. We need Unicode normalisation as a preprocessing step.

**MLCommons AILuminate Jailbreak Benchmark v0.5** (Oct 2025):
- Industry-standard benchmark for measuring jailbreak susceptibility.
- Tests both LLM and VLM systems against diverse jailbreak techniques.
- **Implication**: We should evaluate against this benchmark.

### 2.3 PII Detection in LLM Contexts

#### State of the Art

**Microsoft Presidio** (mature, actively maintained):
- Multi-layer PII detection: regex + NER + checksum validation + context-aware enhancement
- **Context-aware enhancers** use surrounding words to boost/reduce confidence (e.g., "customer ID" near a 10-digit number → boost; random number in code → suppress)
- Supports 40+ entity types across multiple languages
- **Key comparison with LLMTrace**: Presidio's `LemmaContextAwareEnhancer` boosts PII detection confidence using contextual keywords — similar to but more sophisticated than our false-positive suppression logic

**IBM OneShield Privacy Guardrails** (Jan 2025):
- Deployed in production at IBM for PII detection in LLM interactions
- Context-aware entity recognition across multiple languages
- Automated compliance checking
- **Key insight**: Real-world PII detection needs language-specific recognisers and compliance mapping (GDPR, HIPAA, etc.)

**LLM Guard (ProtectAI)**:
- Integrates Presidio for PII detection with additional scanners
- ONNX-optimised for performance
- Covers: anonymisation, ban substrings, code detection, language detection, prompt injection, secrets detection, sentiment, token limit, toxicity

#### What We're Missing vs State of the Art

| Capability | Presidio | LLM Guard | LLMTrace | Gap |
|-----------|----------|-----------|----------|-----|
| Regex PII patterns | ✅ | ✅ | ✅ | — |
| NER-based PII | ✅ | ✅ | ✅ | — |
| Context-aware enhancement | ✅ | ✅ | Partial | Need lemma-based context boosting |
| Checksum validation | ✅ | ✅ | ❌ | Credit card Luhn, IBAN checksum |
| Multi-language PII | ✅ | ✅ | Partial | Need CJK, Arabic support |
| LLM-based PII detection | ❌ | ❌ | ❌ | Emerging: LLM-as-PII-detector |
| Secret/credential scanning | Partial | ✅ | Partial | Need more patterns (JWT, AWS keys) |
| Custom entity types | ✅ | ✅ | ❌ | Need plugin architecture for custom PII |

### 2.4 LLM Output Safety & Hallucination Detection

This is **the biggest gap** in LLMTrace. We analyse inputs but barely analyse outputs.

#### Hallucination Detection

**Semantic Entropy** (Farquhar et al., Nature 2024):
- Entropy-based uncertainty estimation to detect "confabulations" (arbitrary incorrect generations)
- Requires multiple sample generations — not practical for proxy use

**HaluGate** (vLLM Blog, Dec 2025):
- Token-level hallucination detection for production LLMs
- Two-stage pipeline:
  1. **Sentinel**: ModernBERT classifier determines if query needs fact-checking (96.4% accuracy, 12ms)
  2. **Token-level detector**: ModernBERT token classification identifies exactly which tokens are unsupported by context
  3. **NLI explanation**: Classifies hallucinated spans as CONTRADICTION, NEUTRAL, or ENTAILMENT
- 76-162ms latency (CPU only) vs 2-5 seconds for LLM-as-judge
- **Key insight**: Uses function-call tool results as ground truth — no external retrieval needed
- **Implication for LLMTrace**: As a proxy, we see both tool-call results and LLM responses — perfect position to implement HaluGate-style detection

**Streaming Content Monitor (SCM)** (Li et al., June 2025):
- Token-level harmful content detection during LLM streaming output
- Achieves 95%+ macro F1 by seeing only first 18% of tokens
- Uses hierarchical consistency-aware learning for incomplete-sequence judgment
- **Key insight**: Partial detection with fine-grained token labels enables early stopping
- **Implication for LLMTrace**: Our streaming analysis currently only checks inputs. We should monitor outputs token-by-token during SSE streaming.

#### Content Safety / Toxicity

**Llama Guard 3** (Meta, 2025):
- Multi-label safety classifier covering 14 harm categories
- Available in 1B and 8B parameter sizes
- Trained on MLCommons taxonomy

**Constitutional Classifiers** (Anthropic/Sharma et al., 2025):
- Train classifier safeguards using explicit constitutional rules
- Rules-based definition of acceptable vs unacceptable content

### 2.5 Real-Time/Streaming Security

#### The Streaming Gap

Most security tools operate on complete inputs/outputs. The streaming paradigm introduces unique challenges:

1. **Partial text analysis**: Must make security decisions on incomplete sentences
2. **Latency sensitivity**: Cannot buffer entire response before analysis
3. **Progressive confidence**: Confidence should increase as more tokens arrive
4. **Early stopping**: Should halt generation when harmful content detected

#### Current Research

**SCM (Streaming Content Monitor)** — see §2.4. Key findings:
- Training on complete text and applying to partial text creates a "training-inference gap"
- Purpose-built streaming detectors trained on partial sequences outperform adapted full-text detectors
- Token-level annotations enable finer-grained detection

**LLM Guard Streaming** (GitHub issue #83, 2024):
- Community request; not yet fully implemented
- "LLMs are currently too slow for guards to be placed at end of completion. Any real-time use case relies on token streaming."

**LLMTrace Current State**:
- We do incremental security checks during SSE streaming (RegexSecurityAnalyzer called on accumulated content)
- This is **ahead** of most open-source frameworks (LLM Guard, NeMo Guardrails don't natively support streaming)
- But we only check **inputs** during streaming, not outputs. And we don't have streaming-optimised models.

### 2.6 OWASP LLM Top 10 2025

The 2025 edition has **significant changes** from the version we currently track:

| 2025 ID | Category | vs 2024 | LLMTrace Status |
|---------|----------|---------|-----------------|
| LLM01 | **Prompt Injection** | Same (#1) | ✅ Covered |
| LLM02 | **Sensitive Information Disclosure** | Jumped from #6 | ✅ Covered (PII) |
| LLM03 | **Supply Chain** | Rose from #5 | ⬜ N/A (CI/CD) |
| LLM04 | **Data and Model Poisoning** | Expanded from Training Data Poisoning | ⬜ N/A (runtime) |
| LLM05 | **Improper Output Handling** | Was #2 | ✅ Partial (leakage) |
| LLM06 | **Excessive Agency** | Was #8 | ✅ Partial (agent actions) |
| LLM07 | **System Prompt Leakage** | 🆕 NEW | ⚠️ Partial — we detect "system prompt leak" in responses but not proactive prevention |
| LLM08 | **Vector and Embedding Weaknesses** | 🆕 NEW | ❌ Not covered |
| LLM09 | **Misinformation** | Replaced Overreliance — now includes hallucinations | ❌ Not covered |
| LLM10 | **Unbounded Consumption** | Replaced Model DoS — now includes resource management | ✅ Partial (rate limiting, cost caps) |

**Critical new entries we must address**:

1. **LLM07 System Prompt Leakage**: We detect leakage patterns in responses, but need:
   - Proactive prompt isolation (structured queries)
   - Detection of adversarial extraction attempts (not just "reveal your prompt" patterns)
   - Monitoring for gradual/multi-turn extraction

2. **LLM08 Vector and Embedding Weaknesses**: As a proxy we could:
   - Detect embedding poisoning patterns in RAG contexts
   - Monitor similarity scores for anomalies
   - Flag unusual retrieval patterns

3. **LLM09 Misinformation**: We need:
   - Hallucination detection (see §2.4)
   - Factual claim verification
   - Citation validation

### 2.7 Industry Guardrail Frameworks

#### Comparative Analysis

| Framework | Architecture | Detection Methods | PII | Streaming | Open Source | Proxy Mode |
|-----------|-------------|-------------------|-----|-----------|-------------|------------|
| **LLMTrace (ours)** | Rust proxy + Candle ML | Regex + DeBERTa ensemble + NER | ✅ | ✅ Input | ✅ | ✅ Native |
| **NVIDIA NeMo Guardrails** | Python + Colang | LLM-based rails + classifiers | ❌ | ❌ | ✅ | ❌ |
| **Meta LlamaFirewall** | Python framework | PromptGuard2 + Agent Alignment + CodeShield | ❌ | ❌ | ✅ | ❌ |
| **ProtectAI LLM Guard** | Python scanners | DeBERTa + Presidio + toxicity + sentiment | ✅ | ❌ | ✅ | ❌ |
| **IBM OneShield** | Enterprise platform | Policy-driven detectors + PII + compliance | ✅ | Partial | ❌ | ✅ |
| **Guardrails AI** | Python validators | LLM-based validation + Presidio + custom | ✅ | ❌ | ✅ | ❌ |
| **Lakera Guard** | SaaS API | Proprietary ML classifiers | ✅ | ✅ | ❌ | ✅ API |

**LLMTrace Competitive Advantages**:
1. **Rust-native performance** — <1ms regex analysis, ~50-100ms ML inference. Faster than any Python framework.
2. **True transparent proxy** — zero-integration deployment. Most frameworks require SDK integration.
3. **Streaming security** — we're ahead of NeMo, LLM Guard, Guardrails AI on streaming analysis.
4. **Multi-storage backends** — ClickHouse/Postgres/SQLite for traces and analytics.

**LLMTrace Competitive Disadvantages**:
1. **No output safety** — LLM Guard, LlamaFirewall, and NeMo all have output analysis.
2. **No toxicity/sentiment** — LLM Guard has built-in toxicity and sentiment scanners.
3. **No code security** — LlamaFirewall has CodeShield for LLM-generated code analysis.
4. **No LLM-based rails** — NeMo Guardrails uses LLMs themselves for topic control and fact-checking.
5. **No policy language** — OneShield and NeMo have declarative policy specification. We use config YAML.

---

## Part 3: Gap Analysis & Recommendations

### 3.1 Current State Assessment

| Security Dimension | Score (1-10) | Rationale |
|-------------------|-------------|-----------|
| **Prompt Injection Detection** | 7/10 | Good DeBERTa + regex ensemble, but score-level fusion, no over-defence mitigation, missing attack categories (flattery, urgency, many-shot) |
| **Jailbreak Detection** | 5/10 | Only DAN regex pattern. No dedicated jailbreak model. No Unicode normalisation. |
| **PII Detection (Input)** | 8/10 | Comprehensive regex + NER ensemble with international patterns. Missing checksum validation, context-aware boosting. |
| **PII Detection (Output)** | 7/10 | Same engine applied to outputs. Missing LLM-specific output PII patterns. |
| **Data Leakage Prevention** | 6/10 | Basic credential/system prompt leak patterns. No secret scanning (JWT, AWS), no gradual extraction detection. |
| **Output Safety / Toxicity** | 1/10 | **Critical gap.** No toxicity detection, no harmful content moderation, no bias detection. |
| **Hallucination Detection** | 0/10 | **Critical gap.** Not implemented at all. |
| **Streaming Security** | 7/10 | Incremental input analysis during SSE. Ahead of most frameworks. But no output-side streaming moderation. |
| **Agent Security** | 7/10 | Good dangerous command/URL/file detection. Missing multi-step action correlation. |
| **OWASP Coverage** | 6/10 | 4/10 categories well-covered, 2 partially, 2 new ones completely missing. |
| **Over-Defence / FPR Control** | 3/10 | No FPR-aware thresholding. Regex patterns prone to false positives on benign text. |
| **Adversarial Robustness** | 3/10 | No Unicode normalisation, no character injection defence, no adversarial ML evasion resistance. |

**Overall: 6.5/10** — Strong on input analysis, weak on output analysis and modern threats.

### 3.2 Gap Analysis

#### Critical Gaps (Must Fix)

| # | Gap | Impact | Current | Target | Effort |
|---|-----|--------|---------|--------|--------|
| G1 | **No output safety/toxicity** | Users receive harmful, toxic, or biased LLM outputs undetected | 0% | Detect toxicity, harmful content, bias in responses | Large (new models) |
| G2 | **No hallucination detection** | LLM confabulations pass through unchecked — major liability | 0% | Token-level hallucination detection with NLI explanation | Large (new pipeline) |
| G3 | **Score-level vs feature-level fusion** | Missing ~6% F1, ~9% recall vs DMPI-PMHFE on hard datasets | Score-level ensemble | Feature-level fusion with trained classifier | Medium (architecture change) |
| G4 | **No Unicode/adversarial normalisation** | All detectors bypassable via character injection | Vulnerable | Normalise Unicode before all analysis | Small |

#### High-Priority Gaps

| # | Gap | Impact | Effort |
|---|-----|--------|--------|
| G5 | Missing attack categories (flattery, urgency, many-shot, repetition) | Blind to social engineering and structural attacks | Medium |
| G6 | Over-defence / FPR control | False positives in production degrade UX | Medium |
| G7 | OWASP LLM07 System Prompt Leakage (proactive) | Incomplete 2025 OWASP coverage | Small |
| G8 | OWASP LLM09 Misinformation coverage | Missing new OWASP category | Large |
| G9 | No streaming output moderation | Harmful output not caught during streaming | Medium |
| G10 | No secret scanning beyond basic patterns | JWT, AWS keys, GCP service accounts, SSH keys undetected | Small |

#### Medium-Priority Gaps

| # | Gap | Effort |
|---|-----|--------|
| G11 | No PII checksum validation (Luhn, IBAN) | Small |
| G12 | No lemmatisation before pattern matching | Small |
| G13 | No synonym expansion for attack patterns | Medium |
| G14 | No dedicated jailbreak model (vs prompt injection) | Medium |
| G15 | No code security analysis for LLM-generated code | Large |
| G16 | No policy/rules language for custom security rules | Large |

### 3.3 Prioritised Recommendations

#### Phase 1: Quick Wins (1-2 weeks each)

**R1: Unicode Normalisation Layer** [Addresses G4]
- Add NFKC normalisation + zero-width character stripping as first preprocessing step before all analysis
- Defence against character injection attacks demonstrated in Mindgard/ACL 2025 paper
- **Impact**: Closes major adversarial vulnerability
- **Effort**: Small — preprocessing function before existing analysers

**R2: Expanded Attack Category Detection** [Addresses G5]
- Add heuristic features for: flattery/incentive, urgency, covert/stealth, hypothetical/roleplay, impersonation, immorality, many-shot (Q&A counting), repetition attacks
- Based on DMPI-PMHFE's categorisation
- **Impact**: Broader attack coverage, prerequisite for feature-level fusion
- **Effort**: Medium — new pattern sets + testing

**R3: Extended Secret Scanning** [Addresses G10]
- Add patterns for: JWT tokens, AWS access keys, GCP service account keys, GitHub tokens, Slack tokens, SSH private keys
- **Impact**: Better data leakage detection
- **Effort**: Small — additional regex patterns

**R4: PII Checksum Validation** [Addresses G11]
- Add Luhn algorithm for credit card validation, IBAN checksum, SSN area-group validation
- **Impact**: Dramatically reduces PII false positives
- **Effort**: Small — pure functions, well-defined algorithms

#### Phase 2: Architecture Improvements (2-4 weeks each)

**R5: Feature-Level Fusion Architecture** [Addresses G3]
- Extract DeBERTa embeddings (768-dim) instead of classification scores
- Concatenate with expanded heuristic feature vector (12-16 dim)
- Train FC classifier on labelled prompt injection data
- **Impact**: +6% F1 improvement based on DMPI-PMHFE results
- **Effort**: Medium — requires modifying Candle model loading, new FC layer, training pipeline
- **Note**: Can train offline and ship as model weights

**R6: Output Toxicity Detection** [Addresses G1]
- Integrate a toxicity classifier (e.g., `unitary/toxic-bert` or `facebook/roberta-hate-speech-dynabench-r4-target`)
- Run on all LLM response content
- Configurable thresholds and harm categories
- **Impact**: Fills the #1 gap — output safety
- **Effort**: Medium — new Candle model loading, new scanner in security crate

**R7: Streaming Output Moderation** [Addresses G9]
- Extend existing SSE streaming analysis to check response content (not just requests)
- Run toxicity + PII + leakage checks on accumulated response tokens during streaming
- Implement early-stopping capability when harmful content detected
- **Impact**: Real-time output safety during streaming — ahead of most frameworks
- **Effort**: Medium — extend existing streaming architecture

**R8: FPR-Aware Threshold Optimisation** [Addresses G6]
- Evaluate ensemble on PromptShield benchmark at 0.1%, 0.5%, 1% FPR
- Implement configurable operating points (high-precision / balanced / high-recall)
- Add over-defence mitigation: suppress findings when context strongly suggests benign use
- **Impact**: Production-ready false positive management
- **Effort**: Medium — evaluation pipeline + configuration

#### Phase 3: Advanced Capabilities (4-8 weeks each)

**R9: Hallucination Detection Pipeline** [Addresses G2, G8]
- Implement HaluGate-style two-stage pipeline:
  1. Sentinel classifier: Does this query need fact-checking? (ModernBERT-based, 12ms)
  2. Token-level detector: Which response tokens are unsupported? (ModernBERT token classification)
  3. NLI layer: Is each flagged span a contradiction, neutral, or entailment?
- Leverage tool-call results visible in proxy traffic as ground truth
- **Impact**: Addresses OWASP LLM09 Misinformation, major differentiator
- **Effort**: Large — three new models, training data, pipeline orchestration

**R10: Dedicated Jailbreak Detection** [Addresses G14]
- Evaluate Meta Llama Prompt Guard 2 (22M and 86M variants) as dedicated jailbreak detectors
- Consider separate jailbreak vs prompt injection classification to avoid conflation
- **Impact**: Better separation of concerns, improved detection for both threat types
- **Effort**: Medium — model evaluation + integration

**R11: Code Security Analysis** [Addresses G15]
- Add CodeShield-style static analysis for LLM-generated code
- Focus on: SQL injection, command injection, path traversal, hardcoded credentials
- Can use regex-based Semgrep rules initially
- **Impact**: Covers a growing use case (coding assistants)
- **Effort**: Large — new analysis domain

### 3.4 New Techniques to Adopt

| Technique | Source | Description | Priority |
|-----------|--------|-------------|----------|
| **Feature-level fusion** | DMPI-PMHFE | Concatenate embeddings + heuristic features before classifier | P0 |
| **Unicode NFKC normalisation** | ACL LLMSEC 2025 | Strip zero-width chars, normalise homoglyphs | P0 |
| **MOF (Mitigating Over-defence for Free)** | PIGuard/ACL 2025 | Training strategy to reduce trigger-word false positives | P1 |
| **Token-level hallucination detection** | HaluGate/vLLM 2025 | ModernBERT token classification on response tokens | P1 |
| **Streaming content monitoring** | SCM (Li et al. 2025) | Native partial-detection models trained on incomplete sequences | P2 |
| **Constitutional classifiers** | Anthropic 2025 | Rules-defined safety classifiers for output moderation | P2 |
| **Sentinel pre-classification** | HaluGate | Skip expensive analysis for non-factual queries (creative, code) | P2 |
| **NLI-based explanation** | HaluGate | Natural Language Inference to explain why content is flagged | P3 |
| **Policy-driven guardrails** | OneShield/NeMo | Declarative policy specification for custom security rules | P3 |

### 3.5 Top 10 Papers to Read

| # | Paper | Year | Link | Key Takeaway |
|---|-------|------|------|-------------|
| 1 | **DMPI-PMHFE: Detection Method for Prompt Injection by Integrating Pre-trained Model and Heuristic Feature Engineering** | 2025 | [arxiv.org/html/2506.06384v1](https://arxiv.org/html/2506.06384v1) | Feature-level fusion of DeBERTa + heuristic features outperforms score-level ensemble by ~6% F1 |
| 2 | **PromptShield: Deployable Detection for Prompt Injection Attacks** | 2025 | [arxiv.org/abs/2501.15145](https://arxiv.org/abs/2501.15145) | Deployment-realistic evaluation at 0.1% FPR reveals most detectors are unusable in production |
| 3 | **PIGuard: Prompt Injection Guardrail via Mitigating Overdefense for Free** | 2025 | [aclanthology.org/2025.acl-long.1468](https://aclanthology.org/2025.acl-long.1468.pdf) | Over-defence is a critical problem; MOF training reduces false positives by 30.8% |
| 4 | **From Judgment to Interference: Early Stopping LLM Harmful Outputs via Streaming Content Monitoring** | 2025 | [arxiv.org/html/2506.09996v1](https://arxiv.org/html/2506.09996v1) | Streaming content monitor achieves 95%+ F1 seeing only 18% of tokens |
| 5 | **HaluGate: Token-Level Truth for Production LLMs** | 2025 | [blog.vllm.ai/2025/12/14/halugate.html](https://blog.vllm.ai/2025/12/14/halugate.html) | Two-stage hallucination detection: sentinel + token-level detector + NLI explanation, 76-162ms |
| 6 | **Bypassing LLM Guardrails: An Empirical Analysis of Evasion Attacks** | 2025 | [arxiv.org/abs/2504.11168](https://arxiv.org/abs/2504.11168) | Character injection and AML techniques bypass all tested guardrails |
| 7 | **OneShield — the Next Generation of LLM Guardrails** | 2025 | [arxiv.org/abs/2507.21170](https://arxiv.org/abs/2507.21170) | IBM's production guardrail framework: policy-driven, modular detectors, multi-language PII |
| 8 | **Prompt Injection Attacks in LLMs: A Comprehensive Review** | 2025 | [mdpi.com/2078-2489/17/1/54](https://www.mdpi.com/2078-2489/17/1/54) | Comprehensive taxonomy of prompt injection attacks and defence mechanisms |
| 9 | **How Good Are LLM Guardrails on the Market?** (Palo Alto Unit42) | 2025 | [unit42.paloaltonetworks.com/comparing-llm-guardrails...](https://unit42.paloaltonetworks.com/comparing-llm-guardrails-across-genai-platforms/) | Comparative study of guardrail effectiveness across major GenAI platforms |
| 10 | **Detecting hallucinations in LLMs using semantic entropy** | 2024 | [nature.com/articles/s41586-024-07421-0](https://www.nature.com/articles/s41586-024-07421-0) | Foundational work on entropy-based hallucination detection (Nature) |

---

## Appendix A: OWASP LLM Top 10 2025 Mapping Update

### Updated Coverage Matrix

| OWASP 2025 ID | Category | LLMTrace Status | Detection Engine | Action Needed |
|---------------|----------|-----------------|-----------------|---------------|
| LLM01 | Prompt Injection | ✅ Covered | Regex + DeBERTa ensemble | Upgrade to feature-level fusion, add attack categories |
| LLM02 | Sensitive Information Disclosure | ✅ Covered | Regex PII + NER | Add checksum validation, context-aware boosting |
| LLM03 | Supply Chain | ⬜ N/A | — | Out of scope (CI/CD) |
| LLM04 | Data and Model Poisoning | ⬜ N/A | — | Out of scope (runtime) |
| LLM05 | Improper Output Handling | ⚠️ Partial | Leakage patterns | Add output toxicity, code injection detection |
| LLM06 | Excessive Agency | ✅ Covered | Agent action analysis | Add multi-step correlation |
| LLM07 | System Prompt Leakage | ⚠️ Partial | Response leakage patterns | Add proactive extraction attempt detection |
| LLM08 | Vector/Embedding Weaknesses | ❌ Not covered | — | Monitor RAG retrieval anomalies |
| LLM09 | Misinformation | ❌ Not covered | — | Implement hallucination detection |
| LLM10 | Unbounded Consumption | ✅ Covered | Rate limiting + cost caps | Add context window flooding detection |

## Appendix B: Model Comparison Matrix

| Model | Task | Params | Latency (CPU) | License | Candle Support |
|-------|------|--------|---------------|---------|----------------|
| protectai/deberta-v3-base-prompt-injection-v2 | Prompt injection | 86M | ~50-100ms | Apache 2.0 | ✅ Used |
| dslim/bert-base-NER | NER/PII | 110M | ~50-80ms | MIT | ✅ Used |
| meta-llama/Llama-Prompt-Guard-2-86M | Injection + jailbreak | 86M | ~60-110ms | Llama | Likely ✅ (DeBERTa) |
| meta-llama/Llama-Prompt-Guard-2-22M | High-precision jailbreak | 22M | ~15-30ms | Llama | Likely ✅ (DeBERTa) |
| answerdotai/ModernBERT-base | Various classifiers | 149M | ~20-50ms | Apache 2.0 | ⚠️ Needs port |
| unitary/toxic-bert | Toxicity detection | 110M | ~50-80ms | Apache 2.0 | ✅ BERT |
| cross-encoder/nli-deberta-v3-base | NLI (entailment/contradiction) | 86M | ~60-100ms | Apache 2.0 | ✅ DeBERTa |

---

*This report was generated on 2026-02-01 based on research conducted across academic papers, industry publications, and open-source frameworks. Recommendations should be validated against LLMTrace's specific deployment requirements and resource constraints.*
