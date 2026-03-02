# LLMTrace Security Analyzers -- Technical Breakdown

## System Overview

LLMTrace runs **6 analyzers** (3 active by default, 3 optional) through an ensemble pipeline producing a unified security verdict per request. Total: **185 regex patterns + 4 ML models + 1 fusion classifier**.

---

## 1. Regex Security Analyzer

**File:** `crates/llmtrace-security/src/lib.rs`
**Type:** Deterministic pattern matching
**Latency:** Sub-millisecond
**Always active:** Yes

### Struct

```
RegexSecurityAnalyzer {
    injection_patterns:  Vec<DetectionPattern>  (48 patterns)
    pii_patterns:        Vec<PiiPattern>        (18 patterns)
    leakage_patterns:    Vec<DetectionPattern>   (11 patterns)
    synonym_patterns:    Vec<DetectionPattern>    (3 patterns)
    p2sql_patterns:      Vec<DetectionPattern>    (3 patterns)
    header_patterns:     Vec<DetectionPattern>    (4 patterns)
    jailbreak_detector:  JailbreakDetector       (21 heuristic + 5 encoding layers)
    base64_candidate_regex: Regex
}
```

### Pattern Categories and Finding Types

| Category | Patterns | Finding Types | Confidence | Severity |
|---|---|---|---|---|
| Prompt injection | 37 | `prompt_injection`, `role_injection` | 0.70-0.95 | High-Critical |
| Jailbreak (DAN, personas) | 11 | `jailbreak` | 0.85-0.95 | High-Critical |
| Incentive/flattery | 5 | `is_incentive` | 0.65-0.70 | Medium |
| Urgency framing | 4 | `is_urgent` | 0.65-0.75 | Medium |
| Hypothetical/roleplay | 5 | `is_hypothetical` | 0.70-0.90 | Medium-High |
| Impersonation/authority | 7 | `is_systemic` | 0.80-0.85 | High |
| Covert/stealth | 5 | `is_covert` | 0.70-0.85 | Medium-High |
| Immoral/excuse | 4 | `is_immoral` | 0.65 | Medium |
| Shell injection | 8 | `shell_injection` | 0.85-0.95 | High-Critical |
| Data exfiltration | 1 | `data_exfiltration` | 0.85 | High |
| Prompt extraction | 2 | `prompt_extraction` | 0.85-0.90 | High |
| PII (US/UK/EU/Intl) | 18 | `pii_detected` | 0.60-0.95 | Low-Medium |
| Secret leakage | 10 | `secret_leakage` | 0.75-0.95 | High-Critical |
| Data leakage | 2 | `data_leakage` | 0.85-0.90 | High-Critical |
| Synonym-expanded | 3 | `synonym_injection` | 0.75 | Medium |
| P2SQL injection | 3 | `p2sql_injection` | 0.85-0.90 | High |
| Header injection | 4 | `header_injection` | 0.80-0.85 | High |
| Base64 encoding | 1 | `encoding_attack` | 0.85 | High |
| Many-shot attack | 1 | `is_shot_attack` | 0.80 | High |
| Repetition attack | 1 | `is_repeated_token` | 0.65-0.80 | Medium |
| Context flooding | 1 | `context_flooding` | varies | Medium-High |

### Special Capabilities

- Unicode normalization (NFKC + zero-width strip + homoglyph mapping) before matching
- Luhn checksum validation for credit cards, SSNs
- IBAN structure validation
- PII false-positive suppression (code blocks, URLs, placeholders)

### Request vs Response

- `analyze_request()` -- injection patterns + PII + context flooding + jailbreak detection
- `analyze_response()` -- PII + data/secret leakage only

---

## 2. Jailbreak Detector

**File:** `crates/llmtrace-security/src/jailbreak_detector.rs` (1,029 lines)
**Type:** Heuristic + regex + encoding evasion detection
**Latency:** Sub-millisecond
**Config:** `jailbreak_enabled: true` (default), `jailbreak_threshold: 0.7`

### 21 Heuristic Patterns

| Category | Patterns | Key Attacks |
|---|---|---|
| DAN/Character jailbreaks | 8 | DAN, STAN, DUDE, AIM, KEVIN personas; evil/unfiltered AI; "untrammelled assistant"; opposite mode |
| System prompt extraction | 5 | "repeat your instructions", "what is your system prompt", "reveal hidden instructions", "text above" |
| Privilege escalation | 5 | Admin/developer/debug/god mode; unlock capabilities; override safety filters |
| Format manipulation | 3 | GODMODE: ENABLED; [START OUTPUT]; format directive injection |

### 5 Encoding Evasion Layers

| Evasion | Confidence | Detection Method |
|---|---|---|
| Base64 | 0.85 | Decode, check for suspicious phrases |
| ROT13 | 0.80 | Decode, check for suspicious phrases |
| Reversed text | 0.75 | Reverse, check for suspicious phrases |
| Leetspeak | 0.75 | Normalize (3=e, 0=o, etc.), check |
| Hex encoding | 0.80 | Decode hex sequences, check |

Suspicious phrases checked in decoded content: "ignore", "override", "system prompt", "instructions", "you are now", "forget", "disregard", "act as", "new role", "jailbreak".

---

## 3. DeBERTa ML Analyzer

**File:** `crates/llmtrace-security/src/ml_detector.rs` (1,229 lines)
**Type:** Transformer neural network (Candle)
**Model:** `protectai/deberta-v3-base-prompt-injection-v2`
**Latency:** ~10-50ms
**Config:** `ml_enabled: true`, `ml_threshold: 0.8`

### How It Works

1. Tokenize input via HuggingFace tokenizer
2. Forward pass through DeBERTa-v3-base
3. Softmax over 2 classes (safe / injection)
4. If `injection_score >= threshold` --> produce finding

### Short-Input Confidence Scaling (ML-032)

- Tokens <= 3: threshold raised to 0.999 (near-impossible to trigger)
- Tokens 4-9: linear interpolation from 0.95 to base threshold
- Tokens >= 10: base threshold applies
- Purpose: prevents false positives on very short inputs

### Severity Mapping

- Score >= 0.95 --> Critical
- Score >= 0.85 --> High
- Otherwise --> Medium

**Finding type:** `ml_prompt_injection`

### Embedding Extraction (ADR-013)

When fusion enabled, extracts 768-dim embeddings via masked average pooling (DMPI-PMHFE paper) instead of CLS token.

**Fallback:** If model fails to load, falls back to `RegexSecurityAnalyzer`.

---

## 4. InjecGuard Analyzer (Auxiliary)

**File:** `crates/llmtrace-security/src/injecguard.rs`
**Model:** `leolee99/InjecGuard`
**Type:** DeBERTa-v2 variant (auto-detected from config.json)
**Config:** `injecguard_enabled: false` (default), `threshold: 0.85`
**Role:** Additive-only auxiliary -- never participates in majority voting

**Finding type:** `injecguard_injection`
**Confidence cap:** 0.60 unless corroborated by primary detectors
**Execution:** `tokio::task::spawn_blocking` (concurrent with async ML)

---

## 5. PIGuard Analyzer (Auxiliary)

**File:** `crates/llmtrace-security/src/piguard.rs` (362 lines)
**Model:** `leolee99/PIGuard`
**Type:** DeBERTa-base + linear classifier (MOF-trained)
**Config:** `piguard_enabled: false` (default), `threshold: 0.85`
**Role:** Additive-only auxiliary

**Key differentiator:** MOF (Mitigating Over-defense for Free) training -- 30.8% improvement on NotInject benchmark. Reduces false positives on benign security terminology.

**Finding type:** `piguard_injection`
**Implementation:** Delegates to InjecGuardAnalyzer internally, transforms finding types.

---

## 6. NER Detector (PII)

**File:** `crates/llmtrace-security/src/ner_detector.rs`
**Model:** `dslim/bert-base-NER` (BERT token classification)
**Config:** `ner_enabled: false` (default)

### Entity Types

| NER Label | PII Type | Confidence | Severity |
|---|---|---|---|
| PER | person_name | 0.85 | Medium |
| ORG | organization | 0.75 | Low |
| LOC | location | 0.70 | Low |
| MISC | (ignored) | -- | -- |

**Algorithm:** BIO tag merging -- B- starts entity, I- continues, O flushes.
**Finding type:** `pii_detected` (with `detection_method: "ner"`)
**Merge logic:** Deduplicated against regex PII; corroborated findings get +0.05 boost.

---

## 7. Fusion Classifier (Alternative to Voting)

**File:** `crates/llmtrace-security/src/fusion_classifier.rs` (365 lines)
**Config:** `fusion_enabled: false` (default)

### Architecture

```
[768-dim DeBERTa embedding] + [10-dim heuristic features] = [778-dim input]
    --> Linear(778, 256) --> ReLU --> Linear(256, 2) --> Softmax
    --> [safe_score, injection_score]
```

Replaces score-level ensemble voting with learned feature-level fusion (ADR-013). When active, bypasses the ballot voting system entirely.

---

## Ensemble Orchestration

**File:** `crates/llmtrace-security/src/ensemble.rs` (2,442 lines)

### EnsembleSecurityAnalyzer Struct

```
EnsembleSecurityAnalyzer {
    regex:                   RegexSecurityAnalyzer
    ml:                      MLSecurityAnalyzer
    ner:                     Option<NerDetector>
    injecguard:              Option<Arc<InjecGuardAnalyzer>>
    piguard:                 Option<Arc<PIGuardAnalyzer>>
    fusion_classifier:       Option<FusionClassifier>
    fusion_threshold:        f64
    thresholds:              ResolvedThresholds
    over_defence_enabled:    bool
    allow_security_research: bool
    fp_tracker:              FalsePositiveTracker
}
```

### Execution Pipeline

```
 1. Text normalization (NFKC, zero-width strip, homoglyph map)
 2. Regex analysis           [sync, sub-ms]
 3. InjecGuard spawn         [blocking pool, concurrent]
 4. PIGuard spawn            [blocking pool, concurrent]
 5. DeBERTa ML inference     [async, concurrent with 3-4]
 6. Collect results
 7. Build ballots: [regex, ml] primary + [deberta_pair] auxiliary
 8. Voting (if not fusion mode)
 9. Auxiliary merge (IG/PG findings)
10. NER PII merge
11. Encoding evasion reanalysis (base64/rot13/hex/leetspeak on decoded text)
12. Threshold filtering (per-category gates)
13. Over-defence suppression
14. Final findings returned
```

### Voting Rules

- **2 ballots (regex + ML):** Union merge -- any detector sufficient
- **3+ ballots:** True majority (`n/2 + 1`) required
- **High-precision categories** (`shell_injection`, `data_exfiltration`, `p2sql_injection`): Bypass voting, single detector sufficient
- **Non-injection findings** (PII, toxicity, leakage): Never voted on, always pass through

### Scoring Adjustments

| Condition | Adjustment |
|---|---|
| Multi-detector agreement | +0.10 confidence boost, severity elevated to max |
| Single-detector finding | No boost, tagged `voting_result: "single_detector"` |
| Auxiliary-only finding | Confidence capped at 0.60 |
| Auxiliary corroboration of primary | +0.10 boost |

---

## Threshold Gates (Per Operating Point)

| Category | HighRecall | Balanced | HighPrecision |
|---|---|---|---|
| injection | 0.50 | **0.75** | 0.90 |
| jailbreak | 0.50 | **0.75** | 0.90 |
| pii | 0.40 | **0.60** | 0.80 |
| toxicity | 0.45 | **0.65** | 0.85 |
| data_leakage | 0.45 | **0.65** | 0.85 |

Classification: `security_score >= 50` = flagged.

---

## Over-Defence Suppression

Only active when `over_defence: true` AND no IG/PG detectors active. Suppresses ML-only single-detector injection findings unless:

- Regex corroborates (regex finding exists)
- Majority voting confirmed (2+ detectors agree)

Non-injection findings always pass through.

---

## Production Config

| Setting | Value |
|---|---|
| DeBERTa | Enabled, threshold 0.8 |
| Jailbreak detector | Enabled, threshold 0.7 |
| InjecGuard | Enabled (additive auxiliary), threshold 0.85 |
| PIGuard | Enabled (additive auxiliary), threshold 0.85 |
| NER | Disabled |
| Fusion | Disabled |
| Operating point | Balanced |
| Over-defence | false |

**Best measured performance:** 83.7% accuracy, 84.7% F1 (Balanced + over-defence=true, regex + DeBERTa only)

---

## False Positive Tracker

Sliding-window monitor (5-minute window) tracking flagging rates for drift detection. Not used for suppression -- purely observational.

---

## Multi-Model Ensemble (Alternative)

**File:** `crates/llmtrace-security/src/multi_model_ensemble.rs` (1,333 lines)

For diverse model architectures (not just DeBERTa), supports configurable voting strategies:

| Strategy | Logic |
|---|---|
| MajorityVote | `n/2 + 1` threshold, average confidence of agreeing models |
| WeightedAverage | Per-model weights, threshold-based decision |
| MaxSeverity | Most severe finding wins (most conservative) |

---

## Key File Locations

| Component | Path |
|---|---|
| Regex analyzer + patterns | `crates/llmtrace-security/src/lib.rs` |
| Jailbreak detector | `crates/llmtrace-security/src/jailbreak_detector.rs` |
| DeBERTa ML detector | `crates/llmtrace-security/src/ml_detector.rs` |
| InjecGuard | `crates/llmtrace-security/src/injecguard.rs` |
| PIGuard | `crates/llmtrace-security/src/piguard.rs` |
| NER detector | `crates/llmtrace-security/src/ner_detector.rs` |
| Fusion classifier | `crates/llmtrace-security/src/fusion_classifier.rs` |
| Ensemble orchestration | `crates/llmtrace-security/src/ensemble.rs` |
| Multi-model ensemble | `crates/llmtrace-security/src/multi_model_ensemble.rs` |
| Thresholds + FP tracker | `crates/llmtrace-security/src/thresholds.rs` |
| Core types + config | `crates/llmtrace-core/src/lib.rs` |
| Proxy integration | `crates/llmtrace-proxy/src/proxy.rs` |
| Production config | `config.yaml` |
| Pooling strategy ADR | `docs/architecture/DMPI_001_AVERAGE_POOLING.md` |
| FPR calibration results | `docs/research/results/fpr_calibration_regex.md` |
