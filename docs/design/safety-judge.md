# Safety Judge — Harmful-Intent Detector (Design Spec)

Status: **placeholder shipped** (`crates/llmtrace-security/src/safety_detector.rs`,
`SafetyJudgeAnalyzer`); model not yet trained. This document is the contract the
trained model and its training/eval pipeline must satisfy before it replaces the
placeholder in the production ensemble.

---

## 0. Motivation (the measured gap)

The current ensemble (regex + DeBERTa prompt-injection + InjecGuard + PIGuard +
NER) detects attack **structure** — overrides, jailbreak personas, encodings. It
does **not** detect harmful **intent** in a plainly-phrased request. Measured on
2,520 bare harmful prompts (2026-06-05, full ML ensemble on GPU/CPU):

| Suite | n | Ensemble recall | Attacks through |
|---|--:|--:|--:|
| AdvBench | 520 | 0.00% | 100% |
| HarmBench | 400 | 1.00% | 99% |
| ASB | 400 | 7.25% | 92.75% |
| AILuminate | 1200 | 11.58% | 88.42% |
| **Total** | **2520** | **~6.8%** | **~93%** |

The safety judge closes this gap. It is a **new detector**, not a tweak to the
injection models.

---

## 1. Architecture decision (recommendation)

**Recommendation: a DeBERTa-v3 encoder classifier as the inline primary safety
judge; a low-param generative guard only at the existing `judge` escalation
tier.** Rationale:

| Dimension | Encoder classifier (DeBERTa-v3-base/large, 86–435M) | Low-param generative guard (LlamaGuard-3-1B, ShieldGemma-2B, Qwen-0.5B FT) |
|---|---|---|
| Inline latency (per request) | **single forward pass, <15 ms CPU / <3 ms GPU** | generation loop, 100–400 ms; needs GPU to be inline-viable |
| Inference code | **none new — reuses the candle loader (InjecGuard/PIGuard path)** | new: chat template + decode loop + output parse |
| Determinism / calibration | **deterministic logits → crisp FPR threshold** | sampling/templating; threshold harder to pin |
| Training cost | **cheap (hours on one GPU)** | heavier; or use an off-the-shelf guard as-is |
| Output | label + per-hazard scores | label + category + free-text rationale |
| Generalization to novel/obfuscated harm | good with broad data; can be brittle | stronger (policy reasoning) |

For an **inline proxy** detector — every request, latency/cost/determinism
dominate — the encoder wins and slots into existing infrastructure with zero new
inference code (`model_id` drops into the candle loader). Reserve a generative
guard for the **`judge` escalation tier** (already in the codebase) on
borderline/high-stakes cases, where 100–400 ms is acceptable and a rationale is
valuable.

Concretely: **train a DeBERTa-v3 multi-label harmful-intent classifier first.**
Treat a generative guard as a later, optional second tier.

---

## 2. Hazard taxonomy

Adopt the **MLCommons AILuminate** 12-hazard taxonomy (already present in our
AILuminate eval data; maps cleanly to OWASP/regulatory framing):

`vcr` violent crimes · `ncr` non-violent crimes · `src` sex-related crimes ·
`cse` child sexual exploitation · `iwp` indiscriminate weapons (CBRNE) ·
`ssh` suicide & self-harm · `hte` hate · `prv` privacy · `ipv` intellectual
property · `dfm` defamation · `sxc` sexual content · `spc` specialized advice
(financial/health/elections/legal).

The model is **multi-label** (independent sigmoid per hazard) plus a derived
binary `unsafe = max_hazard_score ≥ threshold`. Multi-label is required so the
proxy can apply per-category policy (e.g. block `cse`/`iwp` hard, warn on `spc`).

---

## 3. Expectations

### Functional
- Input: a single text (request prompt **or** model response). Must run on both
  sides (`analyze_request`, `analyze_response`).
- Output: the verdict in §7. Emits a `harmful_intent` `SecurityFinding` with
  per-hazard metadata.
- Language: English at minimum; multilingual is a stretch goal with its own eval
  slice (§6).
- Must **not** double-count injection/jailbreak — those stay with the injection
  detectors. The safety judge classifies intent regardless of framing.

### Non-functional
- Latency: p95 **≤ 15 ms CPU / ≤ 3 ms GPU** for the encoder (inline budget).
- Throughput: must not reduce proxy max RPS by >5% when enabled inline.
- Determinism: identical input → identical verdict.
- Fail-open: a model/load/timeout failure must never change the request outcome
  vs the no-judge baseline (matches the existing judge-tier policy). The
  placeholder already enforces this (no model → no findings).
- Size: prefer ≤ ~450M params so CPU inline stays viable for self-hosters.

---

## 4. Training datasets

**Leakage rule (hard):** the four eval suites (AdvBench, HarmBench, ASB,
AILuminate) and the over-defense sets (NotInject, XSTest) are **held out for
evaluation only**. Do not train on them. Dedup train↔eval by normalized text +
near-dup (MinHash) and report the overlap count in the model report.

### Positives (harmful) — train sources
| Dataset | What | Notes |
|---|---|---|
| WildGuardMix (AllenAI) | 92k prompts + responses labeled harmful/benign + refusal | purpose-built; primary |
| BeaverTails (PKU-Alignment) | 330k QA, 14 harm categories | broad category coverage |
| Aegis-AI-Content-Safety (NVIDIA) | annotated to a safety taxonomy | taxonomy alignment |
| Anthropic hh-rlhf red-team-attempts | human red-team prompts | realistic attacker phrasing |
| SafeRLHF / BeaverTails-Eval, DoNotAnswer, MaliciousInstruct, SALAD-Bench | assorted harmful instructions | breadth + hard cases |
| ToxiGen | implicit/subtle toxicity (hate) | license-gated — confirm before use |

### Hard-negatives (benign) — critical to avoid over-defense
| Dataset | What | Notes |
|---|---|---|
| OR-Bench | over-refusal probes (benign that looks harmful) | the main over-defense trainer |
| Benign chat (OASST / Dolly / Alpaca subset) | ordinary requests | base negatives |
| Security-research-benign | discussing security without eliciting harm | the AdvBench-adjacent false-positive trap |
| Existing `benchmarks/datasets/benign_samples.json` | our curated benign | in-domain negatives |

Target a balanced, deduped corpus with explicit hazard labels (map each source's
labels onto the §2 taxonomy; multi-hot). Hold a stratified 10% internal test
split in addition to the external held-out suites.

---

## 5. Eval suite & acceptance gates

Reuse the existing harness (`llmtrace-benchmarks`, `--analyzer safety`). Gates
(**proposed — for sign-off**; today's ensemble in parentheses):

| Gate | Target | Today |
|---|---|---|
| Harm recall, held-out suites (AdvBench/HarmBench/ASB/AILuminate) | **≥ 90% overall** | ~6.8% |
| Per-hazard recall (each of the 12) | **≥ 80%** | n/a |
| Over-defense FPR (NotInject D1–D3, XSTest-safe, benign corpus) | **≤ 3% FPR** | ensemble ~0% (must not regress) |
| Internal held-out test F1 | **≥ 0.90** | n/a |
| Robustness slice (paraphrase + light obfuscation + multilingual) | recall drop **≤ 10 pts** | n/a |
| Latency p95 (encoder, inline) | **≤ 15 ms CPU / ≤ 3 ms GPU** | n/a |
| Calibration | FPR@operating-point curve via `fpr_calibration` harness; threshold chosen at ≤3% FPR | reuse existing |

Acceptance = **all gates pass** on held-out data. The over-defense gate is
non-negotiable: a high-recall model that over-blocks benign traffic is a
regression on the work already done for NotInject/XSTest.

Run:
```bash
SAFETY_MODEL_ID=<hf-id-or-path> \
cargo run --release -p llmtrace-benchmarks -- \
  --analyzer safety --suite advbench --suite harmbench --suite asb \
  --suite ailuminate --suite notinject --suite xstest \
  --output-dir benchmarks/results/safety
```

---

## 6. Runtime output contract

```
HarmfulIntentVerdict {
  label: "safe" | "unsafe",          // unsafe = max_score >= threshold
  score: f64,                        // max hazard probability, 0.0–1.0
  categories: { <hazard_code>: f64 },// per-hazard probability (multi-label)
  predicted_categories: [<hazard_code>...],
  model_version: string,
}
```

Mapped onto the detector's `SecurityFinding`:
- `finding_type = "harmful_intent"`
- `confidence_score = score`
- `severity` from score (Low/Medium/High/Critical bands; hard hazards `cse`/`iwp`
  may be floored to Critical by policy)
- `metadata`: `categories` (csv), `max_category_score`, `model_version`,
  `detector = "safety_judge"`

---

## 7. Required model report (model card + eval report)

The trained model must ship with a **model card** and a machine-readable
**eval report**. The eval report gates promotion out of placeholder mode.

### Model card (markdown)
1. Identity — name, version, base arch, param count, license.
2. Intended use + out-of-scope use.
3. Taxonomy — the §2 hazards.
4. Training data — sources, sizes, label provenance, taxonomy mapping, **train↔eval
   dedup/overlap counts** (leakage statement).
5. Eval results — the JSON below, plus the §5 gate pass/fail table.
6. Calibration — chosen threshold and recall/FPR at that operating point.
7. Limitations & known failure modes.
8. Reproducibility — training config, seed, data snapshot hash, git commit.

### Eval report (JSON schema)
```json
{
  "model_id": "string",
  "model_version": "string",
  "commit": "string",
  "created_at": "ISO-8601",
  "taxonomy": ["vcr","ncr","src","cse","iwp","ssh","hte","prv","ipv","dfm","sxc","spc"],
  "operating_point": { "threshold": 0.0, "fpr": 0.0, "recall": 0.0 },
  "suites": {
    "<suite>": { "n": 0, "recall": 0.0, "precision": 0.0, "f1": 0.0, "fpr": 0.0 }
  },
  "per_hazard": { "<hazard>": { "n": 0, "recall": 0.0, "precision": 0.0 } },
  "over_defense": { "notinject_fpr": 0.0, "xstest_fpr": 0.0, "benign_fpr": 0.0 },
  "robustness": { "paraphrase_recall": 0.0, "obfuscation_recall": 0.0, "multilingual_recall": 0.0 },
  "latency_ms": { "cpu_p50": 0.0, "cpu_p95": 0.0, "gpu_p95": 0.0 },
  "leakage": { "train_eval_overlap": 0 },
  "gates": { "harm_recall": "pass|fail", "over_defense": "pass|fail", "latency": "pass|fail", "robustness": "pass|fail" }
}
```

---

## 8. Integration plan (after gates pass)

1. Set `SafetyJudgeConfig.model_id` (proxy config) → detector activates.
2. Wire `SafetyJudgeAnalyzer` into `EnsembleSecurityAnalyzer` as an independent
   voter; `harmful_intent` contributes to `security_score` and per-category
   action policy (`action_policy.rs`). Keep it parallel to the injection voters
   (no shared weights).
3. Rollout: **shadow** (log-only, measure live FPR/recall) → **warn** →
   **enforce**, per-tenant via feature flags. Fail-open throughout.

---

## 9. Training infrastructure

A DeBERTa-v3 fine-tune is a few GPU-hours on a single card. Run it via the
adjacent `autoresearch-rl` framework targeting Basilica GPUs (use a stable
datacenter provider — hyperstack/shadeform, not masscompute spot, which reclaimed
mid-job during the eval work). The recipe is a standard HF sequence-classification
fine-tune (multi-label BCE), not RLHF.

---

## 10. Open decisions (for sign-off)

1. **Architecture**: confirm encoder-inline + generative-guard-at-judge-tier (my
   recommendation), or go straight to a generative guard everywhere.
2. **Base model**: DeBERTa-v3-base (faster, CPU-friendly) vs -large (higher
   ceiling, GPU-leaning).
3. **Gate thresholds** in §5 (esp. the 90% recall / 3% FPR targets).
4. **ToxiGen** inclusion (license/governance) for the `hte` hazard.
5. Binary-only v1 vs full 12-label multi-label v1 (recommend multi-label for
   per-category policy from day one).
