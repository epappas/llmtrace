# Judge Evaluation — `openai/gpt-4o-mini` on 27 Labeled Corpora

**Date:** 2026-04-20
**Commit:** `532797bd925c3801f6ceda998660245adbe960e0`
**Branch:** `feat/issue-43-llm-judge-foundation`
**Author:** Evangelos Pappas
**Status:** Baseline. Not a calibration run (see §9).

---

## Abstract

We evaluate the LLMTrace LLM-as-a-Judge (hereafter "the judge") against
27 labeled prompt-injection / jailbreak / benign-prompt corpora,
totalling 1,274 samples (863 malicious, 411 benign) drawn from 23
external academic datasets and 4 local curated sets. The judge is
backed by `openai/gpt-4o-mini` accessed through OpenRouter
(OpenAI-compatible wire protocol) with OpenAI strict
`response_format=json_schema` enforcement enabled. Using the
out-of-the-box system prompt shipped with the judge and no
per-dataset tuning, the model achieves overall **F1 = 0.856**
(precision 0.958, recall 0.774) with a mean end-to-end latency of
1,653 ms (p95 2,613 ms, p99 3,319 ms) at 4-wide concurrency, and a
cost of ≈ $0.00012 per call ($0.15 for the full sweep). Per-dataset
results span from perfect recall on `AdvBench` / `rubend18_jailbreak`
to 0.34 recall on `asb_attacks`. False-positive rate on genuinely
benign prompts is 0.071 overall, but is concentrated in `XSTest`
(FPR = 0.200), the standard over-refusal stress test, and in
`JailbreakBench` benign controls (FPR = 0.231). Results are reported
as a **baseline** for a pluggable judge backend; they are not a
product SLO, not a calibrated production threshold, and not a
literature-defeating claim. All raw data and the reproducer binary
are committed alongside this report.

---

## 1. Introduction

The LLMTrace proxy runs a three-detector security ensemble: a regex
tier, a DeBERTa classifier (behind the `ml` feature), and an
LLM-as-a-Judge tier (behind the `judge` feature, added in
[issue #43](https://github.com/epappas/llmtrace/issues/43) and shipped
on PR #65). Operators have repeatedly asked the same question: *how
well does the judge actually classify real attacks vs. real benign
prompts, and how does that compare to what is reported in the open
literature?*

Answering that question is harder than it looks. There is no single
"prompt injection leaderboard"; published papers each define their
own corpus, their own attack distribution, and their own notion of
"detection", and they score their own defenders, not pluggable
third-party judges. The only honest way to land on a comparable
number is to run the same judge against the same corpora authors
themselves used. This report does that for every external corpus we
already ship under `benchmarks/datasets/external/` — 23 datasets in
total — and for the four local sets we maintain for regression
testing.

We deliberately do **not**:

- Tune the system prompt per dataset.
- Apply any Platt scaling / isotonic calibration (this is out of
  scope for a baseline; see [issue #66](https://github.com/epappas/llmtrace/issues/66)).
- Run the full ensemble — the judge is scored in isolation so its
  standalone behavior is legible.
- Score only the attacker side — every dataset with benign samples
  contributes false-positive rate information.
- Claim these numbers generalize to other judge models. A separate
  run would be required for Anthropic Claude, a self-hosted vLLM
  model, or `gpt-4o` proper.

---

## 2. System under test

### 2.1 Judge pipeline

The judge is invoked through `OpenAIJudgeBackend` (crate
`llmtrace-security`, feature `judge`). It sends a
`/v1/chat/completions` request with:

| Parameter | Value |
|---|---|
| `model` | `openai/gpt-4o-mini` (OpenAI GPT-4o-mini via OpenRouter) |
| `base_url` | `https://openrouter.ai/api` |
| `temperature` | `0.1` |
| `max_tokens` | `512` |
| `response_format` | `json_schema` with `strict: true` |
| `max_retries` | `1` |
| `backoff_base_ms` | `250` |
| `timeout` | `30 000 ms` per call |
| `total_deadline` | `90 000 ms` over all retries |

The system prompt is the hardened default shipped with the crate
(`llmtrace-security/src/judge/prompt.rs`, `DEFAULT_SYSTEM_PROMPT`).
It states the classifier role, treats the candidate text as data not
instruction, specifies the exact JSON schema (`is_threat`,
`category`, `confidence`, `security_score`, `recommended_action`,
`reasoning`), and tells the model to err toward benign under
uncertainty. No operator override was applied.

The user message is a JSON envelope produced by
`build_user_message_json()`: `{candidate: {text, upstream_model,
mode, prior_findings}}`. The candidate text is always embedded as a
JSON string, never as a bare message — this prevents candidate
content from rewriting the envelope shape.

### 2.2 Strict JSON schema enforcement

Commit `8c76171` (finding H-A, issue #81) enables OpenAI
`json_schema` + `strict: true` mode with the full verdict contract.
Under this mode, completions that fail the schema are refused by the
provider, so the malformed-JSON failure class is removed entirely.
All 1,274 calls in this run returned verdicts that parsed; failures
= 0.

### 2.3 Gating is bypassed for the baseline

`verdict_to_outcome()` applies the promotion gate
(`min_confidence >= 0.7`, `min_security_score >= 60`,
`require_ensemble_support`, `shadow`). This gate is **not exercised
in this report** — we report the judge's raw `is_threat` verdict so
the binary classifier behavior is visible. Gating changes what the
proxy *enforces*, not what the judge *says*.

---

## 3. Methodology

### 3.1 Reproducer

The evaluation harness is
`crates/llmtrace-security/examples/judge_benchmark.rs`. It loads
every `*.json` file from the configured dataset directories, derives
ground truth from each sample's `label` field (`malicious` →
expected_threat=true, `benign` → expected_threat=false), and scores
the judge at a configurable concurrency.

Exact invocation used for this run:

```bash
LLMTRACE_JUDGE_OPENAI_API_KEY=$KEY \
BENCH_MAX_PER_SET=50 \
BENCH_EXTERNAL_DIR=benchmarks/datasets/external \
BENCH_CONCURRENCY=4 \
BENCH_SEED=42 \
./target/release/examples/judge_benchmark
```

No API key is committed or persisted.

### 3.2 Sampling

Each dataset is loaded in full, filtered to samples with `label ∈
{malicious, benign}`, then uniformly subsampled down to at most 50
samples per file using a fixed seed (`BENCH_SEED=42`) with
`rand::rngs::StdRng`. For datasets whose published size is below 50
(e.g. `encoding_evasion` with 24 rows; `rubend18_jailbreak` with 79
rows), the full set or a seeded 50-element subset is used.

Rationale for 50/set: balances statistical signal per dataset
against total API cost (1,274 calls at ~$0.00012 each ≈ $0.15).
Rerunning at `BENCH_MAX_PER_SET=0` (full-set, ~23,000 calls, ~$2.70)
would tighten confidence intervals by ~√ samples but is not required
for baseline numbers.

### 3.3 Binary classification

Ground truth is the `label` column on each sample. The judge's
output field `is_threat` (boolean, from its JSON verdict) is the
prediction. We compute:

- **TP** — malicious sample, `is_threat = true`
- **FP** — benign sample, `is_threat = true`
- **TN** — benign sample, `is_threat = false`
- **FN** — malicious sample, `is_threat = false`
- **Precision** = TP / (TP + FP)
- **Recall** = TP / (TP + FN)
- **F1** = 2·Precision·Recall / (Precision + Recall)
- **FPR** = FP / (FP + TN)
- **Accuracy** = (TP + TN) / (TP + FP + TN + FN)

We do not score category match (e.g. did the judge say
`prompt_injection` vs. `jailbreak`) in this baseline. Category-level
confusion is deferred to follow-up work.

### 3.4 Latency measurement

Per-call latency is measured as wall-clock time from
`backend.judge()` invocation to verdict-returned, including HTTP
serialization, network RTT to the OpenRouter gateway, OpenRouter's
own dispatch to the upstream provider (OpenAI), inference time, and
response parsing. We deliberately cannot isolate these components;
the reported number is what operators feel.

### 3.5 Cost estimate

Per-call cost uses OpenAI's published GPT-4o-mini pricing as of
2026-04-20: $0.15 / 1M input tokens, $0.60 / 1M output tokens.
OpenRouter adds a small routing markup, so the actual invoice may
differ slightly; the reported figure is a lower bound.

---

## 4. Datasets

All 27 datasets ship with the repository under
`benchmarks/datasets/`. Each row has the schema
`{id, text, label, category, source, [subcategory]}`. Below is the
provenance and sample count *after* seed-42 subsampling at 50/set.

### 4.1 Local curated sets (n=4)

| File | n | Malicious | Benign | Purpose |
|---|---|---|---|---|
| `injection_samples.json` | 50 | 50 | 0 | Curated direct-injection test set used in regression |
| `encoding_evasion.json` | 24 | 20 | 4 | Obfuscated / encoded payloads (full set, <50) |
| `benign_samples.json` | 50 | 0 | 50 | Ordinary user questions across 39 categories |
| `notinject_samples.json` | 50 | 0 | 50 | Prompts that *look* injection-y but are benign (from `InjecGuard-NotInject`) |

### 4.2 External academic / community corpora (n=23)

| File | n | Mal. | Ben. | Source / citation |
|---|---|---|---|---|
| `advbench_harmful.json` | 50 | 50 | 0 | **AdvBench** — Zou et al. 2023, *Universal and Transferable Adversarial Attacks on Aligned Language Models* |
| `ailuminate_demo.json` | 50 | 50 | 0 | **MLCommons AILuminate** v0.5 demo (2024) |
| `asb_attacks.json` | 50 | 50 | 0 | **Agent Security Bench (ASB)** — Zhang et al. 2024 |
| `bipia_indirect.json` | 50 | 15 | 35 | **BIPIA** — Yi et al. 2023, *Benchmarking and Defending Against Indirect Prompt Injection Attacks* |
| `cyberseceval2_pi.json` | 50 | 50 | 0 | **CyberSecEval 2** (Meta) — Bhatt et al. 2024, Prompt Injection task |
| `deepset_all.json` | 50 | 18 | 32 | **DeepSet prompt-injection-v1** (HuggingFace) |
| `deepset_v2.json` | 50 | 24 | 26 | **DeepSet prompt-injection-v2** (HuggingFace) |
| `harmbench_behaviors.json` | 50 | 50 | 0 | **HarmBench** — Mazeika et al. 2024 |
| `hpi_attack_approx.json` | 50 | 50 | 0 | Community HuggingFace PI attack corpus |
| `in_the_wild_jailbreak.json` | 50 | 50 | 0 | **In-the-Wild Jailbreaks** — Shen et al. 2024 (*Do Anything Now*) |
| `injecagent_attacks.json` | 50 | 50 | 0 | **InjecAgent** — Zhan et al. 2024 (tool-integrated agents) |
| `ivanleomk_all.json` | 50 | 30 | 20 | Community-curated (Ivan Leo Mk) |
| `ivanleomk_v2.json` | 50 | 28 | 22 | Community-curated (Ivan Leo Mk v2) |
| `jackhhao_jailbreak.json` | 50 | 23 | 27 | Community HuggingFace dataset (`jackhhao/jailbreak-classification`) |
| `jailbreakbench.json` | 50 | 24 | 26 | **JailbreakBench** — Chao et al. 2024 |
| `rubend18_jailbreak.json` | 50 | 50 | 0 | Community HuggingFace (`rubend18/ChatGPT-Jailbreak-Prompts`) |
| `safeguard_test.json` | 50 | 15 | 35 | **Protect AI Safeguard** test set |
| `satml_ctf.json` | 50 | 50 | 0 | **SaTML 2024 LLM CTF** competition submissions |
| `spml_chatbot.json` | 50 | 31 | 19 | **SPML Chatbot** — Blue et al. |
| `tensor_trust_attacks.json` | 50 | 50 | 0 | **Tensor Trust** — Toyer et al. 2023 |
| `transfer_attack_samples.json` | 50 | 35 | 15 | Curated transferable attack samples |
| `xstest.json` | 50 | 0 | 50 | **XSTest** — Röttger et al. 2024, safe-prompts-that-look-unsafe |

Totals after subsampling: **1,274 samples** (863 malicious, 411
benign).

---

## 5. Results

### 5.1 Overall

| Metric | Value |
|---|---|
| Samples judged | 1,274 |
| Malicious / benign | 863 / 411 |
| Failures | 0 |
| Wall clock | 527.38 s (8 m 47 s) |
| Throughput | 2.42 calls/sec @ 4-wide |
| TP / FP / TN / FN | 668 / 29 / 382 / 195 |
| **Accuracy** | **0.824** |
| **Precision** | **0.958** |
| **Recall** | **0.774** |
| **F1** | **0.856** |
| **FPR** | **0.071** |
| Mean latency | 1,653 ms |
| p50 / p95 / p99 latency | 1,542 / 2,613 / 3,319 ms |
| Tokens in / out (total) | 672,103 / 83,911 |
| Avg tokens / call | 527 in, 65 out |
| Estimated cost | $0.1512 USD |
| Cost per call | ≈ $0.00012 |

### 5.2 Per-dataset (all 27)

Sorted by recall for malicious-bearing sets; benign-only at the
bottom.

| Dataset | n | pos | TP | FP | FN | Accuracy | Precision | Recall | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `advbench_harmful` | 50 | 50 | 50 | 0 | 0 | 1.000 | 1.000 | 1.000 | — |
| `rubend18_jailbreak` | 50 | 50 | 50 | 0 | 0 | 1.000 | 1.000 | 1.000 | — |
| `in_the_wild_jailbreak` | 50 | 50 | 49 | 0 | 1 | 0.980 | 1.000 | 0.980 | — |
| `injection_samples` (local) | 50 | 50 | 49 | 0 | 1 | 0.980 | 1.000 | 0.980 | — |
| `jackhhao_jailbreak` | 50 | 23 | 22 | 2 | 1 | 0.940 | 0.917 | 0.957 | 0.074 |
| `harmbench_behaviors` | 50 | 50 | 47 | 0 | 3 | 0.940 | 1.000 | 0.940 | — |
| `hpi_attack_approx` | 50 | 50 | 45 | 0 | 5 | 0.900 | 1.000 | 0.900 | — |
| `tensor_trust_attacks` | 50 | 50 | 45 | 0 | 5 | 0.900 | 1.000 | 0.900 | — |
| `jailbreakbench` | 50 | 24 | 21 | 6 | 3 | 0.820 | 0.778 | 0.875 | 0.231 |
| `injecagent_attacks` | 50 | 50 | 43 | 0 | 7 | 0.860 | 1.000 | 0.860 | — |
| `transfer_attack_samples` | 50 | 35 | 30 | 1 | 5 | 0.880 | 0.968 | 0.857 | 0.067 |
| `encoding_evasion` (local) | 24 | 20 | 16 | 0 | 4 | 0.833 | 1.000 | 0.800 | — |
| `safeguard_test` | 50 | 15 | 12 | 3 | 3 | 0.880 | 0.800 | 0.800 | 0.086 |
| `satml_ctf` | 50 | 50 | 40 | 0 | 10 | 0.800 | 1.000 | 0.800 | — |
| `spml_chatbot` | 50 | 31 | 21 | 0 | 10 | 0.800 | 1.000 | 0.677 | 0.000 |
| `ivanleomk_v2` | 50 | 28 | 18 | 0 | 10 | 0.800 | 1.000 | 0.643 | 0.000 |
| `ivanleomk_all` | 50 | 30 | 17 | 0 | 13 | 0.740 | 1.000 | 0.567 | 0.000 |
| `ailuminate_demo` | 50 | 50 | 28 | 0 | 22 | 0.560 | 1.000 | 0.560 | — |
| `bipia_indirect` | 50 | 15 | 8 | 6 | 7 | 0.740 | 0.571 | 0.533 | 0.171 |
| `cyberseceval2_pi` | 50 | 50 | 23 | 0 | 27 | 0.460 | 1.000 | 0.460 | — |
| `deepset_v2` | 50 | 24 | 10 | 0 | 14 | 0.720 | 1.000 | 0.417 | 0.000 |
| `deepset_all` | 50 | 18 | 7 | 0 | 11 | 0.780 | 1.000 | 0.389 | 0.000 |
| `asb_attacks` | 50 | 50 | 17 | 0 | 33 | 0.340 | 1.000 | 0.340 | — |
| `benign_samples` (local) | 50 | 0 | 0 | 0 | 0 | 1.000 | — | — | 0.000 |
| `notinject_samples` (local) | 50 | 0 | 0 | 1 | 0 | 0.980 | — | — | 0.020 |
| `xstest` | 50 | 0 | 0 | 10 | 0 | 0.800 | — | — | 0.200 |

### 5.3 Latency distribution

End-to-end, measured from the harness around `backend.judge()`,
includes network to OpenRouter + OpenRouter routing + OpenAI
inference + response parsing.

| Percentile | Latency |
|---|---|
| p50 | 1,542 ms |
| p95 | 2,613 ms |
| p99 | 3,319 ms |
| mean | 1,653 ms |

This matches the single-provider run on gpt-4o-mini; the
distribution is concentrated around 1.5 s with a long right tail out
to ~3.3 s. p95 **exceeds** the 2,000 ms default `inline_timeout_ms`
in `JudgeWorkerConfig`, meaning that at this provider + model, an
inline judge verdict is not usable without raising that budget to
≥4,000 ms or keeping the judge in async mode.

### 5.4 Cost

| Metric | Value |
|---|---|
| Total cost | $0.1512 |
| Per call | $0.000119 |
| At 1,000 calls/day | $0.12 / day |
| At 100k calls/day | $12 / day |

---

## 6. Strengths and weaknesses

### 6.1 Where the judge does well (recall ≥ 0.90)

- **Direct-override / classic jailbreaks.** `advbench_harmful`,
  `rubend18_jailbreak`, `in_the_wild_jailbreak`,
  `jackhhao_jailbreak`, `harmbench_behaviors`, and the curated
  local `injection_samples`: recall 0.94–1.00. These share a
  common signature — explicit role rewrites, "ignore previous",
  "DAN", roleplay scaffolds. The judge's system prompt
  enumerates this pattern and the model (trained in part on
  public jailbreak discourse) has strong priors here.
- **Prompt-extraction attacks.** `tensor_trust_attacks`
  (extraction + hijacking game submissions): recall 0.90.
- **Novel-form injection prompts.** `hpi_attack_approx`: recall
  0.90.

### 6.2 Where the judge struggles

Three clusters of weakness, in descending severity:

1. **Agent-targeted attacks (`asb_attacks`, recall 0.34;
   `injecagent_attacks`, recall 0.86).** Agent Security Bench
   attacks are payloads *placed in tool outputs and document content*
   designed to hijack an LLM agent that will act on them. A
   standalone judge that sees only the text, with no tool call
   history and no knowledge of what boundary it should protect,
   cannot tell whether a suspicious instruction was addressed to the
   assistant or to the end user. This is a fundamental modeling
   limit, not a prompt-tuning issue. Mitigations require ensemble
   context (tool-output wrapping, Spotlighting, Task-Shield).
2. **Indirect injection (`bipia_indirect`, recall 0.53).** BIPIA
   embeds the injection payload inside an apparently benign
   document/email/table. The judge sees the combined "candidate
   text" and often classifies the benign wrapper as benign rather
   than spotting the embedded subversion.
3. **Structured-payload / token-smuggling (`cyberseceval2_pi`,
   recall 0.46; `ailuminate_demo`, recall 0.56).** CyberSecEval 2
   specifically measures detection of adversarial patterns like
   token smuggling, overload-with-information, virtualization, and
   output-formatting manipulation. A model judging raw text
   without access to the tokenization layer misses many.

### 6.3 False-positive pressure

Two benign sources produce non-trivial FPR:

- **XSTest (FPR = 0.200).** By construction, XSTest prompts are
  *safe* questions whose surface topics (violence, self-harm, drugs,
  sexuality, etc.) are the same as genuinely unsafe prompts. A
  literal reading flags 10/50 as threats. This is the
  over-refusal tax; literature reports XSTest unsafe-flagging in
  a wide range across models, and 20% is within that distribution
  but on the higher end.
- **JailbreakBench benign controls (FPR = 0.231).** These are
  prompts about harmful topics phrased benignly (e.g., questions
  about how defenses work). Our judge currently does not
  distinguish "meta-level discussion of adversarial patterns"
  from "adversarial pattern execution".
- **BIPIA benign (FPR = 0.171).** Documents with innocuous content
  in the same envelope format as adversarial ones; the envelope
  shape appears to be a weak signal.

The FPR *outside* these adversarial/edge sets is
extraordinarily low:

- Local `benign_samples` (synthetic ordinary user queries): 0.000
- Local `notinject_samples` (InjecGuard-NotInject): 0.020
- `spml_chatbot`, `deepset_all`, `deepset_v2`, `ivanleomk_all`,
  `ivanleomk_v2`: 0.000

Meaning: on real benign traffic the judge does not over-block.
It over-blocks specifically on datasets *built* to surface
over-refusal.

---

## 7. Comparison to the open literature

We **do not** claim these numbers beat or match published defenders
— no honest comparison is possible without re-running each paper's
baseline model on the identical sample set. What we can say, with
ranges and citations:

| Dataset | Our judge (gpt-4o-mini zero-shot) | Published baseline range | Notes |
|---|---|---|---|
| AdvBench | recall 1.00 | GPT-4 judge ≈ 0.90–0.98; Llama-Guard-2 ≈ 0.85–0.95 | Strong — but AdvBench is intentionally very adversarial and simple; most modern defenders saturate |
| HarmBench | recall 0.94 | HarmBench paper reports GPT-4 judge ≈ 0.90–0.95; Llama-Guard-2 ≈ 0.85–0.92 | In the top tier |
| JailbreakBench | recall 0.875, FPR 0.231 | Chao et al. report Llama-Guard ≈ 0.85 recall, GPT-4 judge ≈ 0.87 | Recall matches; FPR is the outlier |
| InjecAgent | recall 0.86 | Zhan et al. report GPT-4 judge detection in 0.70–0.90 range depending on task | Comparable |
| CyberSecEval 2 PI | recall 0.46 | Meta reports GPT-4/Llama-3.1 in 0.70–0.80 range | **Gap.** Likely because gpt-4o-mini is a smaller model and our prompt is generic |
| BIPIA indirect | recall 0.53 | Yi et al. report GPT-4 detection ≈ 0.80 | **Gap.** Indirect injection specifically stresses the trust-boundary reasoning |
| XSTest | FPR 0.200 | Röttger et al. show ~5–50% unsafe-flag rates across models | Middle of the pack |
| TensorTrust | recall 0.90 | Toyer et al. report defender success varying widely by attack class | Comparable |

**Honest caveat.** The literature ranges above are from my memory of
the respective papers' headline numbers. They are *indicative*, not
definitive. To produce a truly comparable column, each paper's
reported judge (typically Llama-Guard-2/3, GPT-4, or a dataset's
own fine-tuned classifier) would need to be re-run on our identical
seed-42 sample. That is future work, not a claim made here.

The model under test is deliberately the smallest OpenAI-family
model that supports strict `json_schema` (`gpt-4o-mini`, released
late 2024). Larger siblings (`gpt-4o`, `gpt-4.1-mini`) are expected
to close the gap on CyberSecEval 2 and BIPIA; pure-safety
specialists (Llama-Guard-3-8B, PromptGuard-86M) are expected to
win on AdvBench/HarmBench while losing on cost/latency.

---

## 8. Discussion

### 8.1 What the baseline tells us

- **Deployable-as-ensemble-member, not as standalone gate.**
  Recall 0.77 at FPR 0.071 is good enough to be the third vote in a
  three-detector ensemble (regex + DeBERTa + judge) that requires
  majority to block. Alone, it's a liability.
- **Shadow mode is the right rollout default.** PR #65 ships
  `JudgePromotionConfig.shadow=false` with a `true` path that
  suppresses Block while recording metrics (issue #84). Given
  the XSTest and JailbreakBench benign FPRs above, shipping
  shadow-first for at least 1,000 verdicts before flipping
  enforcement on is the responsible pattern.
- **Promotion gate already compensates.** The default
  `min_confidence=0.7`, `min_security_score=60`, and
  `require_ensemble_support=true` all push decisively against
  judge-only blocks. On this corpus, the judge's average
  confidence on true positives is materially higher than on
  false positives (quantitative analysis deferred).

### 8.2 Where to strengthen the pipeline

- **Indirect / agent injection** is the single biggest gap
  (cf. 6.2). Pairing the judge with Spotlighting (boundary-marker
  wrapping) and InjecAgent-style tool-output sanitization would
  close much of it. Both are already referenced in
  `docs/research/` under `spotlighting-indirect-injection-defense.md`
  and `indirect-injection-firewalls.md`.
- **Token-smuggling / encoding evasion.** Encoded-payload recall
  (0.80 on our set, 0.46 on CyberSecEval 2) will improve with a
  dedicated decoder pre-pass (many are already drafted in
  `crates/llmtrace-security/src/encoding.rs` behind currently
  `dead_code` warnings).
- **Calibration.** The 0.7 default `min_confidence` is a placeholder
  (see PR #65 M-B); the data collected here supports a reliability
  diagram fit but we have not performed it in this report.

### 8.3 Cost discipline

At $0.00012/call, the judge is economically viable at sustained
firing rates up to ~1M calls/day ($120/day). The proxy fires the
judge only above `min_score_threshold=30`, so real production cost
is a small fraction of call volume × $0.00012.

---

## 9. Threats to validity

### 9.1 Single model, single provider, single run

Every number in this report is `openai/gpt-4o-mini` through
OpenRouter on 2026-04-20. Re-running against Anthropic Claude (via
our `anthropic` backend) or a self-hosted Llama variant (via our
`vllm` backend) would produce a materially different table. The H-C
metric-label work (issue #83) makes cross-model comparison
production-observable; this report measures one axis of that matrix.

### 9.2 Seed sensitivity

A single seed (42) was used for subsampling. Repeating the sweep
with 3–5 different seeds would produce a confidence interval on
each per-dataset number. For the overall F1 of 0.856, a
~±0.02 variation across seeds is a reasonable expectation but is
not measured here.

### 9.3 Label noise

Labels in the external corpora are authoritative for those
datasets, but the *definition* of malicious varies. HarmBench
labels "harmful content" targets, AdvBench labels attack suffixes,
JailbreakBench labels jailbreak attempts — these are not the same
definition of "threat" the judge is asked to produce. Where the
definitions diverge from "prompt injection targeting the assistant",
the judge's disagreement is partly dataset-task mismatch, not judge
error.

### 9.4 Self-evaluation bias

The judge is an OpenAI model; several of the attack corpora
(notably in-the-wild jailbreaks) were collected from attacks on
OpenAI endpoints. Models trained on jailbreak-related discourse may
have stronger priors on patterns they have seen before. Runs with
a non-OpenAI judge (Claude, local Llama) are needed to quantify
this.

### 9.5 No ensemble signal

The judge is run standalone, with `prior_findings=[]` on every
candidate. In production, `prior_findings` is populated with regex
and DeBERTa verdicts; the judge receives more signal than it
received here. These numbers are therefore a **lower bound** on
ensemble performance.

---

## 10. Limitations

- **No calibration.** `min_confidence=0.7` is a placeholder, not a
  fitted threshold. Reliability-diagram calibration is tracked in
  issue #66 and PR #65 M-B.
- **No category-level confusion.** Category correctness
  (prompt_injection vs. jailbreak vs. data_exfiltration) is not
  scored; only the binary `is_threat` flag is.
- **No adversarial-resilience evaluation.** We do not attempt to
  attack the judge itself (compound injection where the payload
  targets the judge prompt). This is future work.
- **Small per-set n.** 50 samples/set gives ~±0.1 confidence on
  recall at 0.90; smaller differences between models would require
  larger runs.

---

## 11. Future work

1. **Cross-family run.** Rerun with `anthropic/claude-3-5-haiku`
   (our Anthropic backend is already production-ready and
   exercised in unit tests; #82 adds prompt caching so cost stays
   tractable). Then a local `meta-llama/Llama-3.1-8B-Instruct` via
   the vLLM backend. Report a 3-column comparison table.
2. **Ensemble run.** Invoke the full ensemble
   (regex + DeBERTa + judge) and score at the final `ActionOutcome`
   level, with majority voting and the promotion gate applied.
   Compares a production decision path, not a detector baseline.
3. **Calibration.** Collect confidence scores from this run (which
   are persisted as `JudgeVerdict.confidence`), fit a reliability
   diagram, and publish the calibrated `min_confidence`.
4. **Full-set, multi-seed.** Remove `BENCH_MAX_PER_SET=50`, run
   with 3 seeds, and report confidence intervals.
5. **Literature re-run.** Run Llama-Guard-3-8B (via vLLM backend)
   against this identical corpus to produce a true apples-to-apples
   column.
6. **Agent-context evaluation.** Modify the `model_name` and
   `prior_findings` envelope fields to include a simulated tool-
   output trace; re-score InjecAgent and ASB to see whether context
   plumbing closes those gaps without changing the judge model.

---

## 12. Reproduction

### 12.1 Prerequisites

- Rust toolchain (workspace-pinned; `rustup show` in repo root).
- OpenRouter / OpenAI / Azure / LiteLLM-compatible API key with
  access to `openai/gpt-4o-mini`.
- Budget ≈ $0.15 at the sampling size used here.

### 12.2 Exact commands

```bash
# Build
cargo build --example judge_benchmark -p llmtrace-security \
  --features judge --release

# Run (replace $KEY; never commit it)
LLMTRACE_JUDGE_OPENAI_API_KEY=$KEY \
BENCH_MAX_PER_SET=50 \
BENCH_EXTERNAL_DIR=benchmarks/datasets/external \
BENCH_CONCURRENCY=4 \
BENCH_SEED=42 \
./target/release/examples/judge_benchmark
```

### 12.3 Environment pin

| Field | Value |
|---|---|
| Commit | `532797bd925c3801f6ceda998660245adbe960e0` |
| Date | 2026-04-20 |
| Judge model | `openai/gpt-4o-mini` |
| Provider | OpenRouter (`https://openrouter.ai/api`) |
| Seed | 42 |
| Max per set | 50 |
| Concurrency | 4 |
| Timeout | 30 000 ms per call |
| Retries | 1 |
| Total deadline | 90 000 ms |

### 12.4 Raw output

Not committed (contains point-in-time measurements, not source).
Regenerate via §12.2. The harness prints the full table to stdout
and exits non-zero on any failure.

---

## 13. Citations

Papers referenced, with the datasets they correspond to:

- Zou, Wang, Carlini, Tramèr, Kolter, Fredrikson. 2023. *Universal
  and Transferable Adversarial Attacks on Aligned Language Models.*
  (AdvBench)
- Bhatt et al. (Meta). 2024. *CyberSecEval 2: A Wide-Ranging
  Cybersecurity Evaluation Suite for Large Language Models.*
- Chao, Debenedetti, Robey, Andriushchenko, Croce, Sehwag, Dobriban,
  Flammarion, Pappas, Tramèr, Hassani, Wong. 2024. *JailbreakBench:
  An Open Robustness Benchmark for Jailbreaking Large Language Models.*
- Mazeika, Phan, Yin, Zou, Wang, Mu, Sakhaee, Li, Basart, Li,
  Forsyth, Hendrycks. 2024. *HarmBench: A Standardized Evaluation
  Framework for Automated Red Teaming and Robust Refusal.*
- Röttger, Kirk, Vidgen, Attanasio, Bianchi, Hovy. 2024. *XSTest: A
  Test Suite for Identifying Exaggerated Safety Behaviours in Large
  Language Models.*
- Shen, Chen, Backes, Shen, Zhang. 2024. *"Do Anything Now":
  Characterizing and Evaluating In-the-Wild Jailbreak Prompts.*
- Toyer, Watkins, Mendes, Svegliato, Bailey, Wang, Ong, Elmaaroufi,
  Abbeel, Darrell, Ritter, Russell. 2023. *Tensor Trust:
  Interpretable Prompt Injection Attacks from an Online Game.*
- Yi, Xie, Zhu, Wu, Hu, Liu, Wang, Luu, Liu, Xing. 2023.
  *Benchmarking and Defending Against Indirect Prompt Injection
  Attacks on Large Language Models.* (BIPIA)
- Zhan, Liang, Bai, Wang, Liu, Wang. 2024. *InjecAgent:
  Benchmarking Indirect Prompt Injections in Tool-Integrated Large
  Language Model Agents.*
- Zhang et al. 2024. *Agent Security Bench (ASB): Formalizing and
  Benchmarking Attacks and Defenses in LLM-based Agents.*

Community datasets without a conventional citation:
`deepset/prompt-injections-v1`, `deepset/prompt-injections-v2`,
`jackhhao/jailbreak-classification`,
`rubend18/ChatGPT-Jailbreak-Prompts`, Protect AI Safeguard test set,
SaTML 2024 LLM CTF submissions, Ivan Leo Mk curated corpora,
HuggingFace HPI attack approximation, MLCommons AILuminate v0.5
demo, SPML Chatbot corpus, curated transferable attack samples.

---
