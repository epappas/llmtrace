# autoresearch-rl Judge Fine-Tuning Plan

**Status:** Planning. Execution tracked under issue [#90][90] with children [#102][102]–[#110][110].
**Target model:** `Qwen/Qwen2.5-0.5B-Instruct` + LoRA adapter, trained via GRPO under the `autoresearch-rl/examples/security-judge` harness.
**Target schema:** LLMTrace's 6-field `JudgeVerdict` (same contract gpt-4o-mini already honours in production).
**Target deployment:** vLLM-served, plugged into the cascade slow tier (issue [#88][88]).
**Companion docs:** [`JUDGE_CASCADE.md`](../architecture/JUDGE_CASCADE.md) · [`LLM_JUDGE.md`](../architecture/LLM_JUDGE.md) · [`results/judge_evaluation_gpt4o_mini_2026-04-20.md`](results/judge_evaluation_gpt4o_mini_2026-04-20.md).

[90]: https://github.com/epappas/llmtrace/issues/90
[88]: https://github.com/epappas/llmtrace/issues/88
[102]: https://github.com/epappas/llmtrace/issues/102
[103]: https://github.com/epappas/llmtrace/issues/103
[104]: https://github.com/epappas/llmtrace/issues/104
[105]: https://github.com/epappas/llmtrace/issues/105
[106]: https://github.com/epappas/llmtrace/issues/106
[107]: https://github.com/epappas/llmtrace/issues/107
[108]: https://github.com/epappas/llmtrace/issues/108
[109]: https://github.com/epappas/llmtrace/issues/109
[110]: https://github.com/epappas/llmtrace/issues/110

---

## 1. Why this plan exists

The `gpt-4o-mini` evaluation published 2026-04-20 proved the judge architecture works end-to-end but at **$0.00012/call and ~2.5 s p95**. For production we want a local alternative that:

- runs on our own infra (no egress cost, no provider rate limits),
- emits exactly the same 6-field verdict gpt-4o-mini does (so LLMTrace needs no code changes),
- performs within 5 points of gpt-4o-mini on binary `is_threat` accuracy,
- is cheap enough to serve on a single small GPU.

Qwen2.5-0.5B-Instruct + a task-specific LoRA is the most parameter-efficient path. The user already has `autoresearch-rl` as a working autonomous training harness — it proposes hyperparameters, trains, evaluates, keeps or discards, iterates. The plan below is about **adapting that harness from 2-field to 6-field output** and executing it to convergence.

## 2. Prerequisites (before any issue starts)

| Item | Status | Owner |
|---|---|---|
| `autoresearch-rl` repo cloned + `uv sync --extra dev` works | ✅ exists | user |
| Basilica GPU access + API key in CI | ⚠️ verify | SRE |
| HuggingFace account with ability to push private repos | ⚠️ verify | ML engineer |
| `gpt-4o-mini` API key for teacher distillation (#103) | ✅ have one | user |
| LLMTrace `judge_benchmark.rs` builds + runs against arbitrary vLLM endpoint | ✅ shipped on `0432bb9` | — |

Two items to confirm before kicking off. Everything else is already in place.

## 3. Phases

### Phase 1 — Data preparation (#102, #103)

**Duration:** 1–2 days.
**Parallel:** yes (both sub-issues can run concurrently).

#### 3.1 Corpus expansion (#102)

The existing 19,186-sample 2-class corpus needs four new columns: `category`, `recommended_action`, `security_score`, `confidence`. See #102 for the full mapping table — the important part is that this is deterministic data engineering, not ML, so one engineer can knock it out in a day.

Output: `autoresearch-rl/examples/security-judge/data/corpus_6field.jsonl`.

#### 3.2 Reasoning distillation (#103)

Run every row through `gpt-4o-mini` with LLMTrace's production system prompt; capture the `reasoning` field as the training target. ~19,000 calls with deduplication at ~$1.50 total cost.

Output: `autoresearch-rl/examples/security-judge/data/corpus_6field_with_reasoning.jsonl`.

This is the only phase where the teacher quality matters. Choosing `gpt-4o-mini` is deliberate — a 0.5B student can realistically learn to match gpt-4o-mini-grade reasoning without needing a frontier model as teacher. Upgrading later is trivial (re-run the script); downgrading is impossible once training rolls.

**Exit criterion:** corpus validated, `label_disagreements.jsonl` triaged (teacher sometimes disagrees with our labels — when it does, record the category rate and move on; it's observational signal, not a blocker).

### Phase 2 — Training-loop rewrites (#104, #105, #106)

**Duration:** 2–3 days.
**Parallel:** #104 blocks #105 and #106 (schema is the contract).

#### 3.3 prepare.py rewrite (#104)

This is the **frozen** file in autoresearch-rl — the LLM policy cannot modify it. It owns: data loading, prompt formatting (copy of `DEFAULT_SYSTEM_PROMPT` from the LLMTrace security crate), verdict parsing, and the evaluation protocol.

Key design decision: the evaluation protocol emits a single composite `eval_score` that autoresearch-rl optimises against, plus component metrics (`json_compliance`, `is_threat_acc`, `category_acc`, etc.) for debugging.

#### 3.4 train.py rewrite (#105)

Seven-component reward replacing the two-component one. The component weights are stored in `eval_protocol.json` (produced by prepare.py) so tweaking them doesn't require code changes during autoresearch-rl's hybrid loop.

| Component | Weight |
|---|---:|
| Valid JSON matching 6-field schema | 0.20 |
| `is_threat` correct | 0.25 |
| `category` correct | 0.20 |
| `recommended_action` correct | 0.10 |
| `security_score` within ±10 of target | 0.10 |
| `confidence` calibrated against correctness | 0.10 |
| `reasoning` length + signal word | 0.05 |

#### 3.5 program.md + config.yaml (#106)

`program.md` guides the LLM policy during autoresearch-rl's `llm_diff` mode — when param search stalls, the policy reads this doc plus the full experiment history and proposes code diffs to `train.py`. Updating it to reference the 7 reward components is what lets the LLM propose *useful* diffs instead of random ones.

Policy search grid tightens too: `lora_rank ∈ {8, 16, 32}` (was `{4, 8, 16}` — 6-field output has more tokens, so rank 4 likely underfits); `max_steps ∈ {50, 100, 150}`; `temperature ∈ {0.6, 0.8}` (lower default helps schema compliance).

### Phase 3 — Training execution (#107)

**Duration:** 2–7 days.
**Parallel:** none (one experiment at a time on one GPU).

autoresearch-rl's hybrid policy:

1. Iter 0–5: random param seeds.
2. Iter 5–20: LLM-guided param tuning.
3. Iter 20+: code diffs to train.py (reward tweaks, length penalties, format penalties).

Stop conditions:

- **Success**: every acceptance gate green on val (see §6).
- **Rescope**: three 12-hour runs without improvement, or $200 cost cap, or reward hacking detected.

Rescope options, each becoming a new sub-issue when taken:

- Scale base model to Qwen2.5-1.5B or 3B.
- Regenerate reasoning with a stronger teacher (Claude Haiku).
- Curriculum learning: train on `is_threat` only first, then add `category`, then full schema.

### Phase 4 — Independent evaluation (#108)

**Duration:** 1 day (parallelisable with late #107).

Run the best checkpoint through LLMTrace's own `judge_benchmark.rs` — same 27-corpus set we used for gpt-4o-mini. Head-to-head with:

- `openai/gpt-4o-mini` — baseline (already reported).
- `protectai/deberta-v3-base-prompt-injection-v2` — fast-judge.

Publish `docs/research/results/judge_evaluation_qwen-v1_<date>.md` with the same shape as the gpt-4o-mini report. Include a ship-or-no-ship recommendation with evidence.

This phase is non-negotiable. autoresearch-rl's internal val set may overfit to patterns in the training data; our 27-corpus set is broader and not seen during training.

### Phase 5 — Deployment (#109)

**Duration:** 0.5–1 day.

Merge the LoRA, push to private HF Hub repo `epappas/llmtrace-qwen-judge-v1`, stand up vLLM as a service. Roughly:

```bash
vllm serve ./llmtrace-qwen-judge-v1 \
  --host 0.0.0.0 \
  --port 8000 \
  --max-model-len 4096 \
  --dtype auto \
  --served-model-name llmtrace-qwen-judge-v1
```

Resource footprint: ~2 GiB VRAM at fp16. Runs on any small GPU (A10, T4, RTX 4090).

Helm/Compose artefact committed under `deployments/`.

### Phase 6 — LLMTrace integration (#110)

**Duration:** 7 days (shadow-mode calibration).

Single config flip:

```yaml
judge:
  backend: cascade
  cascade:
    fast_backend: deberta
    slow_backend: vllm             # was null
  vllm:
    base_url: "http://vllm-judge.internal:8000"
    model: "llmtrace-qwen-judge-v1"
  promotion:
    shadow: true                   # mandatory for rollout
```

Collect ≥ 1,000 verdicts under shadow. Fit reliability diagrams on the observed confidences. Calibrate `min_confidence` and the cascade's ambiguous band. Flip `shadow: false`.

Produce a production eval report and archive both the calibration data and the final config.

## 4. What LLMTrace does **not** need to change

This is worth emphasising because it's the architectural payoff of building the cascade and the 6-field schema first:

- **No parser changes.** The verdict JSON parser already accepts the 6-field format (`parse_verdict_json` in `crates/llmtrace-security/src/judge/parser.rs`).
- **No backend changes.** The existing `vllm` backend in `crates/llmtrace-security/src/judge/vllm.rs` serves any HF-format model behind a vLLM HTTP endpoint.
- **No config-schema changes.** `JudgeBackendKind::Cascade` and `JudgeCascadeConfig.slow_backend: Option<JudgeBackendKind>` already exist (issue #88).
- **No worker changes.** `JudgeWorker` holds an `Arc<dyn JudgeBackend>`; the cascade is just another backend.

Flipping to Qwen is one config push. Everything else is the fine-tuning work itself.

## 5. Budget

| Phase | Cost |
|---|---|
| Teacher distillation (#103) | ≤ $1.50 one-time |
| Training GPU (#107) | ≤ $200 one-time, cap hard at that |
| Ongoing vLLM serving | GPU-hours only (no per-call cost) |
| Total one-shot | **≤ $201.50** |

Compare to gpt-4o-mini at $0.00012/call × ~100k elevated calls/day ≈ $12/day = **$4,380/year**. Break-even in ~18 days on volume alone, independent of any latency/privacy argument.

## 6. Acceptance gates (global)

Ship the model when **all** of:

| Gate | Threshold | Source |
|---|---|---|
| `eval_score` | ≥ 0.80 on held-out val | #107 (autoresearch-rl internal) |
| `json_compliance` | ≥ 0.98 | #107 |
| `is_threat` accuracy | within 5 points of DeBERTa-protectai-v2 on identical held-out | #107 |
| Brier score | < 0.15 (calibrated confidence) | #107 |
| F1 on 27-corpus benchmark | ≥ 0.80 | #108 |
| FPR on XSTest+notinject+benign | ≤ 0.05 | #108 |
| ECE (Expected Calibration Error) | ≤ 0.10 | #108 |

**Ship-as-slow-tier-only fallback**: F1 ≥ 0.75 (cascade is more lenient; DeBERTa handles easy cases). Still requires the calibration gates.

**Don't ship**: anything below the fallback.

## 7. Risks and mitigations

| Risk | Probability | Mitigation |
|---|---|---|
| Qwen 0.5B is too small to reliably produce structured 6-field JSON | Medium | #107 rescope option A: escalate to 1.5B or 3B |
| Teacher-distilled reasoning biases the model toward gpt-4o-mini's failure modes | Medium | #108 failure-mode analysis explicitly looks for this; if confirmed, #107 rescope option B regenerates with Claude |
| Training cost blows past $200 before convergence | Low | Hard cap in #107; rescope to smaller grid |
| vLLM memory footprint exceeds budget on target cluster | Low | 0.5B at fp16 is tiny (~2 GiB); worst case quantise to int8 |
| Production traffic looks nothing like eval traffic | Medium | Shadow-mode phase 6 catches this; 7 days of real traffic before enforcement |
| LoRA merge degrades model quality | Low | #108 evaluates the **merged** model, not the adapter — any degradation caught before production |
| Teacher distillation cost runs higher than $1.50 | Low | Budget cap in #103 exits cleanly |

## 8. Timeline

Assuming no rescopes and a full-time data person + a full-time ML engineer:

| Week | Activity | Issues |
|---|---|---|
| 1 | Data prep + teacher distillation | #102, #103 |
| 2 | prepare.py + train.py + program.md; first smoke training runs | #104, #105, #106 |
| 3 | Full training campaign | #107 |
| 4 | Evaluation + LoRA merge + HF Hub + vLLM | #108, #109 |
| 5–6 | Shadow-mode calibration + rollout | #110 |

**End-to-end: 5–6 weeks**, rescope adds 1–2 weeks per occurrence.

## 9. Out of scope (deliberately)

- **Replacing gpt-4o-mini** as the slow tier in every deployment. Some operators will prefer it; the cascade already supports it. Qwen-v1 is *an option*, not a mandate.
- **Training a fast tier** (DeBERTa replacement). That's issue #89; separate track, different model family, different dataset split.
- **Multi-category classifier head for DeBERTa.** Would eliminate the synthesised `category` in the DeBERTa backend but needs its own labelled-dataset work; not on the critical path.
- **Continuous/online learning.** Everything here is offline one-shot training. Continual learning is a separate research track (see `docs/research/self-distillation-continual-learning.md`).

---
