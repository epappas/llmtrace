# Judge Cascade — Architecture Decision Record

**Status:** Accepted. Fast-judge + cascade primitive ship on the branch that
introduces this document; the slow-tier LLM-specific model (fine-tuned Qwen)
ships in a follow-up (issue #90).

**Tracking:** [#86][86] (umbrella) · [#87][87] (fast-judge) · [#88][88]
(cascade) · [#89][89] (DeBERTa retrain) · [#90][90] (Qwen retrain).

**Companion docs:** [`LLM_JUDGE.md`](LLM_JUDGE.md) (judge design, unchanged) ·
[`../guides/llm-judge.md`](../guides/llm-judge.md) (operator setup) ·
[`../research/results/judge_evaluation_gpt4o_mini_2026-04-20.md`](../research/results/judge_evaluation_gpt4o_mini_2026-04-20.md)
(baseline numbers this ADR is reacting to).

[86]: https://github.com/epappas/llmtrace/issues/86
[87]: https://github.com/epappas/llmtrace/issues/87
[88]: https://github.com/epappas/llmtrace/issues/88
[89]: https://github.com/epappas/llmtrace/issues/89
[90]: https://github.com/epappas/llmtrace/issues/90


## Problem

The `gpt-4o-mini` evaluation published on 2026-04-20 gave us honest numbers
for the single-tier LLM judge: overall F1 = 0.856, p95 latency = 2.6 s, cost
≈ $0.00012/call. Two of those numbers are operational blockers for inline
enforcement:

**Latency.**: A p95 of 2.6 s overshoots the default `inline_timeout_ms` of

  2 s. At that latency budget, ~35–40 % of inline calls drop the verdict and
  fall through — the judge becomes effectively async-only.

**Cost at scale.**: $0.00012/call is cheap per request, but at 100 k

  elevated requests per day that's $12/day per tenant. Acceptable on one
  tenant; uncomfortable on dozens.

Meanwhile, our existing DeBERTa ML tier runs locally in ~50 ms on a
modern GPU (or ~2–3 s on CPU, measured warm) with F1 in the 0.95–0.98
range on matched distributions. It's fast and accurate but
votes only once in the ensemble — it does not carry its own promotion gate,
shadow mode, verdict persistence, or drift-tracking metrics, because those
live on the `JudgeBackend` side of the pipeline.

Two observations, one conclusion:

- Most elevated candidates are unambiguous. A classifier gives a strongly
   tilted probability (e.g. 0.02 or 0.97) and is right far more often than it
   is wrong.
- A small slice of elevated candidates *are* ambiguous (probability ≈ 0.5),
   and that's exactly where an expensive, reasoned, text-generative verdict
   pays for itself.

That shape — cheap-confident handled locally, expensive-uncertain escalated —
is a cascade.

## Decision

Ship a three-tier judge cascade:

```
┌──────────────────────────────────────────────────────────────────────┐
│ Tier 0 — Regex (microseconds, existing)                              │
│   clean? → pass early                                                │
│   elevated score ≥ min_score_threshold? → continue                   │
├──────────────────────────────────────────────────────────────────────┤
│ Tier 1 — Ensemble vote (existing, unchanged)                         │
│   regex + DeBERTa (general-purpose, protectai/deberta-v3-…)          │
│   produces an aggregated security_score                              │
├──────────────────────────────────────────────────────────────────────┤
│ Tier 2 — FAST-JUDGE (new: DebertaJudgeBackend)                       │
│   runs the ML analyser as a JudgeBackend                             │
│   ~50 ms on GPU / ~2–3 s on CPU, emitted synchronously from         │
│   spawn_blocking; build with `--features cuda` or `metal` on GPU     │
│   emits a 6-field JudgeVerdict (synthesised where DeBERTa cannot)    │
│                                                                      │
│   confidence ∉ [ambiguous_low, ambiguous_high] → final verdict       │
│   confidence ∈ [ambiguous_low, ambiguous_high] AND slow configured   │
│       → escalate to Tier 3                                           │
├──────────────────────────────────────────────────────────────────────┤
│ Tier 3 — SLOW-JUDGE (new composition of existing LLM backends)       │
│   any of vllm / openai / anthropic                                   │
│   emits a 6-field JudgeVerdict natively (no synthesis)               │
│   subject to the existing promotion gate (#70, #84 shadow, #83 model │
│   label)                                                             │
├──────────────────────────────────────────────────────────────────────┤
│ Tier 4 — (operator-opt-in remote LLM, out of scope for this ADR)     │
└──────────────────────────────────────────────────────────────────────┘
```

The new code is two `JudgeBackend` implementations and a config type — no
changes to the worker, the action router's cascade call site, the storage
schema, or the metrics.

## Why this shape

### 1 Why a cascade instead of two independent judges

Running both tiers on every elevated candidate is wasteful: the fast tier is
already high-precision, so escalating blindly doubles the slow-tier cost and
gives one new verdict per two calls' worth of work. Escalating on an
ambiguous band keeps the slow tier firing only where it adds signal.

### 2 Why `CascadeJudgeBackend` implements `JudgeBackend`

Because every existing judge capability — worker dispatch, shadow mode,
promotion gate, metrics, verdict persistence — is keyed on the
`JudgeBackend` trait. If the cascade is itself a `JudgeBackend`, all of that
composes for free. We add one new backend kind; nothing downstream knows.

### 3 Why `slow` is `Option`

Today we can ship tiers 0–2 without a local fine-tuned slow-judge. Setting
`slow_backend: null` (or omitting the field) makes the cascade degrade
cleanly to "fast-judge alone". When the Qwen retrain (issue #90) lands,
operators flip one config field and gain the slow tier. No code change on
the LLMTrace side is required for that switch.

### 4 Why the default ambiguous band is `[0.3, 0.7]`

Rough calibration from prior literature and from the DeBERTa reliability
curve we've seen in `deberta-prompt-injection` training runs:

- Below 0.3: observed precision of the "benign" prediction is high enough
  that escalation produces very few flips.
- Above 0.7: observed precision of the "injection" prediction is similarly
  high.
- Between: real ambiguity — phrasing that could go either way, content that
  mentions adversarial topics without executing them (XSTest-style), hybrid
  payloads.

These are initial defaults. The benchmark harness (extended under #86 /
#88) produces the reliability curve we'll use to tune them per-model.

### 5 Why DeBERTa synthesises `category` / `reasoning`

Classifiers produce `P(class)`; they do not produce taxonomy or natural
language. Two options:

**Fabricate invisibly**: — forbidden by our "never lie" rule.


**Document a deterministic mapping**: — audit logs, 403 bodies, and stored

  verdicts make it obvious the reasoning came from a template, not an LLM
  explanation. That's the path we take.

The reasoning string is literally:

```
DeBERTa classifier p=0.923 (model=protectai/deberta-v3-base-prompt-injection-v2)
```

Category is fixed at `prompt_injection` until/unless a multi-class head
lands. Issue #89 covers the retraining track where a multi-class DeBERTa
could replace this fixed mapping.

## Telemetry

No new metrics are introduced by the cascade itself. Both inner backends
already emit:

- `llmtrace_judge_requests_total{backend,model,mode,status}`
- `llmtrace_judge_latency_seconds{backend,model,mode}`
- `llmtrace_judge_verdicts_total{category,recommended_action,is_threat,model}`
- `llmtrace_judge_tokens_total{direction,backend,model}`

Dashboards filter by `model` to attribute a decision to its tier:

```
# verdicts from the fast tier
sum(rate(llmtrace_judge_verdicts_total{model=~"deberta.*"}[5m]))

# verdicts from the slow tier
sum(rate(llmtrace_judge_verdicts_total{model=~"qwen.*|gpt-.*|claude-.*"}[5m]))

# escalation rate (slow / fast) ≈ fraction of elevated candidates in the ambiguous band
(slow_rate) / (fast_rate)
```

A purpose-built escalation counter is tracked as a follow-up in #88 for
operators who want the rate as a first-class metric instead of a ratio query.

## Configuration shape

```yaml
judge:
  enabled: true
  backend: cascade                 # new JudgeBackendKind variant

  cascade:
    fast_backend: deberta
    slow_backend: vllm             # or openai / anthropic / null (fast-only)
    ambiguous_low: 0.3
    ambiguous_high: 0.7

  deberta:
    model_id: "protectai/deberta-v3-base-prompt-injection-v2"
    threshold: 0.5                 # used only for is_threat boundary
    cache_dir: "~/.cache/llmtrace/models"

  vllm:
    base_url: "http://vllm.internal:8000"
    model: "llmtrace-qwen-judge-v1"   # once #90 lands

  # promotion, worker, retry, system_prompt, min_score_threshold, persist_verdicts
  # — all unchanged, apply to whatever the cascade ultimately returns.
  promotion:
    shadow: true                   # shadow-first, always
```

Today's rollout (the commit shipping alongside this ADR) supports
`slow_backend: null`, which runs fast-judge only. When Qwen lands, this
becomes `slow_backend: vllm`.

## Verdict persistence

Only the final stage's verdict is written to `judge_verdicts`. Two reasons:

- The promotion gate and the enforcement path already consume a single
   `JudgeVerdict`. Keeping the cascade signature `fn judge(...) ->
   JudgeVerdict` avoids a ripple through the worker and the action router.
- Dual-stage persistence is only valuable for Pipeline Learning (#44), and
   that work hasn't landed. Adding a `stage` column now would be speculative
   schema churn.

When #44 surfaces the need, a follow-up issue adds a nullable `parent_verdict_id`
and `stage: fast|slow|single` to `judge_verdicts`, and the cascade writes
both. Today this is out of scope.

## Failure semantics

Fail-open is preserved end-to-end:

| Failure mode | Cascade behaviour |
|---|---|
| Fast tier errors | Treat as if confidence were in the ambiguous band — escalate if slow is configured, else fail open (the overall judge error surfaces). |
| Fast tier timeout | Same as fast error. Doesn't happen in practice — the DeBERTa backend doesn't do network I/O. |
| Slow tier errors (when escalated) | Fall back to the fast tier's verdict. Operators see both a slow-tier `status!=success` metric AND a final verdict from the fast tier. |
| Both tiers error | Judge returns `Err(_)`, enforcement decision is unchanged (the no-judge baseline). |
| Slow tier not configured and fast is ambiguous | Fast-tier verdict is returned as-is. No escalation attempted. Not a failure. |

## Rollout sequence

**Ship fast-judge + cascade primitive with `slow_backend: null`.**: Fast

   tier is DeBERTa-protectai (the same model we already trust in the
   ensemble). Cascade escalation path is a no-op today. Verdicts persist;
   metrics emit with the `deberta` model label; shadow mode works. This is
   the commit that accompanies this ADR.

**Re-fine-tune Qwen on the 6-field schema**: (issue #90, in the

   `autoresearch-rl` repo). Publish to HF Hub. Stand up vLLM locally.

**Flip `slow_backend: vllm`**: in production config with `promotion.shadow:

   true`. Watch `judge_shadow_would_block_total` and the ambiguous-band
   escalation rate for ~1 000 verdicts.

**Calibrate**: `ambiguous_low`, `ambiguous_high`, and (per #66)

   `min_confidence` against the observed reliability curves.

**Flip shadow off.**: Both tiers now enforce. The fast tier handles the

   bulk; the slow tier handles the interesting cases.

**Separately, retrain the user's DeBERTa**: (issue #89). If it wins

   head-to-head against protectai on our 27-corpus eval at equal or lower
   FPR, swap the default `deberta.model_id`. No other code changes.

Each step is individually shippable. Nothing else is waiting on step 5 to
begin.

## What this ADR does not decide

**Per-tenant cascade.**: Today the cascade is a single global config.

  Per-tenant cascade (different tiers for free vs paid) is a follow-up once
  tenant-scoped judge config lands.

**Dynamic band tuning.**: Bands are static config. Auto-tuning them from

  the observed reliability curve is tempting but premature without a golden
  set (#66).

**Dual persistence.**: See §6. Until Pipeline Learning (#44) needs it, we

  keep the storage contract simple.

**Replacing the ensemble DeBERTa.**: The ensemble's DeBERTa (general

  purpose, protectai) and the fast-judge DeBERTa (cascade gate, whatever
  operators point it at) remain two logical slots. The duplicated inference
  cost is a real inefficiency but not a correctness problem; forwarding the
  ensemble's score into the judge's `prior_findings` is tracked as a
  follow-up under #86.

