# LLM-as-Judge Reliability Patterns

Date: 2026-04-19
Status: Knowledge reference
Scope: Applies to `crates/llmtrace-security/src/judge/` and the tracking issue #43

---

## Context

LLMTrace ships an LLM-as-a-Judge analysis tier as the third detector in its
security ensemble (issue #43, `docs/architecture/LLM_JUDGE.md`). The judge
is both a detector — emitting a `SecurityFinding` with `finding_type =
"llm_judge_verdict"` — and a router target dispatched via
`JudgeRouteAction`. Its verdicts influence enforcement decisions on the
inline path and become training labels for the Pipeline Learning service
(#44) on the async path.

Because the judge participates in enforcement and labels the downstream
training data, **its reliability is a correctness property of the whole
system**, not a separate concern. This document captures the reliability
patterns established in the broader LLM-evaluator literature and
industry practice, and how they apply to LLMTrace's security judge.

---

## 1. Binary outputs beat ordinal scales

LLM judges are materially more consistent when asked for a binary
classification (threat / not threat) than when asked for an ordinal
score (1–10 severity). The effect is repeatable across evaluator
literature: ordinal scales degrade self-consistency by 10–15 percentage
points on repeated runs of the same input, and inter-judge agreement
drops comparably.

### Why it matters for LLMTrace

Our `RawVerdict` schema (`crates/llmtrace-security/src/judge/parser.rs`)
currently asks the judge to emit **three overlapping signals** for every
classification:

| Field               | Type     | Consistency class             |
|---------------------|----------|-------------------------------|
| `is_threat`         | bool     | Binary — high consistency     |
| `security_score`    | 0–100 u8 | Ordinal — low consistency     |
| `confidence`        | 0.0–1.0  | Ordinal — low consistency     |

Asking for all three in one output forces the judge to produce correlated
but not identical signals — and the ordinal ones are the weakest link.
The downstream promotion path (`verdict_to_outcome` in
`crates/llmtrace-proxy/src/action_router.rs`) already drives the
inline enforcement decision from `is_threat` + `recommended_action`
rather than `security_score`, so the binary signal is effectively
authoritative for blocking. The numeric score is used only for severity
band mapping in `verdict_to_finding`.

**Implication**: we should treat `is_threat` as the primary, authoritative
output in the system prompt; describe `security_score` and `confidence`
as operator-facing hints the judge can produce with best-effort accuracy.
Reducing the cognitive load on the ordinal fields tends to improve
self-consistency on the binary field as well.

---

## 2. Cross-family judging reduces self-enhancement bias

A judge model evaluating outputs from its own model family exhibits
measurable bias: it systematically scores its own family's outputs higher
than other models'. This is reported consistently across published
LLM-judge evaluations and is severe enough that it can mask real
regressions — a Claude-judging-Claude pipeline keeps looking "healthy"
even while the application degrades.

### Why it matters for LLMTrace

The concern in LLMTrace's threat model is stricter than self-enhancement
bias: a judge sharing the upstream model's *context* can be compromised
by a prompt injection that the ensemble already flagged. Our
`docs/architecture/LLM_JUDGE.md` §4.8 already recommends a **dedicated
model distinct from the upstream model**. The cross-family literature
adds a second rationale for the same recommendation: even in the absence
of prompt injection, the judge's scores are less trustworthy when its
family matches the upstream.

Today the configuration fields exist (`config.judge.backend`,
`config.upstream_url`) but we do **not** cross-check at startup. An
operator can configure `backend = "openai"` with an OpenAI upstream and
get no warning.

**Implication**: emit a startup warning when the configured judge backend
family is the same as the detected upstream provider family. No
behaviour change — the operator may be intentionally running a
same-family judge — but the log surface makes the risk visible.

---

## 3. Calibration against a human-labelled golden set

A judge that is never measured against ground truth is a judge that
drifts. The standard calibration procedure for LLM-as-Judge systems is:

1. Curate 20–50 labelled examples covering the target behaviours.
2. Run the judge against the set.
3. Measure alignment (agreement rate, F1, confusion matrix).
4. Iterate on the system prompt based on systematic disagreements.
5. Re-run the set on every prompt change or model change.

Industry practice reports 10–15 percentage-point alignment improvements
from a single calibration pass, which is the difference between a judge
that is useful and one that is noise.

### Why it matters for LLMTrace

This is our largest current gap. The LLMTrace judge has:

- No golden evaluation set checked into the repo.
- No alignment metric captured at CI time.
- No drift regression test.

The `judge_verdict_agreement` metric in
`crates/llmtrace-proxy/src/action_router.rs` tracks judge-vs-ensemble
agreement on live traffic — which is useful for monitoring but is **not
a substitute for judge-vs-truth alignment**. The ensemble can be wrong;
"agrees with ensemble" does not mean "correct".

Pipeline Learning (#44) will consume judge verdicts as supervised
training labels for the DeBERTa classifier. If we feed uncalibrated
judge output into that loop, we amplify judge errors into the ML
classifier — a real risk that grows over time.

**Implication**: a curated golden set (covering prompt_injection,
jailbreak, data_exfiltration, benign, borderline categories) with
human labels, exercised in a CI benchmark, is a prerequisite before
the judge is trusted for enforcement promotion at high volume, and a
hard prerequisite before #44 consumes its output as training labels.

---

## 4. Drift tracking

Even a calibrated judge drifts. Published studies of judge-alignment
over multiple model revisions show 3–8 point alignment decay per quarter
when no recalibration is performed. Drift sources include:

- Upstream model updates (silent API-side version changes).
- System prompt edits that appear semantically equivalent but change
  distribution.
- Data distribution shift in live traffic (new attack patterns).

### Why it matters for LLMTrace

We have no drift detection today. The first time a judge starts
confusing jailbreaks for benign prompts, we learn about it from an
incident, not a dashboard.

A nightly (or hourly) replay of the golden set against the live backend,
with the alignment score published as a Prometheus gauge and wired into
an alert rule, catches this the first day drift starts.

**Implication**: the golden-set check is run at two cadences:

- **CI**: hard-fail the build when alignment falls below a threshold.
  This catches prompt regressions before merge.
- **Runtime**: a scheduled job (cron or similar) that re-runs the set
  against the configured backend and exports an alignment gauge. This
  catches model drift and upstream API changes.

---

## 5. The correction-log feedback loop

When operators override a judge verdict (promoting a missed threat or
demoting a false positive), that override is signal. Feeding a running
log of these corrections back into the system prompt as few-shot
examples is a well-established pattern that compounds over time: the
judge's worst disagreements become the examples that prevent the same
disagreement next time.

### Why it matters for LLMTrace

We have no review UI and no correction workflow. The dashboard
(`dashboard/`) surfaces traces and findings but does not let operators
emit verdict overrides.

This pattern requires operator tooling we don't have, so it's
**deferred** — captured here so we don't forget it, not on the
immediate roadmap.

---

## Summary table: current state vs patterns

| Pattern                              | LLMTrace state                 | Gap                              |
|--------------------------------------|--------------------------------|----------------------------------|
| Binary > ordinal                     | Three signals emitted          | Lean prompt toward `is_threat`   |
| Cross-family judging                 | Configurable, not enforced     | Add startup family-match warning |
| Human-labelled golden set            | None                           | Curate + CI benchmark            |
| Drift tracking                       | None                           | Scheduled golden-set replay      |
| Correction log → few-shot            | None (no review UI)            | Deferred; requires ops tooling   |

Gaps 1–4 are tracked in a single follow-up issue with a concrete
implementation plan. Gap 5 is documented above and parked.

---

## References

### LLMTrace

- `docs/architecture/LLM_JUDGE.md` — judge architecture spec (issue #43)
- `crates/llmtrace-security/src/judge/` — backend trait and impls
- `crates/llmtrace-proxy/src/action_router.rs` — `verdict_to_outcome`
  and `agreement_label`
- `crates/llmtrace-proxy/src/judge.rs` — worker loop, config-gated
- PR #65 — full pipeline implementation

### External

- Binary-vs-ordinal consistency findings appear in multiple LLM-judge
  evaluations; a pragmatic industry write-up is Simon Budziak,
  "LLM-as-Judge in LangSmith: Automated Evaluation that Actually Scales"
  (2025), which reports 77% vs 65% self-consistency and ~85% alignment
  with human judgment across 250,000+ annotated cases.
- Self-enhancement bias is a repeatable finding across G-Eval,
  HELM-Evaluator, and multiple LLM-as-judge papers.
- Calibration uplift (10–15 pp) from a first-pass golden set is
  reported by the same LangSmith writeup and is consistent with
  published human-alignment evaluations.
