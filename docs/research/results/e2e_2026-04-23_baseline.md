# E2E adversarial test framework — baseline run (2026-04-23)

This document is the **proof of execution** for the adversarial e2e test framework (umbrella issue [#91][91]) at the conclusion of Loop E2E-L10.

It accompanies — but is distinct from — the auto-generated nightly report (`e2e_2026-04-23.md`). The auto-generated report is byte-deterministic and intended for diff-vs-previous comparisons; this document is a one-time human-authored attestation describing the run methodology, the artifacts attached, and the triage of the single non-passing scenario.

[91]: https://github.com/epappas/llmtrace/issues/91


## Headline

| Metric | Value |
|---|---|
| Corpus | 50 scenarios across 8 attack families |
| Outcome | **49 passed, 1 flaky failure (passes in isolation)** |
| Wall clock (full run) | 18 min 42 s |
| Wall clock (single-scenario re-run) | 1 min 11 s |
| Upstream-fell-for-it rate | 0/49 (proxy + mock upstream — no real LLM was invoked) |
| Tooling commit | `dd059ee feat(e2e): nightly full-corpus + auto-PR report (#100)` |
| Loops L7–L10 PRs | [#122][pr122] (L7), [#124][pr124] (L8), [#125][pr125] (L9), [#126][pr126] (L10) |

[pr122]: https://github.com/epappas/llmtrace/pull/122
[pr124]: https://github.com/epappas/llmtrace/pull/124
[pr125]: https://github.com/epappas/llmtrace/pull/125
[pr126]: https://github.com/epappas/llmtrace/pull/126


## Methodology

The run was executed locally on the L10 branch (`feat/issue-100-e2e-nightly-report`) using the production code paths the nightly workflow will exercise:

```
mkdir -p out
pytest tests/e2e/test_cascade.py -v \
  --scenario-results-json=out/scenario-results.json \
  --junit-xml=out/junit-nightly.xml
python3 scripts/e2e/generate_nightly_report.py \
  --results-json out/scenario-results.json \
  --report-dir docs/research/results/ \
  --date 2026-04-23
```

Same Python harness, same Rust release binary, same scenario corpus, same report generator that the nightly workflow (`.github/workflows/e2e-nightly.yml`) will use under cron. The only difference vs the nightly is the upstream: the local run used the in-process FastAPI mock (`tests/e2e/mock_upstream.py`); a nightly run would point at OpenRouter when `LLMTRACE_E2E_REAL_UPSTREAM_URL` is wired up as a repo secret.

Every scenario went through the **full L1–L10 pipeline**:

**L1**: scenario YAML loaded from `benchmarks/attacks/`


**L2**: scenario validated against `benchmarks/attacks/schema.json` (Draft 2020-12)


**L3**: real `llmtrace-proxy` release binary spawned per session, real `/health` poll until ready


**L4**: per-scenario `/metrics` snapshot taken before + polled after, with delta analysis


**L5**: judge verdict polled from `/debug/judge/verdicts?trace_id=…` for scenarios that assert on the judge tier


**L6**: expectation DSL evaluated each declared comparator (`proxy_outcome.at_least`, `findings_include`, `findings_min_severity`, `judge_verdict.*`)


**L7**: 50-scenario corpus exercised end-to-end (8 families, 50 prompts; 20 tagged `pr-gate`)


**L8**: regex upstream judge ran on every scenario, classifying upstream output against six rule classes


**L9**: (CI workflow): tested by virtue of the L9 PR's own `E2E PR Gate` job passing on PR #125


**L10**: per-scenario JSON sidecar collected via the conftest hook; report generated; cost-cap fixture armed (no-op without `--cost-cap-usd`)



## Attached proofs

Four files in this directory document the run:

| File | Description |
|---|---|
| `e2e_2026-04-23.md` | Auto-generated, deterministic markdown report (per-family roll-ups, upstream-fell-for-it rates, diff vs previous run — empty since this is the baseline). |
| `e2e_2026-04-23.json` | Per-scenario JSON sidecar — one row per scenario with id, family, tags, outcome, duration, upstream judgement. The diff in tomorrow's report compares against this file. |
| `e2e_2026-04-23_junit.xml` | Pytest JUnit XML output. The Actions UI renders these natively when uploaded as a workflow artifact; here it serves as a vendor-neutral test-result archive. |
| `e2e_2026-04-23_pytest_output.txt` | Raw pytest stdout for the run (tee'd from the live session). Includes per-scenario PASSED/FAILED lines and the full traceback for the flaky failure. |


## Triage: the single non-passing scenario

`tensortrust-hijack-tensor-trust-00005-002` failed in the full-corpus run with:

```
requests.exceptions.ConnectionError:
  HTTPConnectionPool(host='127.0.0.1', port=50057): Read timed out.
```

This is a **client-side read timeout from the harness to the proxy**, not a proxy-side fault and not an assertion failure. Re-running the scenario in isolation immediately afterward against the same proxy binary with no other changes:

```
$ pytest tests/e2e/test_cascade.py -k "tensortrust-hijack-tensor-trust-00005" -v
...
tests/e2e/test_cascade.py::test_scenario[tensortrust-hijack-tensor-trust-00005-002] PASSED
1 passed, 49 deselected in 71.35s
```

The same flake was observed in the L7 verification run; in both cases it has been load contention from running 50 scenarios sequentially, with no real failure mode underneath. The auto-generated report still flags it as `failed` (it doesn't get to know about the re-run), and that is the correct behaviour: lying about the outcome would defeat the diff-vs-previous machinery.

**Treatment**: documented as a known-flaky test condition; the appropriate fix lives in a follow-up that either raises the harness HTTP read timeout (currently 30 s in `ProxyHandle.post_chat`) or adds a per-scenario retry budget in the harness. Neither change is in scope for L10.


## What this run validates

Every scenario reaching `passed` (or `failed` with the trace flushed to junit) is direct evidence that:

- The **scenario YAML** was schema-valid.
- The **proxy binary** booted, became healthy, served `/v1/chat/completions`, served `/metrics`, served `/debug/judge/verdicts`.
- The **expectation DSL** evaluated every declared comparator without crashing.
- The **upstream judge** returned a structured `UpstreamJudgement` for every scenario.
- The **L10 sidecar collector** captured outcome + duration + upstream judgement for every scenario.
- The **report generator** produced a syntactically valid markdown report and a byte-stable JSON sidecar.

The 0/49 upstream-fell-for-it rate reflects the mock upstream's behaviour (it returns deterministic refusals to every prompt) and is the correct baseline for a mock-only run. When the nightly workflow runs against a real upstream, this number is the metric to watch — non-zero means the upstream complied with at least one attack and the corresponding LLMTrace decision is the second column of the comparison.


## Reproducing this run

```
# From repo root, after cargo build --release for the proxy.
mkdir -p out
pytest tests/e2e/test_cascade.py -v \
  --scenario-results-json=out/scenario-results.json \
  --junit-xml=out/junit.xml
python3 scripts/e2e/generate_nightly_report.py \
  --results-json out/scenario-results.json \
  --report-dir docs/research/results/ \
  --date $(date -u +%F)
```

The report is byte-deterministic for the same input, so running this twice on the same sidecar produces an identical Markdown file. That property is what makes the "no diff vs yesterday" case a no-op auto-PR (per L10 acceptance).
