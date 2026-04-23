# LLMTrace E2E Adversarial Test Framework

> **Status:** shipped. Loops L1–L10 of umbrella issue [#91](https://github.com/epappas/llmtrace/issues/91) are merged.

This directory holds the harness. The user-facing guide — quick-start, comparator reference, CI workflow contract, scenario authoring — lives at:

**[`docs/guides/e2e-testing.md`](../../docs/guides/e2e-testing.md)**

For the most recent committed corpus run see **[`docs/research/results/e2e_2026-04-23_baseline.md`](../../docs/research/results/e2e_2026-04-23_baseline.md)**.

---

## Quick start (TL;DR)

```bash
# Build the proxy
cargo build --release --manifest-path crates/llmtrace-proxy/Cargo.toml

# Install Python deps
python3 -m pip install -r requirements-e2e.txt

# Run the full 50-scenario suite
pytest tests/e2e/test_cascade.py -v

# Run only the 20 PR-gate scenarios
pytest tests/e2e/test_cascade.py -v --tag=pr-gate
```

`pytest.ini` sets `pythonpath = .`, so no `PYTHONPATH` export needed when running from the repo root.

---

## Layout

```
tests/e2e/
  conftest.py                 fixtures (proxy, mock upstream, scenarios) + L10 sidecar collector + cost cap
  test_cascade.py             main e2e test (parametrised over the 50-scenario corpus)
  observer.py                 /metrics snapshot + delta + judge-verdict polling
  expect.py                   expectation DSL — one comparator per `expected.*` key
  upstream_judge.py           L8 regex upstream judge (six rule classes)
  mock_upstream.py            FastAPI canned-response server (used when LLMTRACE_E2E_REAL_UPSTREAM_URL is unset)
  test_observer_unit.py       unit tests — observer
  test_expect_unit.py         unit tests — expectation DSL
  test_upstream_judge_unit.py unit tests — upstream judge
  test_nightly_report_unit.py unit tests — nightly report generator
  fixtures/
    config-e2e.yaml           base config, judge OFF
    config-e2e-judge.yaml     base config, cascade ON, slow tier null, debug endpoints ON
  README.md                   this file
  .logs/                      gitignored — per-session subprocess logs
```

The scenario corpus and JSON Schema live under `benchmarks/attacks/` (see [`benchmarks/attacks/SCHEMA.md`](../../benchmarks/attacks/SCHEMA.md)).
