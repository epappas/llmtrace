# E2E Adversarial Testing Guide

> **Status:** in development. Tracks umbrella issue [#91](https://github.com/epappas/llmtrace/issues/91). This guide covers Loops E2E-L1–L5 (proxy lifecycle + scenario schema + metrics + judge verdicts). The expectation DSL (L6), CI integration (L9/L10), and broader corpus (L7) follow.

The e2e adversarial test framework exercises a **real LLMTrace proxy** against a YAML corpus of attack scenarios and asserts what the proxy decided about each one. It boots the proxy as a subprocess, fires every scenario at it, and reads back the full observability surface — HTTP status, response headers, `/metrics` deltas, and persisted judge verdicts — then evaluates each scenario's `expected:` block against what was observed.

---

## Quick start

```bash
# Build the proxy binary (release recommended; debug works too)
cargo build --release -p llmtrace

# Install the e2e Python deps into a venv
python3 -m venv .venv-e2e
.venv-e2e/bin/pip install -r requirements-e2e.txt

# Run the suite
.venv-e2e/bin/pytest tests/e2e/ -v

# Run the PR-gate subset (faster; same scenarios as #99 will use)
.venv-e2e/bin/pytest tests/e2e/ -v --tag=pr-gate

# Run scenarios in one family
.venv-e2e/bin/pytest tests/e2e/ -v --family=prompt_injection
```

The harness picks up `target/release/llmtrace-proxy` when present, then `target/debug/llmtrace-proxy`. Override with `LLMTRACE_PROXY_BIN=<path>`. The harness logs the proxy and mock-upstream stdout to `tests/e2e/.logs/` (gitignored).

---

## Architecture (today)

```
pytest
  conftest.py
    mock_upstream     ── canned FastAPI /v1/chat/completions (PR-gate only)
    proxy             ── llmtrace-proxy subprocess, /health-gated boot
    scenarios         ── parametrises tests against benchmarks/attacks/**/*.yaml

  test_cascade.py::test_scenario(proxy, scenario)
      ├── MetricsSnapshot.fetch(/metrics)         (before)
      ├── proxy.post_chat(prompt, trace_id=…)     (X-LLMTrace-Trace-Id set)
      ├── fetch_after_until_settled(…)            (poll until background task lands)
      ├── classify_proxy_outcome(response)        (allow / warn / block)
      ├── poll_judge_verdict(/debug/…)            (when judge_verdict expected)
      └── assertions:
            proxy_outcome.at_{least,most}
            findings_include
            judge_verdict.{is_threat, category, recommended_action.at_*}
```

Subsequent loops slot in:

- **L6** — formalises the assertion logic above into an expectation DSL with per-comparator unit tests.
- **L7** — converts ~50 labeled samples from `benchmarks/datasets/` into the corpus.
- **L8** — adds the upstream-fell-for-it detector for live-LLM nightly runs.
- **L9 / L10** — CI workflows (PR-gate fast subset + nightly full corpus + committed report).

---

## Scenario format

See [`benchmarks/attacks/SCHEMA.md`](../../benchmarks/attacks/SCHEMA.md) for the field reference. The validator (`scripts/e2e/validate_scenarios.py`) runs in CI as the `e2e-validate-scenarios` job; it gates schema drift independently of the harness boot.

---

## Trace-id correlation

Every harness request carries `X-LLMTrace-Trace-Id: <uuid>`. The proxy honours the header (PR #114, Loop E2E-L1a) and uses it as the request's `trace_id` end-to-end:

- Logged with every `tracing` event for that request.
- Propagated to security findings, persisted traces, and the persisted `JudgeVerdict.trace_id`.
- Echoed back as the `X-LLMTrace-Trace-Id` response header on success and error paths.

Because `JudgeVerdictQuery.trace_id` is already part of the verdict store trait, the harness can poll the dev-only `GET /debug/judge/verdicts?trace_id=<uuid>` endpoint to fetch a verdict back by the same id it supplied on the inbound request.

If you supply no header, the proxy generates a fresh `Uuid::new_v4()` as before. The harness always supplies one.

---

## Debug endpoint contract

> **Production-safety call-out.** The `/debug/*` route family is gated by `server.debug_endpoints: bool` (default `false`). When the flag is `false`, the route is **not registered** and returns 404 from axum's not-found handler. **Production proxies must never enable this flag** — verdicts are returned un-auth-gated by trace_id; anything that knows a trace_id can read the verdict.

### `GET /debug/judge/verdicts?trace_id=<uuid>`

| Status | Body | Meaning |
|---|---|---|
| `200` | `JudgeVerdict` JSON (matches the persisted `judge_verdicts` row schema) | Verdict found for the supplied `trace_id` |
| `404` | `{"error": {"message": "no verdict for trace_id", "type": "debug_error"}}` | Either no verdict has landed yet (judge worker is async) or the flag is off |
| `400` | `{"error": {"message": "trace_id must be a UUID", ...}}` | The query param is not a valid RFC 4122 UUID |

Implementation: thin wrapper over `state.storage.judge_verdicts.query_verdicts(JudgeVerdictQuery { trace_id: Some(uuid), limit: Some(1), .. })`. No new trait surface; works against `InMemoryJudgeVerdictStore`, `ClickHouseJudgeVerdictStore`, and `PostgresJudgeVerdictStore`.

---

## Judge verdict collector lifecycle

```
harness POST /v1/chat/completions   (X-LLMTrace-Trace-Id: <uuid>)
       │
       │ proxy enforcement → action_router → judge_route → judge worker queue
       │
       │ HTTP response returns to harness
       │
       │ judge worker dequeues, runs DeBERTa fast tier (cascade), writes verdict
       │ to JudgeVerdictStore (async)
       │
       └─► harness: poll_judge_verdict(base_url, trace_id, timeout=10s)
             ├─ GET /debug/judge/verdicts?trace_id=…  (250 ms polling)
             │     200 → return verdict dict
             │     404 → keep polling
             │     other → raise HTTPError
             └─ timeout → return None (caller decides soft-skip vs hard-fail)
```

The verdict typically lands in 200–800 ms after the synchronous response. The poller waits up to 10 s by default.

For the e2e harness to receive any verdict at all, the proxy config needs:

- `judge.enabled: true`
- `judge.backend: cascade` (or whatever backend produces verdicts)
- `judge.persist_verdicts: true` (default)
- `action_router.enabled: true` *and* `judge_route` in `action_router.default_actions` — without this the JudgeWorker spawns but never receives requests
- `server.debug_endpoints: true` — without this `/debug/judge/verdicts` is not mounted

The shipped `tests/e2e/fixtures/config-e2e-judge.yaml` sets all of the above and is the default the harness loads.

---

## Degraded-mode handling

Provider/upstream flakes must not turn e2e red. The harness watches `llmtrace_judge_requests_total{status="backend_error"}` deltas and softens verdict assertions when it sees an increment:

```python
if judge_expectations is not None:
    verdict = poll_judge_verdict(proxy.base_url, trace_id)
    if verdict is None:
        if judge_backend_errored(delta):
            pytest.skip("judge tier reported backend_error; assertions softened.")
        pytest.fail("verdict expected but never recorded.")
```

The proxy outcome and findings_include assertions stay strict — only the judge_verdict block is softened — because we want to catch LLMTrace regressions, not provider outages.

---

## Shadow-mode signal

`shadow_would_block_count(delta, category=…, recommended_action=…)` reads the per-scenario delta of `llmtrace_judge_shadow_would_block_total`. Useful for scenarios that run with `judge.promotion.shadow: true` and want to assert "the judge *would have* blocked this" without actually changing enforcement.

---

## Expectation DSL — comparator reference

Every key under a scenario's `expected:` block maps to one comparator function in `tests/e2e/expect.py`. The orchestrator `assert_scenario(scenario, response, delta, verdict, judge_degraded)` returns one [`AssertionResult`](../../tests/e2e/expect.py) per comparator (no I/O — the test wrapper handles HTTP, metrics, and verdict polling, then hands the observed values in).

| Key | Type | Semantics |
|---|---|---|
| `proxy_outcome.at_least` | enum (`allow`<`warn`<`block`) | Observed outcome must be **>=** the floor. |
| `proxy_outcome.at_most` | enum (`allow`<`warn`<`block`) | Observed outcome must be **<=** the ceiling. |
| `findings_include` | list of finding-type strings | Every listed `finding_type` must appear at least once in the per-scenario `llmtrace_security_findings_total` delta. |
| `findings_min_severity` | enum (`Info`<`Low`<`Medium`<`High`<`Critical`) | Peak severity across observed findings must be **>=** the floor; "no findings observed" fails with an explicit message rather than a confusing `None < High`. |
| `judge_verdict.is_threat` | bool | Exact match against polled `JudgeVerdict.is_threat`. |
| `judge_verdict.category` | string | Exact match against polled `JudgeVerdict.category`. |
| `judge_verdict.recommended_action.at_least` | enum (`allow`<`flag`<`block`) | Polled `recommended_action` must be **>=** the floor. |
| `judge_verdict.recommended_action.at_most` | enum (`allow`<`flag`<`block`) | Polled `recommended_action` must be **<=** the ceiling. |

### Pass / soft / fail

Each `AssertionResult` carries a `passed: bool` and a `soft: bool` flag. Soft failures fire only on the `judge_verdict.*` block when the verdict is missing **and** the harness saw `llmtrace_judge_requests_total{status="backend_error"}` increment in the same window. The test wrapper aggregates as:

- Any **hard** failure → `pytest.fail` with the full assertion summary attached (per-row markers `[ok]` / `[soft]` / `[FAIL]`, plus the metrics-delta context).
- Only soft failures and zero passes (e.g. judge-only scenario whose tier flaked) → `pytest.skip`.
- Any pass alongside soft failures → still passes (provider/upstream flake should not turn a real-LLMTrace observation red).

### Adding a comparator

1. Add a helper `_compare_<name>` in `tests/e2e/expect.py` returning an `AssertionResult`.
2. Wire it into `_TOP_LEVEL_COMPARATORS` (top-level keys) or `_compare_judge_verdict` (judge-block keys).
3. Add at least one passing + one failing unit test in `tests/e2e/test_expect_unit.py` (the synthetic-input pattern means no proxy boot required).
4. Document the new key in this table.

The orchestrator also surfaces an explicit failure when an unknown `expected.*` key (top-level or under `judge_verdict`) appears, so typos in scenario YAML cannot silently skip an assertion.

---

## Failure-message anatomy

Every assertion failure includes:

- The scenario id (`[dan-classic-001]`).
- The expected vs observed values (with the `at_least`/`at_most` semantics named explicitly).
- The HTTP `status`, `x-llmtrace-flagged` value, and the request `trace_id`.
- A pretty-printed dump of the **non-zero metrics delta** for the security/judge/action families, sorted deterministically:

```
non-zero metrics delta:
  llmtrace_action_executions_total{action_type='judge_route',mode='inline',status='success'} 1
  llmtrace_judge_verdicts_total{category='prompt_injection',is_threat='true',recommended_action='block',model='…'} 1
  llmtrace_security_findings_total{finding_type='jailbreak',severity='Critical'} 2
```

The trace_id is recoverable from the failure message and can be replayed against the proxy log under `tests/e2e/.logs/proxy.log` for deeper investigation.

---

## Serial-execution constraint

The harness diffs *global* Prometheus counters per scenario. That requires serial execution. `pytest-xdist` (`-n auto`) is **rejected at collection time**:

```
UsageError: tests/e2e must run serially: counter-diff observability is global.
```

Per-tenant metric scoping that would make parallel runs safe is an explicit follow-up after L9.

---

## Adding a scenario

1. Pick a `family` from the [SCHEMA enum](../../benchmarks/attacks/SCHEMA.md#family).
2. Create `benchmarks/attacks/<family>/<id>.yaml` matching the schema.
3. Tag `pr-gate` if it should run on every PR (the pr-gate subset must stay fast and representative — a regression-catching scenario beats a redundant one).
4. Run `python3 scripts/e2e/validate_scenarios.py --verbose` to check the schema.
5. Run `pytest tests/e2e/ -v -k <id>` against a real proxy to confirm the assertions are calibrated.
6. Open a PR. CI will run the `e2e-validate-scenarios` job + (once L9 lands) the PR-gate subset.

---

## Where things live

| Concern | Path |
|---|---|
| Scenario YAMLs | `benchmarks/attacks/<family>/<id>.yaml` |
| Scenario JSON Schema | `benchmarks/attacks/schema.json` |
| Schema reference | `benchmarks/attacks/SCHEMA.md` |
| Validator script | `scripts/e2e/validate_scenarios.py` |
| Pytest harness | `tests/e2e/conftest.py` |
| Mock upstream | `tests/e2e/mock_upstream.py` |
| First-cut test | `tests/e2e/test_cascade.py` |
| Metrics observer | `tests/e2e/observer.py` |
| Observer unit tests | `tests/e2e/test_observer_unit.py` |
| Expectation DSL | `tests/e2e/expect.py` |
| Expectation DSL unit tests | `tests/e2e/test_expect_unit.py` |
| Proxy config (judge ON) | `tests/e2e/fixtures/config-e2e-judge.yaml` |
| Proxy config (judge OFF) | `tests/e2e/fixtures/config-e2e.yaml` |
| Proxy debug routes | `crates/llmtrace-proxy/src/debug.rs` |
| Loop tracker | `docs/TODO_E2E.md` |
