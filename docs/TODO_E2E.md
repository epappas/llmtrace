# LLMTrace — E2E Adversarial Test Framework — RALPH Loop Breakdown

**Generated from:** umbrella issue [#91](https://github.com/epappas/llmtrace/issues/91) + children [#92][92]–[#101][101]
**Status:** Draft for review. Not yet merged into `docs/TODO.md`.
**Methodology:** RALPH loops — each loop is one PR-sized unit reviewed by lead engineer before merge.

[91]: https://github.com/epappas/llmtrace/issues/91
[92]: https://github.com/epappas/llmtrace/issues/92
[93]: https://github.com/epappas/llmtrace/issues/93
[94]: https://github.com/epappas/llmtrace/issues/94
[95]: https://github.com/epappas/llmtrace/issues/95
[96]: https://github.com/epappas/llmtrace/issues/96
[97]: https://github.com/epappas/llmtrace/issues/97
[98]: https://github.com/epappas/llmtrace/issues/98
[99]: https://github.com/epappas/llmtrace/issues/99
[100]: https://github.com/epappas/llmtrace/issues/100
[101]: https://github.com/epappas/llmtrace/issues/101

---

## Status Legend
- ⬜ Not started
- 🔄 In progress
- ✅ Done
- ❌ Blocked

---

## Acceptance Criteria (Framework-wide)

The framework's umbrella acceptance is ratified in `#91`:

1. `pytest tests/e2e/ -v` passes locally and in CI on the curated PR-gate subset.
2. The full nightly run produces a deterministic markdown report at `docs/research/results/e2e_<date>.md` that diffs cleanly against the previous run.
3. At least one regression has been caught and filed by the framework before #91 closes (proof it works).
4. `docs/guides/e2e-testing.md` describes how to add a scenario and how to run the harness locally.

Per-loop acceptance is the **AND** of the criteria below the loop table. A loop is ✅ only when:
- The acceptance criteria are met with evidence (commands run + outputs).
- The deliverables table is fully checked off.
- Tests pass on `main` after merge.

---

## Dependency Graph

```
E2E-L1 ──► E2E-L1a ──► E2E-L2 ──┬─► E2E-L3 ──┬─► E2E-L4 ──┬─► E2E-L6 ──┬─► E2E-L9 ──► (PR gate)
                                │            │            │            │
                                │            │            └─► E2E-L5 ──┤
                                │            │                         │
                                │            └─► E2E-L8 ───────────────┤
                                │                                      │
                                └─► E2E-L7 ────────────────────────────┴─► E2E-L10 ──► (nightly)

E2E-L11 (Rust subcommand, stretch) ──► picked up only after E2E-L2..L10 stable
```

**L1a inserted between L1 and L2** — surfaced by the L1 audit (trace-id gap). It blocks L4 and L5 specifically, but starting it before L2 keeps the Rust changes batched with the schema work for review.

---

## Phase E2E-Foundation

### Loop E2E-L1 — Pre-flight Audit
> Verify the proxy already exposes the surfaces the harness assumes (trace-id propagation, metrics shape, judge verdict access). De-risks every downstream loop. Surfaces gaps as Rust-side fix-up sub-tasks **before** Loops E2E-L2+ start.

| ID | Task | Complexity | Status |
|----|------|-----------|--------|
| E2E-001 | Confirm `X-LLMTrace-Test-Trace-Id` (or equivalent) is honored end-to-end | Low | ✅ — gap found |
| E2E-002 | Confirm `/metrics` exposes the labels assumed by L4/L5 | Low | ✅ |
| E2E-003 | Confirm `JudgeVerdictStore` does **not** yet expose `find_by_trace_id` | Low | ✅ — partial: query supports it |
| E2E-004 | Confirm `/health` is auth-exempt and returns 200 quickly | Low | ✅ |
| E2E-005 | Confirm proxy's `upstream_url` accepts a plain `http://localhost:PORT` | Low | ✅ |
| E2E-006 | Confirm graceful shutdown drain ≤ 10 s on SIGTERM | Low | ✅ — needs config override |

#### Findings (2026-04-22)

**E2E-001 — Trace-id propagation: GAP.**
- `crates/llmtrace-proxy/src/proxy.rs:376` always generates `let trace_id = Uuid::new_v4();` at request entry. There is **no inbound trace-id header honored** (no `x-trace-id`, `x-request-id`, `traceparent`, or `x-llmtrace-trace-id`).
- The trace_id is **not echoed** in response headers. `proxy.rs:1147–1167` only injects `x-llmtrace-flagged` / `x-llmtrace-findings` for blocked/flagged requests; the trace-id is logged + stored but not returned.
- Existing `X-LLMTrace-*` headers in use: `x-llmtrace-token`, `x-llmtrace-tenant-id`, `x-llmtrace-agent-id`, `x-llmtrace-provider`, `x-llmtrace-flagged`, `x-llmtrace-findings`. No conflict with adding `x-llmtrace-trace-id`.
- **Required upstream fix (file as a Rust prerequisite under Loop E2E-L5 or as its own micro-loop):**
  - `crates/llmtrace-proxy/src/proxy.rs:376` — accept inbound `X-LLMTrace-Trace-Id: <uuid>` header; if present and parseable, use it instead of generating; otherwise fall back to `Uuid::new_v4()` (current behaviour).
  - `crates/llmtrace-proxy/src/proxy.rs:1147–1167` — always echo `X-LLMTrace-Trace-Id: <uuid>` on every response (success or error), so harness can correlate even when it didn't supply one.
  - Add a config field (or hard-code the header name) — recommendation: hard-code `x-llmtrace-trace-id` to keep config minimal.
- **Blocks:** Loop E2E-L4 (E2E-035), Loop E2E-L5 (E2E-045).

**E2E-002 — `/metrics` shape: GREEN with one label nuance.**
Verified in `crates/llmtrace-proxy/src/metrics.rs`:
| Metric | Labels | Plan match |
|---|---|---|
| `llmtrace_security_findings_total` | `severity`, `finding_type` | ✅ exact |
| `llmtrace_action_executions_total` | `action_type`, `status`, `mode` | ⚠️ plan assumed only `action_type, status` — extra `mode` label is fine, harness should query without filtering on `mode` |
| `llmtrace_judge_requests_total` | `backend`, `model`, `mode`, `status` | ✅ |
| `llmtrace_judge_latency_seconds` | `backend`, `model`, `mode` | ✅ |
| `llmtrace_judge_verdicts_total` | `category`, `recommended_action`, `is_threat`, `model` | ✅ |
| `llmtrace_judge_shadow_would_block_total` | `category`, `recommended_action` | ✅ exact |
| `llmtrace_judge_promotion_rejected_total` | `reason` | ✅ |
| `llmtrace_judge_dropped_total` | `reason` | ✅ (zero-initialised: `disabled`, `below_threshold`, `channel_full`, `channel_closed`, `persist_failure`, `semaphore_closed`, `shutdown`, `analysis_text_truncated`) |
| `llmtrace_judge_verdict_agreement` | `agreement` | ✅ |
| `llmtrace_judge_queue_depth` | (gauge, no labels) | ✅ |
- Also confirmed: metrics endpoint is **unauthenticated** (`metrics.rs:7–8`) — harness can scrape directly with no auth.
- **Action for L4 (E2E-052):** include `mode` in any series query against `action_executions_total` (or use `series(name)` without label match if we want sum-across-modes).

**E2E-003 — `JudgeVerdictStore` access: PARTIAL — no Rust trait change needed; HTTP endpoint still required.**
- `crates/llmtrace-core/src/lib.rs:3219–3251` — `JudgeVerdictQuery` already has `pub trace_id: Option<Uuid>` and `query_verdicts(&self, query: &JudgeVerdictQuery) -> Result<Vec<JudgeVerdict>>` is on the trait.
- All three implementors already filter by `trace_id` via the existing query path: `InMemoryJudgeVerdictStore`, `ClickHouseJudgeVerdictStore`, `PostgresJudgeVerdictStore` (`crates/llmtrace-storage/src/judge_verdict.rs`).
- **No new trait method needed** — Loop E2E-L5 items E2E-040 and E2E-041 are obsolete and should be **deleted from the plan**.
- **Still required:** the debug HTTP endpoint (E2E-042–E2E-044). Confirmed there is no existing `/debug/*` route in `crates/llmtrace-proxy/src/main.rs:917–990`. The endpoint will call `state.storage.judge_verdicts.query_verdicts(JudgeVerdictQuery { trace_id: Some(uuid), .. })` and return the first row (or 404).

**E2E-004 — `/health`: GREEN.**
- Route registered at `crates/llmtrace-proxy/src/main.rs:917`.
- Auth-exempt at `crates/llmtrace-proxy/src/auth.rs:115` (also exempts `/swagger-ui` and `/api-doc`).
- `health_handler` (`crates/llmtrace-proxy/src/proxy.rs:1449`) calls four health checks (traces, metadata, cache, security) — adequate for liveness gating in the harness fixture.
- Harness `/health` poll (60 s timeout in L3 E2E-020) will work as planned.

**E2E-005 — `upstream_url` plaintext: GREEN.**
- Validation at `crates/llmtrace-proxy/src/config.rs:79–82` only requires the URL start with `http://` or `https://`. `http://localhost:PORT` is accepted; the example config (`config.example.yaml:212`) actually defaults to `http://localhost:11434` (Ollama). FastAPI mock pointing at `http://127.0.0.1:<free-port>` will work.

**E2E-006 — Graceful shutdown drain: GREEN with config override.**
- Default `shutdown.timeout_seconds = 30` (`crates/llmtrace-core/src/lib.rs:2382–2384`).
- Harness L3 wants ≤10 s teardown. **No Rust change needed** — the L3 `config-e2e.yaml` fixture (E2E-023) should set `shutdown.timeout_seconds: 5` so SIGTERM-then-wait completes inside the harness's 10 s budget.

#### Plan corrections (apply before starting Loop E2E-L2)

1. **Delete E2E-040 and E2E-041** from Loop E2E-L5 — `find_by_trace_id` already exists via `query_verdicts(JudgeVerdictQuery { trace_id, .. })`. Keep the rest of the Rust prerequisite block (E2E-042–E2E-044) intact.
2. **Add new Rust micro-loop E2E-L1a** — "Honor + echo `X-LLMTrace-Trace-Id`" — must land before Loop E2E-L4 (it gates E2E-035 + E2E-045). Two-file change in `proxy.rs`. ~½ day. New IDs:
   - **E2E-007** — Accept inbound `X-LLMTrace-Trace-Id: <uuid>` header in `proxy.rs:376`; fall back to `Uuid::new_v4()` if missing or unparseable.
   - **E2E-008** — Echo `X-LLMTrace-Trace-Id: <uuid>` on **every** response (success + error paths) in `proxy.rs:1147–1167` and `error_response()`.
   - **E2E-009** — Rust unit test: round-trip an inbound header and assert the echoed value matches.
3. **Pin label nuance** in Loop E2E-L6 (E2E-052) docs: `action_executions_total` queries must accommodate `mode` as a third label.
4. **Add to L3 (E2E-023)**: the rendered e2e config sets `shutdown.timeout_seconds: 5`.

**Acceptance (this loop):**
- ✅ All 6 audit items have a recorded outcome above.
- ✅ One gap (E2E-001) is filed as new micro-loop **E2E-L1a** with three explicit Rust changes (E2E-007, E2E-008, E2E-009).
- ✅ One simplification (E2E-003) prunes the L5 plan (E2E-040, E2E-041 deleted).
- ✅ Two fixture defaults (action_executions `mode` label; `shutdown.timeout_seconds: 5`) recorded for L3/L6.

---

### Loop E2E-L1a — Honor + Echo `X-LLMTrace-Trace-Id` Header (NEW — surfaced by L1)
> Add the harness-controlled correlation id without which Loops E2E-L4 and E2E-L5 can't deterministically attribute observations to scenarios.

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| E2E-007 | `crates/llmtrace-proxy/src/proxy.rs` — new `TRACE_ID_HEADER` const + `extract_or_generate_trace_id(&HeaderMap) -> Uuid` helper; handler reads `x-llmtrace-trace-id` from inbound headers; parses as `Uuid`; falls back to `Uuid::new_v4()` if missing/unparseable | Low | ✅ |
| E2E-008 | `crates/llmtrace-proxy/src/proxy.rs` — every response echoes `X-LLMTrace-Trace-Id: <uuid>`: success builder, `error_response()` (4 call sites updated), `rate_limit_response()`, `cap_rejected_response()` | Low | ✅ |
| E2E-009 | Rust unit tests: valid inbound round-trips (`test_extract_or_generate_trace_id_honors_valid_inbound`), whitespace-tolerant (`…_tolerates_surrounding_whitespace`), missing inbound generates fresh v4 (`…_generates_when_missing`), unparseable inbound generates fresh v4 (`…_generates_when_unparseable`), error_response echoes header (`test_error_response_format`), cap_rejected_response echoes header (`test_cap_rejected_response_format`) | Low | ✅ |

**Acceptance (met):**
- ✅ `cargo test -p llmtrace --lib proxy::` — 27/27 pass (4 new trace-id tests + 2 updated response-shape tests + 21 pre-existing).
- ✅ `cargo test -p llmtrace --lib` — full suite 569/569 pass, no regressions.
- ✅ `cargo clippy -p llmtrace --lib -- -D warnings` — clean.
- ✅ `cargo fmt --check -p llmtrace` — clean.

**Blocks:** Loop E2E-L4 (E2E-035), Loop E2E-L5 (E2E-045). Both can now proceed.

---

## Phase E2E-Schema

### Loop E2E-L2 — Attack-Scenario Schema + Validator (issue [#92][92])
> Lock the YAML contract every test scenario follows. Blocks every other loop in the framework.

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| E2E-010 | `benchmarks/attacks/schema.json` — JSON Schema for scenario YAML | Low | ⬜ |
| E2E-011 | `benchmarks/attacks/SCHEMA.md` — canonical enums (`family`, `proxy_outcome`, `recommended_action`, `severity`) + field reference | Low | ⬜ |
| E2E-012 | `scripts/e2e/validate_scenarios.py` — loads `**/*.yaml`, validates, rejects duplicate ids, prints per-file summary, non-zero exit on failure | Low | ⬜ |
| E2E-013 | 3 hand-written example scenarios: `prompt_injection/dan-classic-001.yaml`, `over_defense/xstest-violence-question-001.yaml`, `encoding_evasion/base64-command-001.yaml` | Low | ⬜ |
| E2E-014 | Pre-commit hook + CI step calling the validator | Low | ⬜ |

**Acceptance:**
- `python3 scripts/e2e/validate_scenarios.py` exits 0 on the 3 example scenarios; exits non-zero if any required field is removed.
- Schema covers both judge-enabled and judge-disabled runs (`judge_verdict` block optional).
- `family` is a closed enum (rejects unknown values).
- Pre-commit hook fires on any change under `benchmarks/attacks/`.

---

## Phase E2E-Harness

### Loop E2E-L3 — Pytest Harness Skeleton + Mock Upstream (issue [#93][93])
> Boot LLMTrace, fire HTTP requests, assert HTTP outcome only. First-cut harness; no metrics/verdict observation yet.

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| E2E-020 | `tests/e2e/conftest.py` — session-scoped `proxy` fixture (subprocess, free-port, `/health` poll, log capture, SIGTERM teardown) | Medium | ⬜ |
| E2E-021 | `tests/e2e/conftest.py::scenarios` fixture (loads `benchmarks/attacks/`, supports `--family=` / `--tag=` filters, parametrises by scenario `id`) | Low | ⬜ |
| E2E-022 | `tests/e2e/mock_upstream.py` — FastAPI `/v1/chat/completions` with canned response | Low | ⬜ |
| E2E-023 | `tests/e2e/fixtures/config-e2e.yaml` (judge off) + `config-e2e-judge.yaml` (cascade enabled, `slow_backend: null` for PR-gate) | Low | ⬜ |
| E2E-024 | `tests/e2e/test_cascade.py::test_scenario` — POSTs prompt, asserts `expected.proxy_outcome.at_least` only | Low | ⬜ |
| E2E-025 | `requirements-e2e.txt` — pinned `pytest`, `requests`, `pyyaml`, `jsonschema`, `prometheus-client`, `fastapi`, `uvicorn` | Low | ⬜ |
| E2E-026 | `tests/e2e/README.md` — how to run + how to inspect logs | Low | ⬜ |
| E2E-027 | `.gitignore` for `tests/e2e/.logs/` | Low | ⬜ |

**Acceptance:**
- `pytest tests/e2e/ -v` boots the proxy and the 3 example scenarios pass on a clean checkout.
- No zombie proxy processes after `pytest` exits, even on test failure (verified by `pgrep llmtrace-proxy` returning nothing).
- `tests/e2e/.logs/<session>.log` contains the proxy stdout/stderr for the last run.
- `requirements-e2e.txt` deps install cleanly into a fresh venv.

---

## Phase E2E-Observation

### Loop E2E-L4 — Metrics-Delta + Trace-id Observer (issue [#94][94])
> Per-request view of `/metrics` so assertions can talk about "this scenario produced N findings of type X".

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| E2E-030 | `tests/e2e/observer.py::MetricsSnapshot` (`fetch`, `diff`, `series(name, labels)`, `__contains__`) | Medium | ⬜ |
| E2E-031 | Pretty-printer that dumps full non-zero delta on assertion failure | Low | ⬜ |
| E2E-032 | Unit tests for parser + diff logic against recorded `/metrics` text fixtures (no live proxy) | Low | ⬜ |
| E2E-033 | One `test_cascade.py` test using `delta.series(...)` to assert finding count | Low | ⬜ |
| E2E-034 | `pytest.mark.serial` marker + `conftest.py` guard that errors if `pytest-xdist` (`-n`) is detected | Low | ⬜ |
| E2E-035 | Trace-id header (`X-LLMTrace-Test-Trace-Id: <uuid>`) added on every request | Low | ⬜ |

**Acceptance:**
- `MetricsSnapshot.diff()` is symmetric and correct on recorded fixtures.
- Failure pretty-print includes the full non-zero delta.
- Running `pytest -n auto` errors loudly with a message about counter-diff requiring serial execution.

---

### Loop E2E-L5 — Judge Verdict Collector (issue [#95][95])
> Stitch async judge verdicts back to per-scenario assertions. Includes Rust changes.
>
> **Updated by L1 audit:** `find_by_trace_id` on the trait is no longer needed — `JudgeVerdictQuery { trace_id: Some(uuid), .. }` + `query_verdicts(...)` already covers it (see L1 findings). E2E-040 and E2E-041 have been removed.

**Rust prerequisite (must land first, in this same loop):**

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| ~~E2E-040~~ | ~~`JudgeVerdictStore::find_by_trace_id`~~ — **SUPERSEDED by L1 audit**; use existing `query_verdicts(JudgeVerdictQuery { trace_id, .. })` | — | 🟰 removed |
| ~~E2E-041~~ | ~~Implement on stores~~ — **SUPERSEDED** (all three stores already honour the trace_id filter) | — | 🟰 removed |
| E2E-042 | New config field `server.debug_endpoints: bool` (default `false`) | Low | ⬜ |
| E2E-043 | Proxy route `GET /debug/judge/verdicts?trace_id=<uuid>` registered conditionally on `server.debug_endpoints`; handler calls `state.storage.judge_verdicts.query_verdicts(JudgeVerdictQuery { trace_id: Some(uuid), ..Default::default() })` and returns first row (or 404) | Medium | ⬜ |
| E2E-044 | Rust tests: endpoint returns 200 with verdict payload when flag on + verdict exists; 404 when flag on + no verdict; 404 when flag off | Low | ⬜ |

**Python harness side:**

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| E2E-045 | `tests/e2e/observer.py::poll_judge_verdict(trace_id, timeout=10s)` — 250 ms polling against debug endpoint | Low | ⬜ |
| E2E-046 | Shadow-mode helper reading `llmtrace_judge_shadow_would_block_total` deltas | Low | ⬜ |
| E2E-047 | Degraded-mode handling: if `llmtrace_judge_requests_total{status="backend_error"}` ticks, scenario marked `degraded`, verdict assertions softened | Medium | ⬜ |
| E2E-048 | `docs/guides/e2e-testing.md` — debug endpoint + judge collector lifecycle | Low | ⬜ |

**Acceptance:**
- Debug endpoint returns the verdict for a fired scenario in < 5 s on lite profile.
- Shadow-mode asserter is exercised by at least one scenario with `promotion.shadow: true`.
- Degraded-mode handling verified by pointing cascade slow at `http://127.0.0.1:1` (refused) and observing the scenario fall to `degraded` rather than fail.
- Debug endpoint returns 404 when `server.debug_endpoints: false`.

---

### Loop E2E-L6 — Expectation DSL + Assertion Helpers (issue [#96][96])
> Formalise how `expected:` translates to pytest assertions. Highest-ROI investment for harness debuggability.

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| E2E-050 | `tests/e2e/expect.py::AssertionResult` dataclass (`passed`, `soft`, `message`, `fields`) | Low | ⬜ |
| E2E-051 | `assert_scenario(scenario, http_response, metrics_delta, verdict=None) -> list[AssertionResult]` | Medium | ⬜ |
| E2E-052 | Comparators: `proxy_outcome.at_least/at_most`, `findings_include`, `findings_min_severity`, `judge_verdict.is_threat`, `judge_verdict.recommended_action.at_least/at_most`, `judge_verdict.category` | Medium | ⬜ |
| E2E-053 | Severity ordering as `IntEnum` (`Info < Low < Medium < High < Critical`) | Low | ⬜ |
| E2E-054 | Per-comparator unit tests against synthetic deltas/verdicts (no proxy boot) | Medium | ⬜ |
| E2E-055 | Wired into `test_cascade.py::test_scenario` (replaces the placeholder `proxy_outcome`-only assertion from L3) | Low | ⬜ |
| E2E-056 | Comparator reference table appended to `docs/guides/e2e-testing.md` | Low | ⬜ |

**Acceptance:**
- All comparators implemented and unit-tested.
- Manually breaking one expectation in a scenario produces a failure message that names the scenario `id` and shows observed vs expected (verified by reading the message).

---

## Phase E2E-Corpus

### Loop E2E-L7 — Seed 50 Curated Scenarios (issue [#97][97])
> First real-world corpus. Independent of L3–L6 once L2 lands, so it parallelises.

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| E2E-060 | `scripts/e2e/seed_corpus_from_labels.py` — converts a labeled dataset slice → scenario YAMLs | Medium | ⬜ |
| E2E-061 | 15 `prompt_injection` scenarios (sources: `injection_samples.json`, deepset, ivanleomk, harmbench) | Low | ⬜ |
| E2E-062 | 10 `jailbreak` scenarios (`in_the_wild_jailbreak`, `jackhhao`, `jailbreakbench`, `rubend18`) | Low | ⬜ |
| E2E-063 | 5 `role_injection` scenarios (`injection_samples` role rows + DAN variants) | Low | ⬜ |
| E2E-064 | 5 `prompt_extraction` scenarios (`tensor_trust`, `cyberseceval2`) | Low | ⬜ |
| E2E-065 | 3 `data_exfiltration` scenarios (`injecagent`, `bipia_indirect`) | Low | ⬜ |
| E2E-066 | 5 `encoding_evasion` scenarios (`encoding_evasion.json`, `transfer_attack`) | Low | ⬜ |
| E2E-067 | 5 `over_defense` scenarios (`xstest`, `notinject_samples.json`) | Low | ⬜ |
| E2E-068 | 2 `indirect_injection` scenarios (`bipia_indirect`) | Low | ⬜ |
| E2E-069 | Triage pass: ≥10 scenarios with hand-tightened `expected:` blocks | Medium | ⬜ |
| E2E-070 | Tag 20 of 50 with `tags: [pr-gate]` for L9 (representative coverage, not redundancy) | Low | ⬜ |
| E2E-071 | `benchmarks/attacks/INDEX.md` (auto-regeneratable) — id + family + source + 1-line preview | Low | ⬜ |

**Acceptance:**
- Exactly 50 scenarios committed; distribution matches table ±2.
- `python3 scripts/e2e/validate_scenarios.py` exits 0.
- ≥10 scenarios have non-default `expected:` (evidence of triage).
- `INDEX.md` matches the filesystem (regen + diff produces no change).

---

### Loop E2E-L8 — Upstream-Fell-For-It Detector (issue [#98][98])
> Did the upstream LLM actually fall for the attack? Independent ground-truth signal alongside LLMTrace's own decision.

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| E2E-080 | `tests/e2e/upstream_judge.py::UpstreamJudge` Protocol | Low | ⬜ |
| E2E-081 | `RegexUpstreamJudge` with 6 canonical rule classes (DAN markers, system-prompt extraction, role-play markers, base64/hex blob heuristic, per-scenario substring/regex canaries, system-prompt-canary substring) | Medium | ⬜ |
| E2E-082 | Plug-in seam: env `LLMTRACE_E2E_UPSTREAM_JUDGE={regex,llm}` (LLM impl deferred — leave the Protocol seam only) | Low | ⬜ |
| E2E-083 | Schema extension (in L2's `schema.json` + `SCHEMA.md`): `upstream_fell_for_it.expected` + `upstream_fell_for_it.canaries[]` | Low | ⬜ |
| E2E-084 | Per-rule-class unit tests against recorded response text | Medium | ⬜ |
| E2E-085 | At least one L7 seed scenario uses `upstream_fell_for_it.expected` and passes | Low | ⬜ |
| E2E-086 | Detector runs and reports even when expectation unset (observational signal for nightly base-rate) | Low | ⬜ |

**Acceptance:**
- All 6 rule classes implemented + unit-tested.
- LLM upstream judge filed as a follow-up issue (do not implement here).
- 4xx response bodies are excluded from detector input (LLMTrace blocking ≠ upstream output).

---

## Phase E2E-CI

### Loop E2E-L9 — PR-Gate Workflow (issue [#99][99])
> Fast must-green subset on every PR. ≤ 5 min wall clock target, hard 10 min cap.

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| E2E-090 | `.github/workflows/e2e-pr.yml` triggered on `pull_request` for paths: `crates/llmtrace-proxy/**`, `crates/llmtrace-security/**`, `config*.yaml`, `benchmarks/attacks/**`, `tests/e2e/**` | Medium | ⬜ |
| E2E-091 | Cargo cache keyed on `Cargo.lock`; release build of `llmtrace-proxy` only | Low | ⬜ |
| E2E-092 | Steps: validator (E2E-012) → `pytest tests/e2e/ -v -m 'pr_gate'` against mock upstream → upload junit XML artifact | Low | ⬜ |
| E2E-093 | 10 min hard timeout with explicit failure message pointing at the `pr-gate` tag set as the knob | Low | ⬜ |

**Acceptance:**
- Workflow runs on a dummy PR and passes.
- Intentionally broken PR (tweak one `expected:` field) fails with a clear, scenario-id-naming message.
- Wall time on representative PR < 5 min; hard fail at 10 min.
- pytest-junit XML accessible from the Actions run UI.

---

### Loop E2E-L10 — Nightly Full-Corpus + Committed Report (issue [#100][100])
> Once-per-night real-LLM run; markdown report committed via auto-PR; diff vs previous run is the primary value.

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| E2E-100 | `.github/workflows/e2e-nightly.yml` — `cron: "0 3 * * *"` + `workflow_dispatch` | Low | ⬜ |
| E2E-101 | Secrets wired: `LLMTRACE_JUDGE_OPENAI_API_KEY` (used as both upstream and slow-tier) | Low | ⬜ |
| E2E-102 | Transient extended corpus generated in-memory from `benchmarks/datasets/` (cap 500 stratified samples; **not committed**) | Medium | ⬜ |
| E2E-103 | Run pytest against `config-e2e-judge.yaml` with real OpenRouter upstream | Low | ⬜ |
| E2E-104 | Report generator → `docs/research/results/e2e_YYYY-MM-DD.md` with sections: Summary, Fails-by-family, Regressions-vs-previous, Upstream-fell-for-it rate by family | Medium | ⬜ |
| E2E-105 | Auto-PR via `peter-evans/create-pull-request` (uses `GITHUB_TOKEN`) | Low | ⬜ |
| E2E-106 | Cost cap (≤$2/run) enforced in code as a pytest fixture that aborts the session on overrun | Medium | ⬜ |
| E2E-107 | Wall-clock cap ≤ 1 hour; exceeds → fail-loud | Low | ⬜ |
| E2E-108 | Report body deterministic (sorted scenario ids, frozen decimal precision, no wall-clock timestamps in the diff-comparable section) | Low | ⬜ |

**Acceptance:**
- `workflow_dispatch` runs successfully once on demand.
- First run commits a report by auto-PR.
- Second run's regression section shows zero changes.
- Deliberately break one scenario, rerun, verify diff section flags the new regression.

---

## Phase E2E-Stretch

### Loop E2E-L11 — Rust `llmtrace redteam` Subcommand (issue [#101][101])
> **Stretch.** Native operator-facing redteam command. Open only after L2–L10 stable and operator demand observed.

| ID | Feature | Complexity | Status |
|----|---------|-----------|--------|
| E2E-110 | `crates/llmtrace-e2e/` — new crate housing scenario + expectation types (shared with Python via JSON Schema export) | Medium | ⬜ |
| E2E-111 | `llmtrace redteam` subcommand: `--attacks <dir>`, `--base-url <url>`, `--filter family=...`, `--report <path>`, `--concurrency <n>` | High | ⬜ |
| E2E-112 | Output: human-readable markdown by default; `--format json` for machine consumption | Medium | ⬜ |
| E2E-113 | `docs/guides/redteam.md` with examples | Low | ⬜ |
| E2E-114 | Decide: Python harness delegates to Rust binary if present, OR Python harness retired entirely | Medium | ⬜ |

**Acceptance (revisit when picked up):**
- Subcommand shipped in release binary.
- One quarter of #91 usage data shows operator demand (otherwise close as `wontfix`).

---

## Sequencing & Estimates

**Solo, 3–4 weeks:**
- Week 1: L1 (½ day) + L2 (1–2 d) + L3 (3–4 d)
- Week 2: L4 (2 d) → L5 incl. Rust prereq (3–4 d) → L6 (2 d), L7 in spare cycles
- Week 3: L8 (2 d) → L9 (2 d) → L10 (3 d)
- Stretch: L11 deferred until usage evidence

**2 engineers, ~2 weeks:**
- Eng A: L1 → L2 → L3 → L4 → L5 → L9
- Eng B: (waits for L2) → L7 → L6 → L8 → L10

**4–5 engineers (the #91 split):**
- A: L1 → L2 → L3 → L9
- B: L7 (kicks off when L2 lands)
- C: L4 → L5
- D: L6 → L8
- E: L10 (after L3–L8 stable)

---

## Cross-Loop Risks

1. **Rust-side coupling** — L5's debug endpoint + `find_by_trace_id` is the only sub-issue requiring Rust changes. Schedule it early so review batches with cascade work.
2. **Counter-diff serialisation** — `pytest -n auto` would silently produce nonsense. L4's hard guard (E2E-034) is non-negotiable.
3. **Trace-id discipline** — L1's E2E-001 is load-bearing. If trace ids aren't already first-class, file an upstream Rust loop **before** starting L4.
4. **Mock upstream scope creep** — keep it canned. Real-LLM responses belong in nightly only.
5. **Over-tuning L8 regex** — observational > assertional by default; over-tuning to the seed corpus produces a false sense of coverage.
6. **Report drift in L10** — non-deterministic markdown means every nightly auto-PR shows noise. E2E-108 is load-bearing for the diff workflow's value.
7. **CI cost ceiling** — nightly with cascade slow-tier could 10× the cost on retry storms. E2E-106 cap enforced in code, not docs.
