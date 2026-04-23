# LLMTrace E2E Adversarial Test Framework

> **Status:** scaffold (Loop E2E-L3 of umbrella [#91](https://github.com/epappas/llmtrace/issues/91)). Asserts proxy outcome only — metrics-delta and judge-verdict observability land in Loops E2E-L4–L6.

The harness boots the LLMTrace proxy as a subprocess against an in-process FastAPI mock upstream, fires every scenario YAML under `benchmarks/attacks/` at it, and asserts the per-scenario `expected.proxy_outcome.at_*` constraints.

---

## Prerequisites

1. **Build the proxy binary** (release recommended for CI parity, debug fine for iteration):

   ```bash
   cargo build --release -p llmtrace
   # or: cargo build -p llmtrace
   ```

   The harness auto-discovers the binary in this order: `LLMTRACE_PROXY_BIN`
   env var → `target/release/llmtrace-proxy` → `target/debug/llmtrace-proxy`.

2. **Install the e2e Python deps** (pinned in `requirements-e2e.txt`):

   ```bash
   python3 -m pip install -r requirements-e2e.txt
   ```

3. **Validate the corpus** (optional but recommended before running tests):

   ```bash
   python3 scripts/e2e/validate_scenarios.py --verbose
   ```

---

## Running the harness

From the repo root:

```bash
pytest tests/e2e/ -v
```

### Filtering scenarios

Both flags are **repeatable** and combine as `family AND (any of tags)`:

```bash
# Only DAN-class attacks
pytest tests/e2e/ -v --family=prompt_injection

# Only the PR-gate subset (recommended for fast local feedback)
pytest tests/e2e/ -v --tag=pr-gate

# Multiple families, multiple tags
pytest tests/e2e/ -v \
  --family=prompt_injection --family=jailbreak \
  --tag=pr-gate --tag=direct-override
```

### Running a single scenario

Use pytest's `-k` to match by scenario id:

```bash
pytest tests/e2e/ -v -k dan-classic-001
```

---

## Outcome heuristic

The first-cut classifier in `test_cascade.py::classify_proxy_outcome` maps the proxy response to one of `allow | warn | block`:

| Response | Outcome |
|---|---|
| HTTP `>= 400` with body `{"error": {"type": "proxy_*", ...}}` | `block` |
| HTTP `200` + `x-llmtrace-flagged: true` response header | `warn` |
| Any other HTTP `200` | `allow` |

This will be replaced by the L6 expectation DSL once metrics deltas (L4) and judge verdicts (L5) are wired up.

---

## Inspecting logs

Both subprocesses (`llmtrace-proxy` and `mock_upstream`) capture stdout and stderr to `tests/e2e/.logs/`:

```
tests/e2e/.logs/proxy.log
tests/e2e/.logs/mock_upstream.log
```

The directory is gitignored. Each pytest session overwrites the logs.

---

## Serial-execution constraint

The harness runs **serially** by design. Loops E2E-L4 / L5 will diff per-scenario `/metrics` snapshots; that requires no other request to be in-flight against the proxy. `pytest-xdist` (`-n auto`) is detected and rejected at collection time:

```
UsageError: tests/e2e must run serially: counter-diff observability is global.
```

If you have a real reason to parallelise, that requires per-tenant metric scoping which is out of scope until after L9.

---

## Layout

```
tests/e2e/
  conftest.py              fixtures: proxy lifecycle, mock upstream, scenarios
  test_cascade.py          first-cut parametrised test (proxy_outcome only)
  mock_upstream.py         FastAPI canned response server
  fixtures/
    config-e2e.yaml        base config, judge OFF
    config-e2e-judge.yaml  base config, cascade ON (slow tier null)
  README.md                this file
  .logs/                   gitignored — per-session subprocess logs
```

The scenario corpus and JSON Schema live under `benchmarks/attacks/` (see [`benchmarks/attacks/SCHEMA.md`](../../benchmarks/attacks/SCHEMA.md)).

---

## What this loop does NOT do (yet)

- No `/metrics` deltas (Loop E2E-L4).
- No judge verdict polling (Loop E2E-L5).
- No `findings_include` / `findings_min_severity` checks (Loop E2E-L6).
- No upstream-fell-for-it detector (Loop E2E-L8).
- No CI integration (Loop E2E-L9).

Each follow-up loop is a separate PR; see [`docs/TODO_E2E.md`](../../docs/TODO_E2E.md) for the full breakdown.
