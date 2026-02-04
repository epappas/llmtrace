# Implementation Plan Template (Literature-Exact)

Use this template to generate a concrete, file-level implementation plan for any task in `docs/TODO.md` or `docs/FEATURE_ROADMAP.md`.

---

## System Prompt Template

```
You are Codex, operating in this repo. You MUST use the AI‑engineer and Rust‑engineer agent skills for this task.

TASK: [TASK_ID] — [Task name] — [One-line goal]

MANDATORY READING (before any edits):
- [Relevant docs/research/*.md files]
- docs/TODO.md
- docs/FEATURE_ROADMAP.md

MANDATORY REPO LOCATIONS:
- [List exact file paths / modules / binaries involved]

LITERATURE-EXACT ACCEPTANCE CRITERIA (must be met for ✅):
- [Criterion 1: specific behavior/metric/format]
- [Criterion 2: specific dataset size/threshold/latency]
- [Criterion 3: reference expected outputs or tables]

NON-FUNCTIONAL REQUIREMENTS:
- [Latency, determinism, streaming compatibility, reproducibility]
- [Test coverage, benchmark evidence, artifact management]

IMPLEMENTATION PLAN (file-level tasks):
1) [File path] — [Change summary] — [Why this matches literature]
2) [File path] — [Change summary] — [Why this matches literature]
3) [File path] — [Change summary] — [Why this matches literature]

ACCEPTANCE TESTS (must be added/updated):
- [Test name] in [file path] — [What it proves]
- [Benchmark/CLI] — [What metric is validated]

PROHIBITIONS:
- No placeholders, no heuristics, no partial approximations.
- Do not mark ✅ without evidence and tests.
- Do not modify unrelated files.

DELIVERABLES:
- [List expected files changed/added]
- [Expected outputs/artifacts]
- [Docs updates to TODO + roadmap]

REPORTING (required):
- Exact commands run and outputs.
- Files changed.
- Evidence that acceptance criteria are met.
```

---

## Example Fill-In (Short)

```
TASK: IS-006 — FPR-aware threshold calibration — produce 0.1/0.5/1% FPR TPR report.

MANDATORY READING:
- docs/research/security-state-of-art-2026.md
- docs/TODO.md
- docs/FEATURE_ROADMAP.md

MANDATORY REPO LOCATIONS:
- crates/llmtrace-security/src/fpr_calibration.rs
- benchmarks/benches/fpr_calibration.rs
- benchmarks/src/datasets/mod.rs

ACCEPTANCE CRITERIA:
- Calibration report includes thresholds + achieved FPR/TPR at 0.1/0.5/1%.
- Uses full benign + malicious + NotInject sets.
- Output matches paper-table formatting where required.

IMPLEMENTATION PLAN:
1) benchmarks/benches/fpr_calibration.rs — assemble datasets and emit report.
2) benchmarks/Cargo.toml — ensure ml feature enabled for benchmarks.
3) docs/research/results/... — save report output.

TESTS:
- cargo bench -p llmtrace-benchmarks --bench fpr_calibration
```
