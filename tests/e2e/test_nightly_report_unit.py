"""Unit tests for the nightly report generator (Loop E2E-L10 of #91).

The report generator's primary value is the diff section vs the
previous run; its primary contract is determinism (sorted ids, frozen
precision, no wall-clock timestamps in the body). These tests pin both.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts" / "e2e"))

import generate_nightly_report as gnr  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _row(id: str, *, outcome: str, family: str = "prompt_injection", **extra) -> dict:
    base = {
        "id": id,
        "family": family,
        "tags": [],
        "outcome": outcome,
        "duration_secs": 1.0,
    }
    base.update(extra)
    return base


def _payload(rows: list[dict]) -> dict:
    return {"schema_version": 1, "scenarios": sorted(rows, key=lambda r: r["id"])}


def _write_results(tmp_path: Path, rows: list[dict]) -> Path:
    p = tmp_path / "results.json"
    p.write_text(json.dumps(_payload(rows), indent=2, sort_keys=True), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Roll-up tests
# ---------------------------------------------------------------------------


def test_summary_counts():
    results = {
        "a": _row("a", outcome="passed"),
        "b": _row("b", outcome="failed"),
        "c": _row("c", outcome="failed"),
        "d": _row("d", outcome="skipped"),
    }
    s = gnr.summary_counts(results)
    assert s == {"total": 4, "passed": 1, "failed": 2, "skipped": 1}


def test_fails_by_family_sorted():
    results = {
        "z-1": _row("z-1", outcome="failed", family="jailbreak"),
        "a-1": _row("a-1", outcome="failed", family="jailbreak"),
        "p-1": _row("p-1", outcome="failed", family="prompt_injection"),
        "p-2": _row("p-2", outcome="passed", family="prompt_injection"),
    }
    out = gnr.fails_by_family(results)
    assert list(out.keys()) == ["jailbreak", "prompt_injection"]
    assert out["jailbreak"] == ["a-1", "z-1"]
    assert out["prompt_injection"] == ["p-1"]


def test_upstream_fell_for_it_rate_skips_none():
    results = {
        "a": _row(
            "a",
            outcome="passed",
            upstream_judgement={"fell_for_it": True, "rule": "dan_marker", "reason": "x"},
        ),
        "b": _row(
            "b",
            outcome="passed",
            upstream_judgement={"fell_for_it": False, "rule": None, "reason": "y"},
        ),
        "c": _row(
            "c",
            outcome="passed",
            upstream_judgement={"fell_for_it": None, "rule": None, "reason": "skipped"},
        ),
    }
    rates = gnr.upstream_fell_for_it_rate(results)
    assert rates == {
        "prompt_injection": {"observed": 2, "fell_for_it": 1, "rate": "50.0%"}
    }


# ---------------------------------------------------------------------------
# Diff tests
# ---------------------------------------------------------------------------


def test_diff_first_run_lists_everything_as_new():
    current = {"a": _row("a", outcome="passed"), "b": _row("b", outcome="failed")}
    diff = gnr.diff_outcomes(current, previous=None)
    assert diff["new"] == [
        {"id": "a", "outcome": "passed"},
        {"id": "b", "outcome": "failed"},
    ]
    assert diff["regressions"] == []
    assert diff["recoveries"] == []
    assert diff["removed"] == []


def test_diff_regression_passed_to_failed():
    previous = {"x": _row("x", outcome="passed")}
    current = {"x": _row("x", outcome="failed")}
    diff = gnr.diff_outcomes(current, previous)
    assert diff["regressions"] == [{"id": "x", "from": "passed", "to": "failed"}]
    assert diff["recoveries"] == []


def test_diff_recovery_failed_to_passed():
    previous = {"x": _row("x", outcome="failed")}
    current = {"x": _row("x", outcome="passed")}
    diff = gnr.diff_outcomes(current, previous)
    assert diff["recoveries"] == [{"id": "x", "from": "failed", "to": "passed"}]
    assert diff["regressions"] == []


def test_diff_skip_to_passed_is_not_a_recovery():
    previous = {"x": _row("x", outcome="skipped")}
    current = {"x": _row("x", outcome="passed")}
    diff = gnr.diff_outcomes(current, previous)
    # skipped is not a fail state; this is a no-op
    assert diff["regressions"] == []
    assert diff["recoveries"] == []
    assert diff["new"] == []


def test_diff_new_and_removed():
    previous = {"old": _row("old", outcome="passed")}
    current = {"new": _row("new", outcome="passed")}
    diff = gnr.diff_outcomes(current, previous)
    assert diff["new"] == [{"id": "new", "outcome": "passed"}]
    assert diff["removed"] == [{"id": "old", "outcome": "passed"}]


# ---------------------------------------------------------------------------
# Determinism tests
# ---------------------------------------------------------------------------


def test_render_no_wall_clock_timestamps_in_body():
    """The body must not contain HH:MM:SS or ISO timestamps that would
    make the diff non-deterministic across same-input runs."""
    results = {"a": _row("a", outcome="passed")}
    body = gnr.render_report(
        date="2026-04-23",
        results=results,
        previous_path=None,
        diff=gnr.diff_outcomes(results, None),
    )
    # The date is in the heading (intentional). Anything that looks like
    # a HH:MM:SS clock time should be absent.
    import re
    assert re.search(r"\b\d{2}:\d{2}:\d{2}\b", body) is None


def test_render_byte_identical_on_repeated_calls():
    results = {
        "a": _row("a", outcome="passed"),
        "b": _row("b", outcome="failed"),
    }
    diff = gnr.diff_outcomes(results, None)
    a = gnr.render_report(
        date="2026-04-23", results=results, previous_path=None, diff=diff
    )
    b = gnr.render_report(
        date="2026-04-23", results=results, previous_path=None, diff=diff
    )
    assert a == b


def test_render_full_pipeline_writes_two_files(tmp_path):
    results_path = _write_results(
        tmp_path,
        [
            _row(
                "a",
                outcome="passed",
                upstream_judgement={"fell_for_it": False, "rule": None, "reason": "x"},
            ),
            _row("b", outcome="failed", family="jailbreak"),
        ],
    )
    report_dir = tmp_path / "out"
    sys.argv = [
        "generate_nightly_report.py",
        "--results-json", str(results_path),
        "--report-dir", str(report_dir),
        "--date", "2026-04-23",
    ]
    rc = gnr.main()
    assert rc == 0
    md = report_dir / "e2e_2026-04-23.md"
    js = report_dir / "e2e_2026-04-23.json"
    assert md.exists()
    assert js.exists()
    body = md.read_text(encoding="utf-8")
    assert "# E2E nightly report — 2026-04-23" in body
    assert "## Summary" in body
    assert "## Regressions vs previous" in body
    assert "## Fails by family" in body
    assert "## Upstream-fell-for-it rate by family" in body


def test_find_previous_report_skips_current_date(tmp_path):
    (tmp_path / "e2e_2026-04-22.json").write_text("{}", encoding="utf-8")
    (tmp_path / "e2e_2026-04-23.json").write_text("{}", encoding="utf-8")
    prev = gnr.find_previous_report(tmp_path, "2026-04-23")
    assert prev is not None
    assert prev.name == "e2e_2026-04-22.json"


def test_find_previous_report_none_when_only_current(tmp_path):
    (tmp_path / "e2e_2026-04-23.json").write_text("{}", encoding="utf-8")
    prev = gnr.find_previous_report(tmp_path, "2026-04-23")
    assert prev is None
