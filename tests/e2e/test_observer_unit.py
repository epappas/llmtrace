"""Unit tests for the metrics observer (Loop E2E-L4 of #91).

No live proxy: tests parse the recorded `/metrics` text fixtures under
tests/e2e/fixtures/ so the parser+diff logic is exercised
deterministically. The fixtures are hand-built to cover the four shapes
the observer needs to get right: counter delta, gauge "latest wins",
histogram (count/sum/bucket) deltas, and counter samples that are still
zero in both snapshots (must not appear as a non-zero delta).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.e2e.observer import (
    MetricsSnapshot,
    collect_finding_types,
    render_assertion_context,
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def _load(name: str) -> str:
    return (FIXTURES_DIR / name).read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def before() -> MetricsSnapshot:
    return MetricsSnapshot.parse(_load("sample_metrics_before.txt"))


@pytest.fixture(scope="module")
def after() -> MetricsSnapshot:
    return MetricsSnapshot.parse(_load("sample_metrics_after.txt"))


@pytest.fixture(scope="module")
def delta(before: MetricsSnapshot, after: MetricsSnapshot) -> MetricsSnapshot:
    return after.diff(before)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def test_parser_recognises_metric_types(before: MetricsSnapshot) -> None:
    assert before.metric_types["llmtrace_security_findings"] == "counter"
    assert before.metric_types["llmtrace_judge_queue_depth"] == "gauge"
    assert before.metric_types["llmtrace_judge_latency_seconds"] == "histogram"


def test_contains_matches_family_and_sample_name(before: MetricsSnapshot) -> None:
    assert "llmtrace_security_findings_total" in before
    assert "llmtrace_security_findings" in before
    assert "llmtrace_judge_queue_depth" in before
    assert "no_such_metric" not in before


# ---------------------------------------------------------------------------
# Counter diffs
# ---------------------------------------------------------------------------


def test_counter_delta_subtracts_per_label_set(delta: MetricsSnapshot) -> None:
    # Existing label set: 14 - 12 = 2.
    assert (
        delta.series(
            "llmtrace_security_findings_total",
            {"finding_type": "prompt_injection", "severity": "High"},
        )
        == 2.0
    )


def test_counter_delta_for_new_label_set_is_full_value(delta: MetricsSnapshot) -> None:
    # `prompt_injection / Medium` only appears in `after`; delta == after value.
    assert (
        delta.series(
            "llmtrace_security_findings_total",
            {"finding_type": "prompt_injection", "severity": "Medium"},
        )
        == 1.0
    )


def test_counter_delta_zero_for_unchanged_series(delta: MetricsSnapshot) -> None:
    # `jailbreak / Medium` is identical (4) in both snapshots → delta 0.
    assert (
        delta.series(
            "llmtrace_security_findings_total",
            {"finding_type": "jailbreak", "severity": "Medium"},
        )
        == 0.0
    )


def test_label_subset_match_sums_across_unspecified_labels(
    delta: MetricsSnapshot,
) -> None:
    # finding_type=prompt_injection sums across both severity buckets:
    # (14-12) + (1-0) = 3.
    assert (
        delta.series(
            "llmtrace_security_findings_total",
            {"finding_type": "prompt_injection"},
        )
        == 3.0
    )


def test_series_returns_none_when_no_match(delta: MetricsSnapshot) -> None:
    assert delta.series("llmtrace_security_findings_total", {"finding_type": "ghost"}) is None
    assert delta.series("nonexistent_metric") is None


def test_query_works_with_or_without_total_suffix(delta: MetricsSnapshot) -> None:
    a = delta.series(
        "llmtrace_security_findings_total",
        {"finding_type": "prompt_injection", "severity": "High"},
    )
    b = delta.series(
        "llmtrace_security_findings",
        {"finding_type": "prompt_injection", "severity": "High"},
    )
    assert a == b == 2.0


# ---------------------------------------------------------------------------
# Gauge: "latest wins"
# ---------------------------------------------------------------------------


def test_gauge_uses_latest_value_not_subtraction(delta: MetricsSnapshot) -> None:
    # Subtraction would give 5 - 2 = 3, but gauges report the *latest*.
    assert delta.series("llmtrace_judge_queue_depth") == 5.0


# ---------------------------------------------------------------------------
# Histogram: count/sum/bucket deltas
# ---------------------------------------------------------------------------


def test_histogram_count_subtracts(delta: MetricsSnapshot) -> None:
    assert (
        delta.series(
            "llmtrace_judge_latency_seconds_count",
            {"backend": "deberta", "mode": "sync", "model": "x"},
        )
        == 2.0
    )


def test_histogram_sum_subtracts(delta: MetricsSnapshot) -> None:
    observed = delta.series(
        "llmtrace_judge_latency_seconds_sum",
        {"backend": "deberta", "mode": "sync", "model": "x"},
    )
    assert observed == pytest.approx(0.19, abs=1e-9)


def test_histogram_bucket_subtracts(delta: MetricsSnapshot) -> None:
    assert (
        delta.series(
            "llmtrace_judge_latency_seconds_bucket",
            {"le": "0.1", "backend": "deberta", "mode": "sync", "model": "x"},
        )
        == 1.0
    )


# ---------------------------------------------------------------------------
# Pretty-printing
# ---------------------------------------------------------------------------


def test_nonzero_items_excludes_zero_deltas(delta: MetricsSnapshot) -> None:
    names_with_nonzero = {row[0] for row in delta.nonzero_items()}
    assert "llmtrace_security_findings_total" in names_with_nonzero
    assert "llmtrace_judge_dropped_total" not in names_with_nonzero  # was 0 in both


def test_render_nonzero_is_deterministic_and_sorted(delta: MetricsSnapshot) -> None:
    rendered = delta.render_nonzero()
    lines = [line for line in rendered.splitlines() if line.strip()]
    assert lines == sorted(lines), (
        "non-zero delta render must be sorted so failure messages diff cleanly"
    )


def test_render_assertion_context_filters_to_security_families(
    delta: MetricsSnapshot,
) -> None:
    rendered = render_assertion_context(delta)
    assert "llmtrace_security_findings_total" in rendered
    # Histogram families intentionally not in the filtered context: too noisy.
    assert "llmtrace_judge_latency_seconds_bucket" not in rendered


# ---------------------------------------------------------------------------
# Helpers used by integration tests
# ---------------------------------------------------------------------------


def test_collect_finding_types_returns_only_observed_types(
    delta: MetricsSnapshot,
) -> None:
    assert collect_finding_types(delta) == {"prompt_injection"}


def test_render_no_changes_is_explicit() -> None:
    # An empty-on-empty diff has no non-zero samples (gauge "latest wins"
    # semantics mean a real before.diff(before) still surfaces gauge values,
    # so we synthesise a true no-op delta here).
    empty = MetricsSnapshot()
    rendered = empty.render_nonzero()
    assert "no non-zero samples" in rendered


def test_diff_self_zeroes_counter_samples_but_keeps_gauge(
    before: MetricsSnapshot,
) -> None:
    no_change = before.diff(before)
    assert (
        no_change.series(
            "llmtrace_security_findings_total",
            {"finding_type": "prompt_injection", "severity": "High"},
        )
        == 0.0
    )
    # Gauges report the latest absolute value, even on a self-diff.
    assert no_change.series("llmtrace_judge_queue_depth") == 2.0
