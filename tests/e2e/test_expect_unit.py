"""Unit tests for the expectation DSL (Loop E2E-L6 of #91).

Pure-function tests: every input is synthesised in-process. No proxy is
booted, no network is hit. Each comparator gets at least one passing
test and one failing test so failure-message wording is exercised.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from tests.e2e.expect import (
    AssertionResult,
    ProxyOutcome,
    RecommendedAction,
    Severity,
    assert_scenario,
    classify_proxy_outcome,
    render_assertion_summary,
)
from tests.e2e.observer import MetricsSnapshot


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


@dataclass
class FakeResponse:
    status_code: int
    headers: dict[str, str]
    body: dict[str, Any] | None = None

    def json(self):
        if self.body is None:
            raise ValueError("no body")
        return self.body


def _delta_from_text(text: str) -> MetricsSnapshot:
    return MetricsSnapshot.parse(text)


def _scenario(expected: dict[str, Any], sid: str = "scn-001") -> dict[str, Any]:
    return {"id": sid, "family": "prompt_injection", "prompt": "x", "expected": expected}


def _empty_response(status: int = 200, flagged: bool = False) -> FakeResponse:
    headers = {"x-llmtrace-flagged": "true"} if flagged else {}
    return FakeResponse(status_code=status, headers=headers)


def _block_response() -> FakeResponse:
    return FakeResponse(
        status_code=403,
        headers={},
        body={"error": {"type": "proxy_error", "message": "blocked"}},
    )


# ---------------------------------------------------------------------------
# Severity ladder
# ---------------------------------------------------------------------------


def test_severity_ordering_is_total_and_increasing() -> None:
    assert (
        Severity.INFO
        < Severity.LOW
        < Severity.MEDIUM
        < Severity.HIGH
        < Severity.CRITICAL
    )


def test_severity_parse_round_trips_labels() -> None:
    for label in ("Info", "Low", "Medium", "High", "Critical"):
        assert Severity.parse(label).label == label


def test_severity_parse_rejects_unknown_label() -> None:
    with pytest.raises(ValueError, match="unknown severity"):
        Severity.parse("Catastrophic")


# ---------------------------------------------------------------------------
# Outcome classifier
# ---------------------------------------------------------------------------


def test_classify_proxy_outcome_block_when_proxy_error() -> None:
    assert classify_proxy_outcome(_block_response()) is ProxyOutcome.BLOCK


def test_classify_proxy_outcome_warn_when_flagged_header_set() -> None:
    assert classify_proxy_outcome(_empty_response(flagged=True)) is ProxyOutcome.WARN


def test_classify_proxy_outcome_allow_when_clean_200() -> None:
    assert classify_proxy_outcome(_empty_response()) is ProxyOutcome.ALLOW


def test_classify_proxy_outcome_allow_when_4xx_without_proxy_error_type() -> None:
    # Upstream 4xx that the proxy forwarded; not a proxy block.
    response = FakeResponse(status_code=429, headers={}, body=None)
    assert classify_proxy_outcome(response) is ProxyOutcome.ALLOW


# ---------------------------------------------------------------------------
# proxy_outcome.at_least / at_most
# ---------------------------------------------------------------------------


def test_proxy_outcome_at_least_passes_when_observed_meets_floor() -> None:
    results = assert_scenario(
        _scenario({"proxy_outcome.at_least": "warn"}),
        response=_empty_response(flagged=True),
        delta=MetricsSnapshot(),
    )
    assert [r.passed for r in results] == [True]


def test_proxy_outcome_at_least_fails_when_observed_below_floor() -> None:
    results = assert_scenario(
        _scenario({"proxy_outcome.at_least": "warn"}),
        response=_empty_response(),
        delta=MetricsSnapshot(),
    )
    assert results[0].passed is False
    assert "expected >= warn" in results[0].message
    assert "observed allow" in results[0].message


def test_proxy_outcome_at_most_passes_when_observed_within_ceiling() -> None:
    results = assert_scenario(
        _scenario({"proxy_outcome.at_most": "warn"}),
        response=_empty_response(flagged=True),
        delta=MetricsSnapshot(),
    )
    assert results[0].passed is True


def test_proxy_outcome_at_most_fails_when_observed_above_ceiling() -> None:
    results = assert_scenario(
        _scenario({"proxy_outcome.at_most": "warn"}),
        response=_block_response(),
        delta=MetricsSnapshot(),
    )
    assert results[0].passed is False
    assert "expected <= warn" in results[0].message
    assert "observed block" in results[0].message


# ---------------------------------------------------------------------------
# findings_include
# ---------------------------------------------------------------------------


_FINDINGS_FIXTURE = """
# HELP llmtrace_security_findings_total .
# TYPE llmtrace_security_findings_total counter
llmtrace_security_findings_total{finding_type="jailbreak",severity="High"} 2.0
llmtrace_security_findings_total{finding_type="encoding_attack",severity="Critical"} 1.0
"""


def test_findings_include_passes_when_all_required_types_observed() -> None:
    delta = _delta_from_text(_FINDINGS_FIXTURE)
    results = assert_scenario(
        _scenario(
            {
                "findings_include": ["jailbreak", "encoding_attack"],
                "proxy_outcome.at_least": "warn",
            }
        ),
        response=_empty_response(flagged=True),
        delta=delta,
    )
    findings = next(r for r in results if r.comparator == "findings_include")
    assert findings.passed is True


def test_findings_include_fails_with_missing_types_listed() -> None:
    delta = _delta_from_text(_FINDINGS_FIXTURE)
    results = assert_scenario(
        _scenario(
            {"findings_include": ["jailbreak", "prompt_injection", "ghost"]}
        ),
        response=_empty_response(),
        delta=delta,
    )
    findings = next(r for r in results if r.comparator == "findings_include")
    assert findings.passed is False
    assert "prompt_injection" in findings.message
    assert "ghost" in findings.message
    assert "jailbreak" not in findings.fields["missing"]


# ---------------------------------------------------------------------------
# findings_min_severity
# ---------------------------------------------------------------------------


def test_findings_min_severity_passes_when_peak_meets_floor() -> None:
    delta = _delta_from_text(_FINDINGS_FIXTURE)
    results = assert_scenario(
        _scenario({"findings_min_severity": "High"}),
        response=_empty_response(),
        delta=delta,
    )
    sev = next(r for r in results if r.comparator == "findings_min_severity")
    assert sev.passed is True
    assert sev.fields["observed_peak"] == "Critical"


def test_findings_min_severity_fails_when_peak_below_floor() -> None:
    fixture = (
        "# HELP llmtrace_security_findings_total .\n"
        "# TYPE llmtrace_security_findings_total counter\n"
        'llmtrace_security_findings_total{finding_type="repeat",severity="Low"} 1.0\n'
    )
    results = assert_scenario(
        _scenario({"findings_min_severity": "High"}),
        response=_empty_response(),
        delta=_delta_from_text(fixture),
    )
    sev = next(r for r in results if r.comparator == "findings_min_severity")
    assert sev.passed is False
    assert "expected >= High" in sev.message
    assert "observed peak Low" in sev.message


def test_findings_min_severity_fails_with_clear_message_when_no_findings() -> None:
    results = assert_scenario(
        _scenario({"findings_min_severity": "Medium"}),
        response=_empty_response(),
        delta=MetricsSnapshot(),
    )
    sev = next(r for r in results if r.comparator == "findings_min_severity")
    assert sev.passed is False
    assert "observed no findings" in sev.message


# ---------------------------------------------------------------------------
# judge_verdict.*
# ---------------------------------------------------------------------------


def _verdict(**overrides: Any) -> dict[str, Any]:
    base = {
        "is_threat": True,
        "category": "prompt_injection",
        "recommended_action": "flag",
        "confidence": 0.9,
    }
    base.update(overrides)
    return base


def test_judge_verdict_passes_when_all_keys_match() -> None:
    results = assert_scenario(
        _scenario(
            {
                "judge_verdict": {
                    "is_threat": True,
                    "category": "prompt_injection",
                    "recommended_action.at_least": "flag",
                }
            }
        ),
        response=_empty_response(flagged=True),
        delta=MetricsSnapshot(),
        verdict=_verdict(),
    )
    judge_results = [r for r in results if r.comparator.startswith("judge_verdict.")]
    assert all(r.passed for r in judge_results)


def test_judge_verdict_is_threat_fails_with_clear_message() -> None:
    results = assert_scenario(
        _scenario({"judge_verdict": {"is_threat": False}}),
        response=_empty_response(),
        delta=MetricsSnapshot(),
        verdict=_verdict(is_threat=True),
    )
    res = next(r for r in results if r.comparator == "judge_verdict.is_threat")
    assert res.passed is False
    assert "expected False" in res.message
    assert "observed True" in res.message


def test_judge_verdict_recommended_action_at_least_passes_with_higher_observed() -> None:
    results = assert_scenario(
        _scenario(
            {"judge_verdict": {"recommended_action.at_least": "flag"}}
        ),
        response=_empty_response(),
        delta=MetricsSnapshot(),
        verdict=_verdict(recommended_action="block"),
    )
    res = next(
        r
        for r in results
        if r.comparator == "judge_verdict.recommended_action.at_least"
    )
    assert res.passed is True


def test_judge_verdict_recommended_action_at_most_rejects_higher_observed() -> None:
    results = assert_scenario(
        _scenario({"judge_verdict": {"recommended_action.at_most": "flag"}}),
        response=_empty_response(),
        delta=MetricsSnapshot(),
        verdict=_verdict(recommended_action="block"),
    )
    res = next(
        r
        for r in results
        if r.comparator == "judge_verdict.recommended_action.at_most"
    )
    assert res.passed is False
    assert "expected <= flag" in res.message
    assert "observed block" in res.message


def test_judge_verdict_returns_hard_fail_when_verdict_missing_and_healthy() -> None:
    results = assert_scenario(
        _scenario({"judge_verdict": {"is_threat": True}}),
        response=_empty_response(),
        delta=MetricsSnapshot(),
        verdict=None,
        judge_degraded=False,
    )
    res = next(r for r in results if r.comparator == "judge_verdict.is_threat")
    assert res.passed is False
    assert res.soft is False
    assert "no verdict was recorded" in res.message
    assert "healthy" in res.message


def test_judge_verdict_returns_soft_fail_when_verdict_missing_and_degraded() -> None:
    results = assert_scenario(
        _scenario({"judge_verdict": {"is_threat": True}}),
        response=_empty_response(),
        delta=MetricsSnapshot(),
        verdict=None,
        judge_degraded=True,
    )
    res = next(r for r in results if r.comparator == "judge_verdict.is_threat")
    assert res.passed is False
    assert res.soft is True
    assert "soft-failed" in res.message


# ---------------------------------------------------------------------------
# Orchestrator-level behaviour
# ---------------------------------------------------------------------------


def test_unknown_top_level_expectation_key_returns_failure_row() -> None:
    results = assert_scenario(
        _scenario({"some_made_up_key": True}),
        response=_empty_response(),
        delta=MetricsSnapshot(),
    )
    assert len(results) == 1
    assert results[0].passed is False
    assert "not a supported expectation key" in results[0].message


def test_unknown_judge_verdict_subkey_returns_failure_row() -> None:
    results = assert_scenario(
        _scenario({"judge_verdict": {"weird_field": "value"}}),
        response=_empty_response(),
        delta=MetricsSnapshot(),
        verdict=_verdict(),
    )
    res = next(r for r in results if r.comparator == "judge_verdict.weird_field")
    assert res.passed is False
    assert "not a supported comparator" in res.message


def test_render_assertion_summary_includes_marker_per_row() -> None:
    rows = [
        AssertionResult(comparator="a", passed=True, fields={"x": 1}),
        AssertionResult(
            comparator="b", passed=False, soft=True, message="b explained"
        ),
        AssertionResult(comparator="c", passed=False, message="c explained"),
    ]
    rendered = render_assertion_summary(rows)
    assert "[ok] a" in rendered
    assert "[soft] b" in rendered
    assert "[FAIL] c" in rendered


def test_render_assertion_summary_handles_empty_input() -> None:
    assert "no comparators" in render_assertion_summary([])
