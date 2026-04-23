"""Expectation DSL for the e2e adversarial test framework (Loop E2E-L6 of #91).

Formalises how the `expected:` block of a scenario YAML becomes a list
of `AssertionResult` rows, one per declared comparator. The orchestrator
`assert_scenario(...)` is pure (no I/O): callers fetch the HTTP
response, the metrics delta, and (optionally) the judge verdict, then
hand them in. This makes both the comparators and the orchestrator
trivially unit-testable without booting the proxy.

Failure messages are the highest-ROI investment in the harness — bad
ones turn "the framework broke" into a 30-minute triage. Every comparator
formats its own message naming the scenario id, the expected value, and
the observed value (with the `at_least`/`at_most` semantics named
explicitly).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Mapping

from tests.e2e.observer import MetricsSnapshot, collect_finding_types

# ---------------------------------------------------------------------------
# Ordered enums — the harness compares with `>=` / `<=` semantics
# ---------------------------------------------------------------------------


class Severity(IntEnum):
    """Severity ladder shipped on every `SecurityFinding`.

    Ordered Info < Low < Medium < High < Critical. `findings_min_severity`
    asserts the **peak** severity across the per-scenario finding delta
    is >= the requested floor.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, raw: str) -> "Severity":
        try:
            return _SEVERITY_BY_LABEL[raw]
        except KeyError as e:
            raise ValueError(
                f"unknown severity {raw!r}; valid: {sorted(_SEVERITY_BY_LABEL)}"
            ) from e

    @property
    def label(self) -> str:
        return _SEVERITY_LABELS[self]


_SEVERITY_LABELS: dict[Severity, str] = {
    Severity.INFO: "Info",
    Severity.LOW: "Low",
    Severity.MEDIUM: "Medium",
    Severity.HIGH: "High",
    Severity.CRITICAL: "Critical",
}
_SEVERITY_BY_LABEL: dict[str, Severity] = {v: k for k, v in _SEVERITY_LABELS.items()}


class ProxyOutcome(IntEnum):
    ALLOW = 0
    WARN = 1
    BLOCK = 2

    @classmethod
    def parse(cls, raw: str) -> "ProxyOutcome":
        try:
            return _PROXY_OUTCOME_BY_LABEL[raw]
        except KeyError as e:
            raise ValueError(
                f"unknown proxy_outcome {raw!r}; valid: "
                f"{sorted(_PROXY_OUTCOME_BY_LABEL)}"
            ) from e


_PROXY_OUTCOME_BY_LABEL: dict[str, ProxyOutcome] = {
    "allow": ProxyOutcome.ALLOW,
    "warn": ProxyOutcome.WARN,
    "block": ProxyOutcome.BLOCK,
}


class RecommendedAction(IntEnum):
    ALLOW = 0
    FLAG = 1
    BLOCK = 2

    @classmethod
    def parse(cls, raw: str) -> "RecommendedAction":
        try:
            return _RECOMMENDED_ACTION_BY_LABEL[raw]
        except KeyError as e:
            raise ValueError(
                f"unknown recommended_action {raw!r}; valid: "
                f"{sorted(_RECOMMENDED_ACTION_BY_LABEL)}"
            ) from e


_RECOMMENDED_ACTION_BY_LABEL: dict[str, RecommendedAction] = {
    "allow": RecommendedAction.ALLOW,
    "flag": RecommendedAction.FLAG,
    "block": RecommendedAction.BLOCK,
}


# ---------------------------------------------------------------------------
# AssertionResult
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AssertionResult:
    """One row per declared comparator.

    `passed=False, soft=True` is the degraded-mode case where the harness
    saw evidence the upstream/judge tier flaked (e.g. backend_error). The
    reporter (Loop E2E-L10) treats soft failures as observational signal,
    not a fail.
    """

    comparator: str
    passed: bool
    soft: bool = False
    message: str = ""
    fields: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# HTTP outcome classifier (kept here so the DSL is self-contained)
# ---------------------------------------------------------------------------


def classify_proxy_outcome(response) -> ProxyOutcome:
    """Map a `requests.Response` to a `ProxyOutcome`.

    HTTP >= 400 with body `{"error": {"type": "proxy_*", ...}}` → BLOCK
    (the proxy itself rejected the request). HTTP 200 + the
    `x-llmtrace-flagged: true` response header → WARN. Anything else 2xx
    → ALLOW. Refined by L4/L5 to map all known proxy responses; not a
    heuristic, just a small lookup table.
    """
    if response.status_code >= 400:
        body = _safe_json(response)
        if isinstance(body, dict):
            err = body.get("error")
            if isinstance(err, dict) and str(err.get("type", "")).startswith(
                "proxy_"
            ):
                return ProxyOutcome.BLOCK
    flagged = response.headers.get("x-llmtrace-flagged")
    if flagged and flagged.lower() == "true":
        return ProxyOutcome.WARN
    return ProxyOutcome.ALLOW


def _safe_json(response):
    try:
        return response.json()
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Per-comparator helpers
# ---------------------------------------------------------------------------


def _peak_severity(delta: MetricsSnapshot) -> Severity | None:
    """Return the highest `severity` label across non-zero security findings.

    None means no finding was observed in the window — used by
    `findings_min_severity` to distinguish "saw nothing" from
    "observed Info" so error messages stay accurate.
    """
    peak: Severity | None = None
    for (name, labels), value in delta.samples.items():
        if name != "llmtrace_security_findings_total" or value <= 0:
            continue
        sev_label = dict(labels).get("severity")
        if sev_label is None:
            continue
        try:
            sev = Severity.parse(sev_label)
        except ValueError:
            # Unknown severity label means the proxy emitted something
            # outside the canonical ladder; surface in the message rather
            # than crashing the assertion.
            continue
        if peak is None or sev > peak:
            peak = sev
    return peak


def _compare_proxy_outcome_at_least(
    sid: str, expected_label: str, observed: ProxyOutcome, response
) -> AssertionResult:
    floor = ProxyOutcome.parse(expected_label)
    passed = observed >= floor
    return AssertionResult(
        comparator="proxy_outcome.at_least",
        passed=passed,
        message=(
            ""
            if passed
            else (
                f"[{sid}] proxy_outcome.at_least expected >= {expected_label}, "
                f"observed {observed.name.lower()} "
                f"(status={response.status_code}, "
                f"flagged={response.headers.get('x-llmtrace-flagged')!r})."
            )
        ),
        fields={
            "expected_at_least": expected_label,
            "observed": observed.name.lower(),
            "status": response.status_code,
        },
    )


def _compare_proxy_outcome_at_most(
    sid: str, expected_label: str, observed: ProxyOutcome, response
) -> AssertionResult:
    ceiling = ProxyOutcome.parse(expected_label)
    passed = observed <= ceiling
    return AssertionResult(
        comparator="proxy_outcome.at_most",
        passed=passed,
        message=(
            ""
            if passed
            else (
                f"[{sid}] proxy_outcome.at_most expected <= {expected_label}, "
                f"observed {observed.name.lower()} "
                f"(status={response.status_code}, "
                f"flagged={response.headers.get('x-llmtrace-flagged')!r})."
            )
        ),
        fields={
            "expected_at_most": expected_label,
            "observed": observed.name.lower(),
            "status": response.status_code,
        },
    )


def _compare_findings_include(
    sid: str, expected_types: list[str], delta: MetricsSnapshot
) -> AssertionResult:
    observed_types = collect_finding_types(delta)
    missing = [t for t in expected_types if t not in observed_types]
    passed = not missing
    return AssertionResult(
        comparator="findings_include",
        passed=passed,
        message=(
            ""
            if passed
            else (
                f"[{sid}] findings_include expected to observe "
                f"{expected_types}, missing {missing} "
                f"(saw {sorted(observed_types) or 'none'})."
            )
        ),
        fields={
            "expected": expected_types,
            "missing": missing,
            "observed": sorted(observed_types),
        },
    )


def _compare_findings_min_severity(
    sid: str, expected_label: str, delta: MetricsSnapshot
) -> AssertionResult:
    floor = Severity.parse(expected_label)
    peak = _peak_severity(delta)
    passed = peak is not None and peak >= floor
    if peak is None:
        message = (
            f"[{sid}] findings_min_severity expected >= {expected_label}, "
            f"observed no findings."
        )
    elif passed:
        message = ""
    else:
        message = (
            f"[{sid}] findings_min_severity expected >= {expected_label}, "
            f"observed peak {peak.label}."
        )
    return AssertionResult(
        comparator="findings_min_severity",
        passed=passed,
        message=message,
        fields={
            "expected_floor": expected_label,
            "observed_peak": peak.label if peak else None,
        },
    )


def _compare_judge_verdict(
    sid: str,
    expected: Mapping[str, Any],
    verdict: Mapping[str, Any] | None,
    judge_degraded: bool,
) -> list[AssertionResult]:
    """Run every key in the expected.judge_verdict block.

    When the verdict is missing AND the judge tier reported a backend
    error, every comparator returns a soft failure (the reporter logs
    them but they do not red the run). When the verdict is missing and
    the tier was healthy, every comparator returns a hard failure.
    """
    keys = sorted(expected.keys())
    if verdict is None:
        soft = judge_degraded
        return [
            AssertionResult(
                comparator=f"judge_verdict.{key}",
                passed=False,
                soft=soft,
                message=(
                    f"[{sid}] judge_verdict.{key} expected {expected[key]!r} "
                    f"but no verdict was recorded"
                    + (
                        " (judge tier reported backend_error; soft-failed)."
                        if soft
                        else " (judge tier was healthy; hard-failed)."
                    )
                ),
                fields={"expected": expected[key], "observed": None},
            )
            for key in keys
        ]

    results: list[AssertionResult] = []
    for key in keys:
        if key == "is_threat":
            results.append(_compare_verdict_is_threat(sid, expected[key], verdict))
        elif key == "category":
            results.append(_compare_verdict_category(sid, expected[key], verdict))
        elif key == "recommended_action.at_least":
            results.append(
                _compare_verdict_recommended_action(
                    sid, expected[key], verdict, mode="at_least"
                )
            )
        elif key == "recommended_action.at_most":
            results.append(
                _compare_verdict_recommended_action(
                    sid, expected[key], verdict, mode="at_most"
                )
            )
        else:
            results.append(
                AssertionResult(
                    comparator=f"judge_verdict.{key}",
                    passed=False,
                    message=(
                        f"[{sid}] judge_verdict.{key} is not a supported "
                        f"comparator."
                    ),
                    fields={"expected": expected[key]},
                )
            )
    return results


def _compare_verdict_is_threat(
    sid: str, expected: bool, verdict: Mapping[str, Any]
) -> AssertionResult:
    observed = bool(verdict.get("is_threat"))
    passed = observed == bool(expected)
    return AssertionResult(
        comparator="judge_verdict.is_threat",
        passed=passed,
        message=(
            ""
            if passed
            else (
                f"[{sid}] judge_verdict.is_threat expected {bool(expected)!r}, "
                f"observed {observed!r}."
            )
        ),
        fields={"expected": bool(expected), "observed": observed},
    )


def _compare_verdict_category(
    sid: str, expected: str, verdict: Mapping[str, Any]
) -> AssertionResult:
    observed = verdict.get("category")
    passed = observed == expected
    return AssertionResult(
        comparator="judge_verdict.category",
        passed=passed,
        message=(
            ""
            if passed
            else (
                f"[{sid}] judge_verdict.category expected {expected!r}, "
                f"observed {observed!r}."
            )
        ),
        fields={"expected": expected, "observed": observed},
    )


def _compare_verdict_recommended_action(
    sid: str,
    expected_label: str,
    verdict: Mapping[str, Any],
    *,
    mode: str,
) -> AssertionResult:
    """Shared body for `recommended_action.at_least` / `at_most`."""
    bound = RecommendedAction.parse(expected_label)
    observed_label = verdict.get("recommended_action")
    observed = (
        RecommendedAction.parse(observed_label)
        if observed_label in _RECOMMENDED_ACTION_BY_LABEL
        else None
    )
    passed = (
        observed is not None
        and (observed >= bound if mode == "at_least" else observed <= bound)
    )
    op = ">=" if mode == "at_least" else "<="
    if observed is None:
        message = (
            f"[{sid}] judge_verdict.recommended_action.{mode} expected "
            f"{op} {expected_label}, observed unknown value "
            f"{observed_label!r}."
        )
    elif passed:
        message = ""
    else:
        message = (
            f"[{sid}] judge_verdict.recommended_action.{mode} expected "
            f"{op} {expected_label}, observed {observed.name.lower()}."
        )
    return AssertionResult(
        comparator=f"judge_verdict.recommended_action.{mode}",
        passed=passed,
        message=message,
        fields={
            f"expected_{mode}": expected_label,
            "observed": observed.name.lower() if observed else observed_label,
        },
    )


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

# Map of every supported `expected.*` key (top-level) to its comparator
# function. Adding a new comparator means adding one entry here plus one
# helper above plus one unit test in test_expect_unit.py.
_TOP_LEVEL_COMPARATORS: dict[str, Callable[..., AssertionResult]] = {
    "proxy_outcome.at_least": lambda sid, expected, ctx: (
        _compare_proxy_outcome_at_least(
            sid, expected, ctx["proxy_outcome"], ctx["response"]
        )
    ),
    "proxy_outcome.at_most": lambda sid, expected, ctx: (
        _compare_proxy_outcome_at_most(
            sid, expected, ctx["proxy_outcome"], ctx["response"]
        )
    ),
    "findings_include": lambda sid, expected, ctx: (
        _compare_findings_include(sid, list(expected), ctx["delta"])
    ),
    "findings_min_severity": lambda sid, expected, ctx: (
        _compare_findings_min_severity(sid, expected, ctx["delta"])
    ),
}


def assert_scenario(
    scenario: Mapping[str, Any],
    *,
    response,
    delta: MetricsSnapshot,
    verdict: Mapping[str, Any] | None = None,
    judge_degraded: bool = False,
) -> list[AssertionResult]:
    """Evaluate every declared comparator in `scenario.expected`.

    Returns one [`AssertionResult`] per comparator. The caller decides
    how to aggregate (typically: any hard failure fails the test, soft
    failures are reported but tolerated). `verdict=None` is fine when
    the scenario does not assert on the judge tier.
    """
    sid = scenario.get("id") or "<unknown>"
    expected_block = scenario.get("expected") or {}
    results: list[AssertionResult] = []
    proxy_outcome = classify_proxy_outcome(response)
    ctx = {"response": response, "delta": delta, "proxy_outcome": proxy_outcome}

    for key in sorted(expected_block):
        if key in _TOP_LEVEL_COMPARATORS:
            results.append(_TOP_LEVEL_COMPARATORS[key](sid, expected_block[key], ctx))
        elif key == "judge_verdict":
            results.extend(
                _compare_judge_verdict(
                    sid,
                    expected_block[key] or {},
                    verdict,
                    judge_degraded=judge_degraded,
                )
            )
        else:
            results.append(
                AssertionResult(
                    comparator=key,
                    passed=False,
                    message=f"[{sid}] {key} is not a supported expectation key.",
                    fields={"expected": expected_block[key]},
                )
            )
    return results


def render_assertion_summary(results: list[AssertionResult]) -> str:
    """Format every result as a single multiline summary for messages.

    Includes per-row pass/soft/fail markers so the reader can scan the
    block at a glance without parsing comparator names.
    """
    if not results:
        return "  (no comparators evaluated)"
    lines: list[str] = []
    for r in results:
        if r.passed:
            marker = "ok"
        elif r.soft:
            marker = "soft"
        else:
            marker = "FAIL"
        lines.append(
            f"  [{marker}] {r.comparator}: "
            + (r.message if r.message else _summarise_fields(r.fields))
        )
    return "\n".join(lines)


def _summarise_fields(fields: dict[str, Any]) -> str:
    # On success messages are empty by design; the field map is the
    # most useful one-line summary.
    return ", ".join(f"{k}={v!r}" for k, v in sorted(fields.items()))
