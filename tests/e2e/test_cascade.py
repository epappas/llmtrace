"""E2E scenario test (Loops E2E-L3 + L4 + L5 of #91).

L3 brought up the proxy lifecycle and the binary `proxy_outcome`
assertion. L4 added the metrics-delta observer so the harness can
assert the `expected.findings_include` constraint. L5 wires in the
judge-verdict collector via the `/debug/judge/verdicts` endpoint so
the harness can also assert `expected.judge_verdict.*` constraints
and surface shadow-mode + degraded-mode signals.

Loop E2E-L6 will replace the per-comparator if-blocks below with a
formalised expectation DSL.

Outcome heuristic (refined in L6's expectation DSL):

  * HTTP status >= 400 with a JSON body whose `error.type` starts with
    `proxy_` → block (the proxy itself rejected the request).
  * HTTP 200 + `x-llmtrace-flagged: true` response header → warn
    (the proxy forwarded but flagged the request).
  * Any other HTTP 200 → allow.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Final

import pytest

from tests.e2e.observer import (
    MetricsSnapshot,
    collect_finding_types,
    fetch_after_until_settled,
    judge_backend_errored,
    poll_judge_verdict,
    render_assertion_context,
)

if TYPE_CHECKING:
    from .conftest import ProxyHandle

PROXY_OUTCOME_ORDER: Final[dict[str, int]] = {"allow": 0, "warn": 1, "block": 2}
RECOMMENDED_ACTION_ORDER: Final[dict[str, int]] = {
    "allow": 0,
    "flag": 1,
    "block": 2,
}


def classify_proxy_outcome(response) -> str:
    if response.status_code >= 400:
        body = _safe_json(response)
        if isinstance(body, dict):
            err = body.get("error")
            if isinstance(err, dict) and str(err.get("type", "")).startswith(
                "proxy_"
            ):
                return "block"
    flagged = response.headers.get("x-llmtrace-flagged")
    if flagged and flagged.lower() == "true":
        return "warn"
    return "allow"


def _safe_json(response):
    try:
        return response.json()
    except ValueError:
        return None


def _expected_at_least(scenario: dict) -> str | None:
    return (scenario.get("expected") or {}).get("proxy_outcome.at_least")


def _expected_at_most(scenario: dict) -> str | None:
    return (scenario.get("expected") or {}).get("proxy_outcome.at_most")


def _expected_findings_include(scenario: dict) -> list[str]:
    raw = (scenario.get("expected") or {}).get("findings_include") or []
    return [str(item) for item in raw]


def _expected_judge_verdict(scenario: dict) -> dict | None:
    return (scenario.get("expected") or {}).get("judge_verdict")


@pytest.mark.serial
def test_scenario(proxy: "ProxyHandle", scenario: dict) -> None:
    skip = scenario.get("skip")
    if skip:
        pytest.skip(skip.get("reason") or "scenario marked skip")

    trace_id = uuid.uuid4()
    before = MetricsSnapshot.fetch(proxy.metrics_url)
    response = proxy.post_chat(prompt=scenario["prompt"], trace_id=trace_id)
    # LLMTrace records security findings in a background task that
    # outlives the synchronous response. Poll /metrics until the delta
    # settles when we expect the scenario to produce findings or a
    # judge verdict; otherwise a single immediate snapshot is enough.
    judge_expectations = _expected_judge_verdict(scenario)
    findings_required = _expected_findings_include(scenario)
    expect_metric_change = bool(findings_required) or judge_expectations is not None
    after = fetch_after_until_settled(
        proxy.metrics_url, before=before, expect_metric_change=expect_metric_change
    )
    delta = after.diff(before)

    observed = classify_proxy_outcome(response)
    observed_rank = PROXY_OUTCOME_ORDER[observed]

    at_least = _expected_at_least(scenario)
    at_most = _expected_at_most(scenario)
    sid = scenario["id"]

    failure_context = render_assertion_context(delta)
    judge_degraded = judge_backend_errored(delta)

    if at_least is not None:
        floor = PROXY_OUTCOME_ORDER[at_least]
        assert observed_rank >= floor, (
            f"[{sid}] proxy_outcome.at_least expected >= {at_least}, "
            f"observed {observed} (status={response.status_code}, "
            f"flagged={response.headers.get('x-llmtrace-flagged')!r}). "
            f"trace_id={trace_id}\n"
            f"non-zero metrics delta:\n{failure_context}"
        )

    if at_most is not None:
        ceiling = PROXY_OUTCOME_ORDER[at_most]
        assert observed_rank <= ceiling, (
            f"[{sid}] proxy_outcome.at_most expected <= {at_most}, "
            f"observed {observed} (status={response.status_code}, "
            f"flagged={response.headers.get('x-llmtrace-flagged')!r}). "
            f"trace_id={trace_id}\n"
            f"non-zero metrics delta:\n{failure_context}"
        )

    if findings_required:
        observed_finding_types = collect_finding_types(delta)
        missing = [f for f in findings_required if f not in observed_finding_types]
        assert not missing, (
            f"[{sid}] findings_include expected to observe {findings_required}, "
            f"missing {missing} (saw {sorted(observed_finding_types) or 'none'}). "
            f"trace_id={trace_id}\n"
            f"non-zero metrics delta:\n{failure_context}"
        )

    if judge_expectations is not None:
        verdict = poll_judge_verdict(proxy.base_url, trace_id)
        if verdict is None:
            if judge_degraded:
                pytest.skip(
                    f"[{sid}] judge tier reported backend_error; verdict "
                    f"assertions softened. trace_id={trace_id}"
                )
            pytest.fail(
                f"[{sid}] judge_verdict expected but no verdict was recorded "
                f"after polling. trace_id={trace_id}\n"
                f"non-zero metrics delta:\n{failure_context}"
            )
        _assert_judge_verdict(sid, judge_expectations, verdict, trace_id)


def _assert_judge_verdict(
    sid: str, expected: dict, verdict: dict, trace_id
) -> None:
    if "is_threat" in expected:
        observed = bool(verdict.get("is_threat"))
        assert observed == bool(expected["is_threat"]), (
            f"[{sid}] judge_verdict.is_threat expected {expected['is_threat']!r}, "
            f"observed {observed!r}. trace_id={trace_id}"
        )
    if "category" in expected:
        observed = verdict.get("category")
        assert observed == expected["category"], (
            f"[{sid}] judge_verdict.category expected {expected['category']!r}, "
            f"observed {observed!r}. trace_id={trace_id}"
        )
    floor = expected.get("recommended_action.at_least")
    if floor is not None:
        observed = verdict.get("recommended_action")
        assert (
            observed in RECOMMENDED_ACTION_ORDER
            and RECOMMENDED_ACTION_ORDER[observed] >= RECOMMENDED_ACTION_ORDER[floor]
        ), (
            f"[{sid}] judge_verdict.recommended_action.at_least expected >= {floor!r}, "
            f"observed {observed!r}. trace_id={trace_id}"
        )
    ceiling = expected.get("recommended_action.at_most")
    if ceiling is not None:
        observed = verdict.get("recommended_action")
        assert (
            observed in RECOMMENDED_ACTION_ORDER
            and RECOMMENDED_ACTION_ORDER[observed] <= RECOMMENDED_ACTION_ORDER[ceiling]
        ), (
            f"[{sid}] judge_verdict.recommended_action.at_most expected <= {ceiling!r}, "
            f"observed {observed!r}. trace_id={trace_id}"
        )
