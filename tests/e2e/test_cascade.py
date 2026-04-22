"""E2E scenario test (Loops E2E-L3 + L4 of #91).

Loop E2E-L3 added the proxy lifecycle + the binary `proxy_outcome`
assertion. Loop E2E-L4 wires in the metrics-delta observer so the
harness can also assert the `expected.findings_include` constraint
from the scenario YAML — by snapshotting `/metrics` before and after
each scenario fires and reading per-scenario counter deltas.

Loops E2E-L5 / L6 will add judge-verdict assertions and the full
expectation DSL on top of these primitives.

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
    render_assertion_context,
)

if TYPE_CHECKING:
    from .conftest import ProxyHandle

PROXY_OUTCOME_ORDER: Final[dict[str, int]] = {"allow": 0, "warn": 1, "block": 2}


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
    # settles when we expect the scenario to produce findings;
    # otherwise a single immediate snapshot is sufficient.
    expect_metric_change = bool(_expected_findings_include(scenario))
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

    findings_required = _expected_findings_include(scenario)
    if findings_required:
        observed_finding_types = collect_finding_types(delta)
        missing = [f for f in findings_required if f not in observed_finding_types]
        assert not missing, (
            f"[{sid}] findings_include expected to observe {findings_required}, "
            f"missing {missing} (saw {sorted(observed_finding_types) or 'none'}). "
            f"trace_id={trace_id}\n"
            f"non-zero metrics delta:\n{failure_context}"
        )
