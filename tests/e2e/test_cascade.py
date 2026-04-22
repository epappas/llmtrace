"""First-cut e2e scenario test (Loop E2E-L3 of #91).

Asserts only the proxy outcome — the metrics-delta and judge-verdict
checks live in Loops E2E-L4 / L5 / L6. This file's job is to prove the
harness boots, fires every scenario in the corpus, and reads back a
single binary signal (allow / warn / block) with enough fidelity to
catch a regression in the proxy decision path.

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


def test_scenario(proxy: "ProxyHandle", scenario: dict) -> None:
    skip = scenario.get("skip")
    if skip:
        pytest.skip(skip.get("reason") or "scenario marked skip")

    trace_id = uuid.uuid4()
    response = proxy.post_chat(prompt=scenario["prompt"], trace_id=trace_id)
    observed = classify_proxy_outcome(response)
    observed_rank = PROXY_OUTCOME_ORDER[observed]

    at_least = _expected_at_least(scenario)
    at_most = _expected_at_most(scenario)
    sid = scenario["id"]

    if at_least is not None:
        floor = PROXY_OUTCOME_ORDER[at_least]
        assert observed_rank >= floor, (
            f"[{sid}] proxy_outcome.at_least expected >= {at_least}, "
            f"observed {observed} (status={response.status_code}, "
            f"flagged={response.headers.get('x-llmtrace-flagged')!r}). "
            f"trace_id={trace_id}"
        )

    if at_most is not None:
        ceiling = PROXY_OUTCOME_ORDER[at_most]
        assert observed_rank <= ceiling, (
            f"[{sid}] proxy_outcome.at_most expected <= {at_most}, "
            f"observed {observed} (status={response.status_code}, "
            f"flagged={response.headers.get('x-llmtrace-flagged')!r}). "
            f"trace_id={trace_id}"
        )
