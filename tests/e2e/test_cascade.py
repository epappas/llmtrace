"""E2E scenario test (Loops E2E-L3 + L4 + L5 + L6 of #91).

L3 brought up the proxy lifecycle. L4 added the metrics-delta observer.
L5 added the judge-verdict collector + degraded-mode handling. L6
formalised the per-comparator if-blocks here into a DSL — this file
is now thin: it owns I/O (HTTP request, /metrics scrape, verdict poll)
and hands the observed data to `expect.assert_scenario(...)` which
returns one [`AssertionResult`] per declared comparator.

Hard failures fail the test with the full assertion summary attached.
Soft failures (degraded mode — judge tier reported `backend_error`)
are reported but do not red the run; they convert to `pytest.skip`
on a per-scenario basis.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

import pytest

from tests.e2e.expect import (
    AssertionResult,
    assert_scenario,
    render_assertion_summary,
)
from tests.e2e.observer import (
    MetricsSnapshot,
    fetch_after_until_settled,
    judge_backend_errored,
    poll_judge_verdict,
    render_assertion_context,
)
from tests.e2e.upstream_judge import UpstreamJudgement, select_judge

if TYPE_CHECKING:
    from .conftest import ProxyHandle


_UPSTREAM_JUDGE = select_judge()


@pytest.mark.serial
def test_scenario(proxy: "ProxyHandle", scenario: dict) -> None:
    skip = scenario.get("skip")
    if skip:
        pytest.skip(skip.get("reason") or "scenario marked skip")

    trace_id = uuid.uuid4()
    sid = scenario.get("id") or "<unknown>"
    expected = scenario.get("expected") or {}

    before = MetricsSnapshot.fetch(proxy.metrics_url)
    response = proxy.post_chat(prompt=scenario["prompt"], trace_id=trace_id)

    expect_metric_change = bool(
        expected.get("findings_include")
        or expected.get("findings_min_severity")
        or expected.get("judge_verdict")
    )
    after = fetch_after_until_settled(
        proxy.metrics_url, before=before, expect_metric_change=expect_metric_change
    )
    delta = after.diff(before)
    judge_degraded = judge_backend_errored(delta)

    verdict = (
        poll_judge_verdict(proxy.base_url, trace_id)
        if expected.get("judge_verdict") is not None
        else None
    )

    upstream_judgement = _judge_upstream(scenario, response)

    results = assert_scenario(
        scenario,
        response=response,
        delta=delta,
        verdict=verdict,
        judge_degraded=judge_degraded,
        upstream_judgement=upstream_judgement,
    )

    _evaluate(
        results,
        sid=sid,
        trace_id=trace_id,
        response=response,
        delta=delta,
        upstream_judgement=upstream_judgement,
    )


def _judge_upstream(scenario: dict, response) -> UpstreamJudgement:
    """Run the upstream judge over the response body.

    Always runs (observational signal). The judge itself skips when the
    response is a 4xx LLMTrace-error envelope so we never feed
    LLMTrace's own output into the rule classes.
    """
    response_text = _safe_response_text(response)
    return _UPSTREAM_JUDGE.judge(
        scenario=scenario,
        response_status=response.status_code,
        response_text=response_text,
    )


def _safe_response_text(response) -> str:
    """Best-effort extraction of the upstream-visible text content.

    Tries OpenAI chat-completions shape first; falls back to the raw
    body text. Never raises — a malformed body just yields an empty
    string and the judge marks the scenario as "no rule matched".
    """
    try:
        body = response.json()
    except ValueError:
        try:
            return response.text or ""
        except Exception:
            return ""
    if isinstance(body, dict):
        choices = body.get("choices")
        if isinstance(choices, list) and choices:
            first = choices[0]
            if isinstance(first, dict):
                message = first.get("message")
                if isinstance(message, dict):
                    content = message.get("content")
                    if isinstance(content, str):
                        return content
                text = first.get("text")
                if isinstance(text, str):
                    return text
    try:
        return response.text or ""
    except Exception:
        return ""


def _evaluate(
    results: list[AssertionResult],
    *,
    sid: str,
    trace_id: uuid.UUID,
    response,
    delta: MetricsSnapshot,
    upstream_judgement: UpstreamJudgement | None = None,
) -> None:
    """Aggregate the comparator rows into a pytest verdict.

    Soft-only failures (degraded mode) → `pytest.skip` so the suite stays
    green when the judge tier flakes for upstream-of-LLMTrace reasons.
    Hard failures → `pytest.fail` with the full assertion summary plus
    the metrics-delta context attached.
    """
    hard_failures = [r for r in results if not r.passed and not r.soft]
    soft_failures = [r for r in results if not r.passed and r.soft]

    summary = render_assertion_summary(results)
    metrics_context = render_assertion_context(delta)
    upstream_line = _format_upstream_judgement(upstream_judgement)

    if hard_failures:
        pytest.fail(
            "\n".join(
                [
                    f"[{sid}] {len(hard_failures)} comparator(s) failed "
                    f"(trace_id={trace_id}, status={response.status_code}).",
                    "assertions:",
                    summary,
                    "non-zero metrics delta:",
                    metrics_context,
                    "upstream judgement:",
                    upstream_line,
                ]
            )
        )

    if soft_failures and not [r for r in results if r.passed]:
        pytest.skip(
            f"[{sid}] all {len(soft_failures)} comparator(s) soft-failed "
            f"(degraded judge tier; trace_id={trace_id})"
        )


def _format_upstream_judgement(j: UpstreamJudgement | None) -> str:
    if j is None:
        return "  (judge not invoked)"
    return f"  fell_for_it={j.fell_for_it} rule={j.rule!r} reason={j.reason!r}"
