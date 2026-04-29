"""Determinism contract for `scripts/e2e/calibrate_upstream_judge.py`.

The nightly auto-PR pattern (peter-evans/create-pull-request with
`add-paths: docs/research/results/upstream_judge_calibration_*.md`)
no-ops on byte-identical content. That only works if the markdown
renderer is byte-stable when verdicts are identical day-over-day —
the same contract `e2e_<date>.md` honours.

These tests exercise the renderer with hand-crafted Row instances so
they run offline (no LLM, no network, no API key needed) and pin the
deterministic surface against accidental drift.

Specifically asserted:
  1. Same rows + same date → byte-identical markdown.
  2. The markdown contains zero free-text fields from the LLM verdict
     (no `reason` strings, no exact `rule` wording outside the
     stable-tally section).
  3. Cost is rounded to nearest cent in markdown but exact in the JSON
     sidecar.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# The script lives under scripts/e2e/ — load it as a module so we can
# reach `_render_markdown`, `_render_sidecar_json`, and `Row` directly.
_SCRIPT_PATH = REPO_ROOT / "scripts" / "e2e" / "calibrate_upstream_judge.py"
_spec = importlib.util.spec_from_file_location(
    "calibrate_upstream_judge", _SCRIPT_PATH
)
assert _spec is not None and _spec.loader is not None
_calibrate = importlib.util.module_from_spec(_spec)
sys.modules["calibrate_upstream_judge"] = _calibrate
_spec.loader.exec_module(_calibrate)

from tests.e2e.upstream_judge import UpstreamJudgement  # noqa: E402


def _row(
    *,
    case_id: str,
    family: str,
    expected: bool,
    regex_fell: bool | None,
    regex_rule: str | None,
    regex_reason: str,
    llm_fell: bool | None,
    llm_rule: str | None,
    llm_reason: str,
) -> "_calibrate.Row":
    case = _calibrate.CalibrationCase(
        id=case_id,
        family=family,
        expected=expected,
        scenario={"prompt": f"prompt for {case_id}"},
        response=f"response for {case_id}",
    )
    regex = UpstreamJudgement(
        fell_for_it=regex_fell,
        rule=regex_rule,
        reason=regex_reason,
        fields={},
    )
    llm = UpstreamJudgement(
        fell_for_it=llm_fell,
        rule=llm_rule,
        reason=llm_reason,
        fields={},
    )
    return _calibrate.Row(case=case, regex=regex, llm=llm)


@pytest.fixture
def two_rows() -> list:
    return [
        _row(
            case_id="case-a",
            family="jailbreak",
            expected=True,
            regex_fell=True,
            regex_rule="dan_marker",
            regex_reason="matched DAN prefix",
            llm_fell=True,
            llm_rule="dan_persona",
            llm_reason="LLM saw DAN compliance",
        ),
        _row(
            case_id="case-b",
            family="indirect_injection",
            expected=True,
            regex_fell=False,
            regex_rule=None,
            regex_reason="no rule matched",
            llm_fell=True,
            llm_rule="data_exfiltration",
            llm_reason="model exfiltrated PII",
        ),
    ]


# ---------------------------------------------------------------------------
# Determinism contract — the load-bearing test
# ---------------------------------------------------------------------------


def test_markdown_is_byte_identical_when_rendered_twice(two_rows):
    md1 = _calibrate._render_markdown(
        two_rows,
        model="kimi-k2.6",
        backend="openai",
        cost_used_usd=0.019162,
        calls_made=12,
        sidecar_filename="upstream_judge_calibration_2026-04-29.json",
    )
    md2 = _calibrate._render_markdown(
        two_rows,
        model="kimi-k2.6",
        backend="openai",
        cost_used_usd=0.019162,
        calls_made=12,
        sidecar_filename="upstream_judge_calibration_2026-04-29.json",
    )
    assert md1 == md2, (
        "renderer is non-deterministic; the auto-PR will produce daily "
        "noise even when verdicts are unchanged."
    )


def test_markdown_byte_stable_under_cost_jitter_within_one_cent(two_rows):
    """Cost variance below 1c must NOT change the markdown.

    Token counts vary day-over-day even when verdicts are identical
    (the LLM may phrase a same-meaning `reason` differently within
    the 100-char cap). Rounding to nearest cent absorbs that jitter.
    """
    md_low = _calibrate._render_markdown(
        two_rows,
        model="kimi-k2.6",
        backend="openai",
        cost_used_usd=0.019100,
        calls_made=12,
        sidecar_filename="x.json",
    )
    md_high = _calibrate._render_markdown(
        two_rows,
        model="kimi-k2.6",
        backend="openai",
        cost_used_usd=0.021400,
        calls_made=12,
        sidecar_filename="x.json",
    )
    assert md_low == md_high, (
        "rounding window must absorb sub-cent cost jitter; saw a diff "
        "between $0.0191 and $0.0214 (both round to $0.02)."
    )


def test_markdown_changes_when_a_verdict_flips(two_rows):
    """Sanity guard against over-rounding: real verdict changes MUST diff."""
    md_before = _calibrate._render_markdown(
        two_rows,
        model="kimi-k2.6",
        backend="openai",
        cost_used_usd=0.019162,
        calls_made=12,
        sidecar_filename="x.json",
    )
    flipped = list(two_rows)
    flipped[1] = _row(
        case_id="case-b",
        family="indirect_injection",
        expected=True,
        regex_fell=False,
        regex_rule=None,
        regex_reason="no rule matched",
        llm_fell=False,  # flipped
        llm_rule="insufficient_signal",  # flipped
        llm_reason="model gave nothing concrete",
    )
    md_after = _calibrate._render_markdown(
        flipped,
        model="kimi-k2.6",
        backend="openai",
        cost_used_usd=0.019162,
        calls_made=12,
        sidecar_filename="x.json",
    )
    assert md_before != md_after, (
        "renderer is over-rounding; a verdict flip MUST surface in "
        "the diff or the regression bed is useless."
    )


# ---------------------------------------------------------------------------
# Free-text exclusion
# ---------------------------------------------------------------------------


def test_markdown_excludes_llm_reason_strings(two_rows):
    md = _calibrate._render_markdown(
        two_rows,
        model="kimi-k2.6",
        backend="openai",
        cost_used_usd=0.019162,
        calls_made=12,
        sidecar_filename="x.json",
    )
    # The free-text reasons in our fixture are uniquely identifiable.
    for reason in (
        "matched DAN prefix",
        "LLM saw DAN compliance",
        "no rule matched",
        "model exfiltrated PII",
    ):
        assert reason not in md, (
            f"markdown contains free-text reason {reason!r}; this string "
            "should live in the sidecar JSON only."
        )


def test_markdown_excludes_attack_prompt_and_response_bodies(two_rows):
    md = _calibrate._render_markdown(
        two_rows,
        model="kimi-k2.6",
        backend="openai",
        cost_used_usd=0.019162,
        calls_made=12,
        sidecar_filename="x.json",
    )
    # The case fixture sets these to deterministic but still
    # non-stable-against-corpus-edit strings — we keep them out of the
    # markdown to bound the diff to corpus list changes only.
    assert "prompt for case-a" not in md
    assert "response for case-a" not in md


# ---------------------------------------------------------------------------
# Sidecar contract
# ---------------------------------------------------------------------------


def test_sidecar_contains_full_free_text(two_rows):
    sidecar = _calibrate._render_sidecar_json(
        two_rows,
        model="kimi-k2.6",
        backend="openai",
        cost_used_usd=0.019162,
        calls_made=12,
    )
    payload = json.loads(sidecar)
    assert payload["model"] == "kimi-k2.6"
    assert payload["backend"] == "openai"
    assert payload["calls_made"] == 12
    assert payload["cost_used_usd"] == 0.019162
    assert len(payload["rows"]) == 2
    row0 = payload["rows"][0]
    assert row0["llm"]["reason"] == "LLM saw DAN compliance"
    assert row0["regex"]["reason"] == "matched DAN prefix"


def test_sidecar_is_stable_keyed(two_rows):
    """Sorted-keys JSON output is byte-stable across renders."""
    s1 = _calibrate._render_sidecar_json(
        two_rows,
        model="kimi-k2.6",
        backend="openai",
        cost_used_usd=0.019162,
        calls_made=12,
    )
    s2 = _calibrate._render_sidecar_json(
        two_rows,
        model="kimi-k2.6",
        backend="openai",
        cost_used_usd=0.019162,
        calls_made=12,
    )
    assert s1 == s2


# ---------------------------------------------------------------------------
# Rule tally — sort order
# ---------------------------------------------------------------------------


def test_rule_tally_sorts_by_count_desc_then_label_asc():
    rows = [
        _row(
            case_id=f"case-{i}",
            family="jailbreak",
            expected=True,
            regex_fell=False,
            regex_rule=None,
            regex_reason="r",
            llm_fell=True,
            llm_rule=label,
            llm_reason="r",
        )
        for i, label in enumerate(
            [
                "benign_response",
                "benign_response",
                "benign_response",
                "refusal",
                "refusal",
                "deflection",
            ]
        )
    ]
    tally = _calibrate._rule_tally(rows, lambda r: r.llm)
    assert tally == [
        ("benign_response", 3),
        ("refusal", 2),
        ("deflection", 1),
    ]


def test_rule_tally_breaks_ties_by_label_alphabetical():
    rows = [
        _row(
            case_id=f"case-{i}",
            family="jailbreak",
            expected=True,
            regex_fell=False,
            regex_rule=None,
            regex_reason="r",
            llm_fell=True,
            llm_rule=label,
            llm_reason="r",
        )
        for i, label in enumerate(["zebra", "apple", "mango"])
    ]
    tally = _calibrate._rule_tally(rows, lambda r: r.llm)
    # All counts == 1; ascending label order.
    assert tally == [("apple", 1), ("mango", 1), ("zebra", 1)]
