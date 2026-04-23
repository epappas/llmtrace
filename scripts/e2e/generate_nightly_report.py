#!/usr/bin/env python3
"""Nightly e2e report generator (Loop E2E-L10 of #91).

Reads the per-scenario JSON sidecar produced by `tests/e2e/conftest.py`
(`--scenario-results-json`) and produces a deterministic Markdown
report under `docs/research/results/e2e_YYYY-MM-DD.md`.

The diff section ("Regressions vs previous") compares the current
sidecar against the most recent prior report's sidecar (looked up by
filename ordering on disk). The diff section is the primary value of
this report — the rest is mostly context.

Output is deterministic (sorted ids, frozen decimal precision, no
wall-clock timestamps in the diff-comparable section) so two runs on
the same data produce byte-identical files. The auto-PR step relies
on this to short-circuit "noop" runs.

Usage:
    python3 scripts/e2e/generate_nightly_report.py \\
        --results-json out/scenario-results.json \\
        --report-dir docs/research/results/ \\
        --date 2026-04-23
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def load_results(path: Path) -> dict[str, dict]:
    """Return scenarios keyed by id from a `--scenario-results-json` payload."""
    if not path.exists():
        raise FileNotFoundError(f"results JSON not found: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or "scenarios" not in payload:
        raise ValueError(
            f"{path}: malformed sidecar; expected top-level key 'scenarios'"
        )
    out: dict[str, dict] = {}
    for row in payload["scenarios"]:
        if not isinstance(row, dict) or "id" not in row:
            continue
        out[row["id"]] = row
    return out


def find_previous_report(report_dir: Path, current_date: str) -> Path | None:
    """Return the most recent prior report's sidecar, if any.

    Reports are named `e2e_YYYY-MM-DD.md`; sidecars sit beside them as
    `e2e_YYYY-MM-DD.json`. Finding the previous run is purely
    filename-based — no timestamps inside the file are inspected.
    """
    candidates = sorted(report_dir.glob("e2e_*.json"))
    candidates = [
        p for p in candidates
        if p.stem != f"e2e_{current_date}"
    ]
    return candidates[-1] if candidates else None


# ---------------------------------------------------------------------------
# Roll-ups
# ---------------------------------------------------------------------------


def summary_counts(results: Mapping[str, dict]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for row in results.values():
        counts[row.get("outcome", "unknown")] += 1
    counts["total"] = len(results)
    return dict(counts)


def fails_by_family(results: Mapping[str, dict]) -> dict[str, list[str]]:
    """Map family → sorted list of failing scenario ids."""
    out: dict[str, list[str]] = defaultdict(list)
    for sid, row in results.items():
        if row.get("outcome") in ("failed", "error"):
            family = row.get("family") or "<unknown>"
            out[family].append(sid)
    return {family: sorted(ids) for family, ids in sorted(out.items())}


def upstream_fell_for_it_rate(results: Mapping[str, dict]) -> dict[str, dict]:
    """Per-family aggregation of upstream judge outcomes.

    Returns family → {observed: int, fell_for_it: int, rate: str}. The
    rate is rendered as a fixed-precision string ("12.5%") so the diff
    output stays byte-stable across runs.
    """
    by_family: dict[str, dict[str, int]] = defaultdict(
        lambda: {"observed": 0, "fell_for_it": 0}
    )
    for row in results.values():
        family = row.get("family") or "<unknown>"
        upstream = row.get("upstream_judgement")
        if not isinstance(upstream, Mapping):
            continue
        if upstream.get("fell_for_it") is None:
            continue
        by_family[family]["observed"] += 1
        if upstream.get("fell_for_it") is True:
            by_family[family]["fell_for_it"] += 1
    out: dict[str, dict] = {}
    for family, counts in sorted(by_family.items()):
        observed = counts["observed"]
        fell = counts["fell_for_it"]
        rate = f"{(100.0 * fell / observed):.1f}%" if observed else "n/a"
        out[family] = {"observed": observed, "fell_for_it": fell, "rate": rate}
    return out


def diff_outcomes(
    current: Mapping[str, dict], previous: Mapping[str, dict] | None
) -> dict[str, list[dict]]:
    """Diff scenario outcomes vs previous run.

    Returns three sorted lists:
      * regressions  — passed → failed/error
      * recoveries   — failed/error → passed
      * new          — present today, absent yesterday
      * removed      — present yesterday, absent today
    """
    out = {"regressions": [], "recoveries": [], "new": [], "removed": []}
    if previous is None:
        out["new"] = [
            {"id": sid, "outcome": row.get("outcome")}
            for sid, row in sorted(current.items())
        ]
        return out
    fail_states = {"failed", "error"}
    for sid in sorted(current):
        cur = current[sid]
        prev = previous.get(sid)
        if prev is None:
            out["new"].append({"id": sid, "outcome": cur.get("outcome")})
            continue
        cur_fail = cur.get("outcome") in fail_states
        prev_fail = prev.get("outcome") in fail_states
        if cur_fail and not prev_fail:
            out["regressions"].append(
                {
                    "id": sid,
                    "from": prev.get("outcome"),
                    "to": cur.get("outcome"),
                }
            )
        elif prev_fail and not cur_fail:
            out["recoveries"].append(
                {
                    "id": sid,
                    "from": prev.get("outcome"),
                    "to": cur.get("outcome"),
                }
            )
    for sid in sorted(set(previous) - set(current)):
        out["removed"].append(
            {"id": sid, "outcome": previous[sid].get("outcome")}
        )
    return out


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


def render_report(
    *,
    date: str,
    results: Mapping[str, dict],
    previous_path: Path | None,
    diff: Mapping[str, list[dict]],
) -> str:
    summary = summary_counts(results)
    fails = fails_by_family(results)
    upstream = upstream_fell_for_it_rate(results)

    lines: list[str] = []
    lines.append(f"# E2E nightly report — {date}")
    lines.append("")
    lines.append(
        "Auto-generated by `scripts/e2e/generate_nightly_report.py`. "
        "The diff section is the primary value; per-run roll-ups are "
        "context."
    )
    lines.append("")

    # Summary
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("|---|---|")
    for key in ("total", "passed", "failed", "error", "skipped"):
        lines.append(f"| {key} | {summary.get(key, 0)} |")
    lines.append("")

    # Regressions
    lines.append("## Regressions vs previous")
    lines.append("")
    if previous_path is None:
        lines.append("_No previous run; this is the baseline._")
    else:
        lines.append(f"_Compared against `{previous_path.name}`._")
    lines.append("")
    _render_diff_section(lines, "Regressions", diff["regressions"])
    _render_diff_section(lines, "Recoveries", diff["recoveries"])
    _render_diff_section(lines, "New scenarios", diff["new"])
    _render_diff_section(lines, "Removed scenarios", diff["removed"])

    # Fails by family
    lines.append("## Fails by family")
    lines.append("")
    if not fails:
        lines.append("_No failures._")
    else:
        for family, ids in fails.items():
            lines.append(f"### `{family}` ({len(ids)})")
            lines.append("")
            for sid in ids:
                lines.append(f"- `{sid}`")
            lines.append("")

    # Upstream-fell-for-it
    lines.append("## Upstream-fell-for-it rate by family")
    lines.append("")
    if not upstream:
        lines.append(
            "_No upstream judgements observed (judge skipped every "
            "scenario, e.g. proxy blocked on every request)._"
        )
    else:
        lines.append("| Family | Observed | Fell for it | Rate |")
        lines.append("|---|---|---|---|")
        for family, row in upstream.items():
            lines.append(
                f"| `{family}` | {row['observed']} | "
                f"{row['fell_for_it']} | {row['rate']} |"
            )
    lines.append("")

    return "\n".join(lines) + "\n"


def _render_diff_section(lines: list[str], title: str, rows: list[dict]) -> None:
    lines.append(f"### {title} ({len(rows)})")
    lines.append("")
    if not rows:
        lines.append("_None._")
        lines.append("")
        return
    if title in ("Regressions", "Recoveries"):
        lines.append("| Scenario | From | To |")
        lines.append("|---|---|---|")
        for row in rows:
            lines.append(
                f"| `{row['id']}` | {row.get('from')} | {row.get('to')} |"
            )
    else:
        lines.append("| Scenario | Outcome |")
        lines.append("|---|---|")
        for row in rows:
            lines.append(f"| `{row['id']}` | {row.get('outcome')} |")
    lines.append("")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--results-json",
        required=True,
        type=Path,
        help="Path to the per-scenario JSON sidecar.",
    )
    parser.add_argument(
        "--report-dir",
        required=True,
        type=Path,
        help="Directory to write `e2e_<date>.md` and `e2e_<date>.json` into.",
    )
    parser.add_argument(
        "--date",
        default=dt.date.today().isoformat(),
        help="ISO date for the report filename (default: today UTC).",
    )
    args = parser.parse_args()

    args.report_dir.mkdir(parents=True, exist_ok=True)
    current = load_results(args.results_json)

    previous_path = find_previous_report(args.report_dir, args.date)
    previous = load_results(previous_path) if previous_path else None

    diff = diff_outcomes(current, previous)
    report_md = render_report(
        date=args.date,
        results=current,
        previous_path=previous_path,
        diff=diff,
    )

    out_md = args.report_dir / f"e2e_{args.date}.md"
    out_json = args.report_dir / f"e2e_{args.date}.json"
    out_md.write_text(report_md, encoding="utf-8")
    # Mirror the sidecar next to the report so tomorrow's diff has
    # something to compare against.
    out_json.write_text(args.results_json.read_text(encoding="utf-8"), encoding="utf-8")

    print(f"wrote {out_md}")
    print(f"wrote {out_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
