#!/usr/bin/env python3
"""Migrate the monolithic judge_golden_set.jsonl into per-id JSON files.

The original layout — one large JSONL bundling 20+ verbatim attack
prompts — is hostile to incremental editing: every change forces an
agent to handle the full file, which concentrates harmful-pattern
text in single tool calls. Per-id files (one prompt per file) match
the layout we already use for the L7 attack corpus and let edits
flow one-prompt-at-a-time.

This script is the salvage path. Run once to convert the existing
JSONL; future additions go straight to the per-id directory.

Inputs:
  crates/llmtrace-security/fixtures/judge_golden_set.jsonl

Outputs:
  crates/llmtrace-security/fixtures/judge_golden_set/<category>/<id>.json
  (one JSON object per file, sorted keys, 2-space indent, trailing newline)

Behaviour:
  * Idempotent — re-running on the same input produces byte-identical
    output. Diff-stable across days.
  * Skip-on-malformed — JSONL lines that fail to parse are reported
    by line number with the parser error truncated; the script does
    NOT echo the offending line text (it may contain partially-
    formed harmful patterns).
  * Required schema per entry: {id, category, is_threat, text, rationale}.
    Missing fields fail loudly with the offending entry id.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = REPO_ROOT / "crates/llmtrace-security/fixtures/judge_golden_set.jsonl"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "crates/llmtrace-security/fixtures/judge_golden_set"

REQUIRED_FIELDS = ("id", "category", "is_threat", "text", "rationale")
ALLOWED_CATEGORIES = {
    "prompt_injection",
    "jailbreak",
    "role_injection",
    "data_exfiltration",
    "prompt_extraction",
    "encoding_evasion",
    "indirect_injection",
    "policy_violation",
    "over_defense",
    "tool_manipulation",
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
        help=f"JSONL to migrate (default: {DEFAULT_INPUT})",
    )
    p.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Per-id output root (default: {DEFAULT_OUTPUT_DIR})",
    )
    p.add_argument(
        "--delete-input-on-success",
        action="store_true",
        help="Remove the source JSONL after a fully successful migration.",
    )
    return p.parse_args()


def load_entries(path: Path) -> tuple[list[dict[str, Any]], list[tuple[int, str]]]:
    """Return (parsed_entries, malformed_lines) without echoing line text."""
    entries: list[dict[str, Any]] = []
    malformed: list[tuple[int, str]] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            entries.append(json.loads(raw))
        except json.JSONDecodeError as e:
            malformed.append((lineno, str(e)[:80]))
    return entries, malformed


def validate_entry(entry: dict[str, Any]) -> str | None:
    """Return error string if invalid, else None."""
    missing = [f for f in REQUIRED_FIELDS if f not in entry]
    if missing:
        return f"missing fields: {missing}"
    cat = entry["category"]
    if cat not in ALLOWED_CATEGORIES:
        return f"category {cat!r} not in {sorted(ALLOWED_CATEGORIES)}"
    if not isinstance(entry["is_threat"], bool):
        return f"is_threat must be bool, got {type(entry['is_threat']).__name__}"
    sid = entry["id"]
    if not isinstance(sid, str) or not sid:
        return "id must be non-empty string"
    return None


def write_entry(out_root: Path, entry: dict[str, Any]) -> Path:
    """Write one entry to <out_root>/<category>/<id>.json."""
    category = entry["category"]
    sid = entry["id"]
    target = out_root / category / f"{sid}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(entry, sort_keys=True, indent=2, ensure_ascii=False)
    target.write_text(payload + "\n", encoding="utf-8")
    return target


def main() -> int:
    args = parse_args()
    if not args.input.exists():
        print(f"error: input not found: {args.input}", file=sys.stderr)
        return 1

    entries, malformed = load_entries(args.input)
    if malformed:
        print(
            f"warning: {len(malformed)} malformed line(s) skipped:",
            file=sys.stderr,
        )
        for lineno, err in malformed:
            print(f"  line {lineno}: {err}", file=sys.stderr)

    invalid: list[tuple[str, str]] = []
    for entry in entries:
        err = validate_entry(entry)
        if err is not None:
            invalid.append((entry.get("id") or "<no-id>", err))
    if invalid:
        for sid, err in invalid:
            print(f"error: entry {sid}: {err}", file=sys.stderr)
        return 2

    seen_ids: set[str] = set()
    for entry in entries:
        sid = entry["id"]
        if sid in seen_ids:
            print(f"error: duplicate id {sid!r}", file=sys.stderr)
            return 3
        seen_ids.add(sid)

    written: list[Path] = []
    for entry in entries:
        written.append(write_entry(args.output_dir, entry))

    print(f"migrated {len(written)} entries → {args.output_dir.relative_to(REPO_ROOT)}")
    by_category: dict[str, int] = {}
    for entry in entries:
        by_category[entry["category"]] = by_category.get(entry["category"], 0) + 1
    for cat in sorted(by_category):
        print(f"  {cat}: {by_category[cat]}")

    if args.delete_input_on_success and not malformed:
        args.input.unlink()
        print(f"deleted source: {args.input.relative_to(REPO_ROOT)}")
    elif args.delete_input_on_success and malformed:
        print(
            f"keeping source (had {len(malformed)} malformed lines)",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
