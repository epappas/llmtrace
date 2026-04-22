#!/usr/bin/env python3
"""Validate attack-scenario YAML files under benchmarks/attacks/.

Walks every *.yaml file under the attacks directory, validates each against
benchmarks/attacks/schema.json, and checks that ids are unique across the
whole corpus. Prints a one-line summary per file; exits non-zero on any
failure so it can gate CI and local pre-push hooks.

Usage:
    python3 scripts/e2e/validate_scenarios.py
    python3 scripts/e2e/validate_scenarios.py --attacks-dir benchmarks/attacks
    python3 scripts/e2e/validate_scenarios.py --verbose
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import jsonschema
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ATTACKS_DIR = REPO_ROOT / "benchmarks" / "attacks"
DEFAULT_SCHEMA_PATH = DEFAULT_ATTACKS_DIR / "schema.json"


@dataclass
class FileResult:
    path: Path
    scenario_id: str | None
    errors: list[str]

    @property
    def ok(self) -> bool:
        return not self.errors


def load_schema(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_scenario(path: Path) -> tuple[dict | None, str | None]:
    try:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return None, f"yaml parse error: {e}"
    if not isinstance(data, dict):
        return None, "top-level YAML must be a mapping"
    return data, None


def validate_one(path: Path, validator: jsonschema.Draft202012Validator) -> FileResult:
    scenario, parse_error = load_scenario(path)
    if parse_error:
        return FileResult(path=path, scenario_id=None, errors=[parse_error])

    errors = [format_error(e) for e in validator.iter_errors(scenario)]
    scenario_id = scenario.get("id") if isinstance(scenario.get("id"), str) else None
    return FileResult(path=path, scenario_id=scenario_id, errors=errors)


def format_error(err: jsonschema.ValidationError) -> str:
    path = ".".join(str(p) for p in err.absolute_path) or "<root>"
    return f"{path}: {err.message}"


def detect_duplicate_ids(results: list[FileResult]) -> dict[str, list[Path]]:
    by_id: dict[str, list[Path]] = defaultdict(list)
    for r in results:
        if r.scenario_id is not None:
            by_id[r.scenario_id].append(r.path)
    return {sid: paths for sid, paths in by_id.items() if len(paths) > 1}


def discover_yaml_files(attacks_dir: Path) -> list[Path]:
    return sorted(p for p in attacks_dir.rglob("*.yaml") if p.is_file())


def display_path(path: Path) -> Path:
    try:
        return path.relative_to(REPO_ROOT)
    except ValueError:
        return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--attacks-dir",
        type=Path,
        default=DEFAULT_ATTACKS_DIR,
        help="Directory containing scenario YAML files (default: benchmarks/attacks).",
    )
    parser.add_argument(
        "--schema",
        type=Path,
        default=DEFAULT_SCHEMA_PATH,
        help="Path to schema.json (default: benchmarks/attacks/schema.json).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print the path of each scenario even on success.",
    )
    args = parser.parse_args()

    if not args.schema.exists():
        print(f"error: schema not found at {args.schema}", file=sys.stderr)
        return 2
    if not args.attacks_dir.exists():
        print(
            f"error: attacks directory not found at {args.attacks_dir}", file=sys.stderr
        )
        return 2

    schema = load_schema(args.schema)
    validator = jsonschema.Draft202012Validator(schema)

    yaml_files = discover_yaml_files(args.attacks_dir)
    if not yaml_files:
        print(f"no scenarios found under {args.attacks_dir}", file=sys.stderr)
        return 0

    results = [validate_one(p, validator) for p in yaml_files]
    duplicates = detect_duplicate_ids(results)

    failed = 0
    for r in results:
        rel = display_path(r.path)
        if r.ok:
            if args.verbose:
                print(f"ok  {rel}  id={r.scenario_id}")
        else:
            failed += 1
            print(f"FAIL {rel}")
            for err in r.errors:
                print(f"     - {err}")

    if duplicates:
        print("\nDuplicate scenario ids:")
        for sid, paths in sorted(duplicates.items()):
            print(f"  {sid}:")
            for p in paths:
                print(f"    - {display_path(p)}")

    total = len(results)
    passed = total - failed
    print(
        f"\n{passed}/{total} scenarios valid"
        + (f", {len(duplicates)} duplicate id(s)" if duplicates else "")
    )

    return 0 if failed == 0 and not duplicates else 1


if __name__ == "__main__":
    sys.exit(main())
