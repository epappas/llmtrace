#!/usr/bin/env python3
"""Export benchmark datasets, stress test results, and DB traces as flat JSONL files.

Outputs:
  results/corpus_samples.jsonl    -- every raw dataset sample (prompt, label, metadata)
  results/eval_results.jsonl      -- stress test results (classification, scores, findings)
  results/traces_spans.jsonl      -- all spans from ClickHouse (flat, one row per span)
  results/traces_findings.jsonl   -- all security findings (flat, one row per finding)
"""

import json
import urllib.request
from pathlib import Path
from typing import Any

DATASETS_DIR = Path(__file__).parent.parent / "datasets"
RESULTS_DIR = Path(__file__).parent.parent / "results"


def load_all_datasets() -> list[dict[str, Any]]:
    """Load every JSON dataset file from core and external dirs."""
    samples: list[dict[str, Any]] = []
    for path in sorted(DATASETS_DIR.glob("*.json")):
        data = json.loads(path.read_text())
        for s in data:
            s["_dataset_file"] = path.name
        samples.extend(data)

    ext = DATASETS_DIR / "external"
    if ext.is_dir():
        for path in sorted(ext.glob("*.json")):
            data = json.loads(path.read_text())
            for s in data:
                s["_dataset_file"] = f"external/{path.name}"
            samples.extend(data)
    return samples



def build_text_index(corpus: list[dict[str, Any]]) -> dict[str, str]:
    """Build id -> full text lookup from corpus samples."""
    return {s["id"]: s.get("text", "") for s in corpus if "id" in s}


def export_eval_results(
    results_file: Path,
    output: Path,
    text_index: dict[str, str],
) -> int:
    """Export stress test results as flat JSONL.

    Each line has the full prompt text, ground truth, and our classification output.
    Skips results where all samples have zero findings (failed runs).
    """
    if not results_file.exists():
        return 0

    data = json.loads(results_file.read_text())
    samples = data.get("samples", [])
    run_time = data.get("run_time", "")

    has_any_findings = any(s.get("num_findings", 0) > 0 for s in samples)
    if not has_any_findings:
        return -1

    with open(output, "w") as f:
        for s in samples:
            sid = s.get("id", "")
            full_text = text_index.get(sid, s.get("text_preview", ""))
            row = {
                "id": sid,
                "text": full_text,
                "label": s.get("label", ""),
                "category": s.get("category", ""),
                "subcategory": s.get("subcategory", ""),
                "text_len": s.get("text_len", 0),
                "http_status": s.get("http_status", 0),
                "latency_ms": s.get("latency_ms", 0),
                "security_score": s.get("security_score", 0),
                "num_findings": s.get("num_findings", 0),
                "finding_types": s.get("finding_types", []),
                "voting_results": s.get("voting_results", []),
                "ml_score": s.get("ml_score"),
                "ml_label": s.get("ml_label", ""),
                "classification": s.get("classification", ""),
                "run_time": run_time,
            }
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    return len(samples)


CLICKHOUSE_URL = "http://localhost:8123/"

SPANS_QUERY = """
SELECT *
FROM llmtrace.spans
ORDER BY start_time
FORMAT JSONEachRow
"""


def ch_query(query: str) -> list[dict[str, Any]]:
    """Execute a ClickHouse query and return rows as dicts."""
    req = urllib.request.Request(CLICKHOUSE_URL, data=query.encode())
    resp = urllib.request.urlopen(req, timeout=120)
    rows: list[dict[str, Any]] = []
    for line in resp:
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def flatten_span(row: dict[str, Any]) -> dict[str, Any]:
    """Flatten a ClickHouse span row into a flat dict."""
    findings_raw = row.get("security_findings", "[]")
    findings = json.loads(findings_raw) if isinstance(findings_raw, str) else findings_raw
    tags_raw = row.get("tags", "{}")
    tags = json.loads(tags_raw) if isinstance(tags_raw, str) else tags_raw

    return {
        "span_id": row.get("span_id", ""),
        "trace_id": row.get("trace_id", ""),
        "tenant_id": row.get("tenant_id", ""),
        "operation_name": row.get("operation_name", ""),
        "start_time": row.get("start_time", ""),
        "end_time": row.get("end_time"),
        "duration_ms": row.get("duration_ms"),
        "provider": row.get("provider", "").strip('"'),
        "model_name": row.get("model_name", ""),
        "prompt": row.get("prompt", ""),
        "response": row.get("response", ""),
        "prompt_tokens": row.get("prompt_tokens"),
        "completion_tokens": row.get("completion_tokens"),
        "total_tokens": row.get("total_tokens"),
        "status_code": row.get("status_code"),
        "security_score": row.get("security_score"),
        "num_findings": len(findings),
        "finding_types": [f.get("finding_type", "") for f in findings],
        "tags": tags,
    }


def flatten_finding(
    span_row: dict[str, Any], finding: dict[str, Any]
) -> dict[str, Any]:
    """Flatten a single security finding with its parent span context."""
    metadata = finding.get("metadata", {})
    return {
        "finding_id": finding.get("id", ""),
        "span_id": span_row.get("span_id", ""),
        "trace_id": span_row.get("trace_id", ""),
        "start_time": span_row.get("start_time", ""),
        "prompt": span_row.get("prompt", ""),
        "security_score": span_row.get("security_score"),
        "severity": finding.get("severity", ""),
        "finding_type": finding.get("finding_type", ""),
        "description": finding.get("description", ""),
        "confidence_score": finding.get("confidence_score"),
        "location": finding.get("location", ""),
        "detected_at": finding.get("detected_at", ""),
        "requires_alert": finding.get("requires_alert", False),
        "voting_result": metadata.get("voting_result", ""),
        "agreeing_detectors": metadata.get("agreeing_detectors", ""),
        "ensemble_agreement": metadata.get("ensemble_agreement", ""),
        "pattern_name": metadata.get("pattern_name", ""),
        "ml_model": metadata.get("ml_model", ""),
        "ml_score": metadata.get("ml_score", ""),
        "ml_label": metadata.get("ml_label", ""),
        "source_detector": metadata.get("source_detector", ""),
        "auxiliary_corroboration": metadata.get("auxiliary_corroboration", ""),
    }


def export_traces(spans_out: Path, findings_out: Path) -> tuple[int, int]:
    """Export all spans and flattened findings from ClickHouse."""
    rows = ch_query(SPANS_QUERY)

    n_spans = 0
    n_findings = 0
    with open(spans_out, "w") as fs, open(findings_out, "w") as ff:
        for row in rows:
            flat = flatten_span(row)
            fs.write(json.dumps(flat, ensure_ascii=False) + "\n")
            n_spans += 1

            findings_raw = row.get("security_findings", "[]")
            findings = (
                json.loads(findings_raw)
                if isinstance(findings_raw, str)
                else findings_raw
            )
            for finding in findings:
                flat_f = flatten_finding(row, finding)
                ff.write(json.dumps(flat_f, ensure_ascii=False) + "\n")
                n_findings += 1

    return n_spans, n_findings


def main() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Export raw corpus
    corpus_out = RESULTS_DIR / "corpus_samples.jsonl"
    corpus = load_all_datasets()
    with open(corpus_out, "w") as f:
        for s in corpus:
            row = {
                "id": s.get("id", ""),
                "text": s.get("text", ""),
                "label": s.get("label", ""),
                "category": s.get("category", ""),
                "subcategory": s.get("subcategory", ""),
                "source": s.get("source", ""),
                "dataset_file": s.get("_dataset_file", ""),
            }
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"Exported {len(corpus)} corpus samples -> {corpus_out}")

    # Build text index for enriching eval results
    text_index = build_text_index(corpus)

    # 2. Export sampled eval results
    sampled_file = RESULTS_DIR / "proxy_stress_test_v2.json"
    eval_out = RESULTS_DIR / "eval_results.jsonl"
    n = export_eval_results(sampled_file, eval_out, text_index)
    if n > 0:
        print(f"Exported {n} eval results -> {eval_out}")
    elif n == -1:
        print(f"Skipped {sampled_file.name}: no findings (failed run)")
    else:
        print(f"No sampled results found at {sampled_file}")

    # 3. Export full eval results (if available and valid)
    full_file = RESULTS_DIR / "proxy_stress_test_full.json"
    full_out = RESULTS_DIR / "eval_results_full.jsonl"
    n = export_eval_results(full_file, full_out, text_index)
    if n > 0:
        print(f"Exported {n} full eval results -> {full_out}")
    elif n == -1:
        print(f"Skipped {full_file.name}: no findings (failed run)")
    else:
        print(f"No full results found at {full_file}")

    # 4. Export traces from ClickHouse
    spans_out = RESULTS_DIR / "traces_spans.jsonl"
    findings_out = RESULTS_DIR / "traces_findings.jsonl"
    try:
        n_spans, n_findings = export_traces(spans_out, findings_out)
        print(f"Exported {n_spans} spans -> {spans_out}")
        print(f"Exported {n_findings} findings -> {findings_out}")
    except Exception as e:
        print(f"ClickHouse export failed: {e}")


if __name__ == "__main__":
    main()
