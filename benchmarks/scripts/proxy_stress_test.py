#!/usr/bin/env python3
"""
Send a diverse mix of malicious and benign payloads through the llmtrace proxy
and collect security classification results for analysis.
"""

import json
import random
import time
import sys
import os
import requests
from pathlib import Path
from typing import Any

PROXY_URL = os.environ.get("PROXY_URL", "http://localhost:8080")
API_KEY = os.environ.get("OPENAI_API_KEY", "")
DATASETS_DIR = Path(__file__).parent.parent / "datasets"

random.seed(42)


def load_dataset(path: Path) -> list[dict[str, Any]]:
    with open(path) as f:
        return json.load(f)


def sample_from(data: list[dict], n: int, label_filter: str | None = None) -> list[dict]:
    if label_filter:
        data = [d for d in data if d.get("label") == label_filter]
    return random.sample(data, min(n, len(data)))


def build_test_corpus() -> list[dict[str, Any]]:
    """Build a diverse mix of ~40 samples from multiple datasets."""
    corpus: list[dict[str, Any]] = []

    # Core datasets
    injections = load_dataset(DATASETS_DIR / "injection_samples.json")
    benign = load_dataset(DATASETS_DIR / "benign_samples.json")
    encoding = load_dataset(DATASETS_DIR / "encoding_evasion.json")
    notinject = load_dataset(DATASETS_DIR / "notinject_samples.json")

    # External datasets
    cybersec = load_dataset(DATASETS_DIR / "external" / "cyberseceval2_pi.json")
    hpi = load_dataset(DATASETS_DIR / "external" / "hpi_attack_approx.json")
    deepset = load_dataset(DATASETS_DIR / "external" / "deepset_v2.json")

    # Mix: ~20 malicious, ~20 benign
    corpus.extend(sample_from(injections, 8, "malicious"))     # classic injections
    corpus.extend(sample_from(encoding, 5, "malicious"))       # encoding evasion attacks
    corpus.extend(sample_from(cybersec, 4, "malicious"))       # cyberseceval2 attacks
    corpus.extend(sample_from(hpi, 3, "malicious"))            # HPI attacks

    corpus.extend(sample_from(benign, 8, "benign"))            # simple benign
    corpus.extend(sample_from(notinject, 6, "benign"))         # tricky benign (over-defense test)
    corpus.extend(sample_from(deepset, 3, "benign"))           # deepset benign
    corpus.extend(sample_from(encoding, 3, "benign"))          # benign encoding discussions

    random.shuffle(corpus)
    return corpus


def send_request(text: str, model: str = "gpt-4o-mini") -> dict[str, Any]:
    """Send a chat completion request through the proxy."""
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}",
    }
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": text}],
        "max_tokens": 50,
    }
    resp = requests.post(
        f"{PROXY_URL}/v1/chat/completions",
        headers=headers,
        json=payload,
        timeout=30,
    )
    return {
        "status_code": resp.status_code,
        "body": resp.json() if resp.status_code == 200 else resp.text,
    }


def fetch_latest_findings(limit: int = 50) -> list[dict[str, Any]]:
    """Fetch the latest security findings from the proxy API."""
    resp = requests.get(
        f"{PROXY_URL}/api/v1/security/findings",
        params={"limit": limit},
        headers={"X-LLMTrace-Tenant-ID": get_tenant_id()},
        timeout=10,
    )
    if resp.status_code != 200:
        return []
    return resp.json().get("data", [])


def get_tenant_id() -> str:
    resp = requests.get(f"{PROXY_URL}/api/v1/tenants", timeout=10)
    tenants = resp.json()
    return tenants[0]["id"] if tenants else ""


def match_finding_to_sample(
    findings: list[dict[str, Any]], text: str, min_time: str | None = None
) -> dict[str, Any] | None:
    """Find the span whose prompt matches the given text.

    When min_time is set, only consider spans started at or after that ISO timestamp.
    """
    for f in findings:
        if min_time and f.get("start_time", "") < min_time:
            continue
        prompt = f.get("prompt", "")
        if text[:80] in prompt:
            return f
    return None


def main() -> None:
    if not API_KEY:
        print("ERROR: Set OPENAI_API_KEY env var")
        sys.exit(1)

    corpus = build_test_corpus()
    print(f"Built test corpus: {len(corpus)} samples")
    print(f"  Malicious: {sum(1 for s in corpus if s['label'] == 'malicious')}")
    print(f"  Benign:    {sum(1 for s in corpus if s['label'] == 'benign')}")
    print()

    # Record start time so we only match spans from this run
    from datetime import datetime, timezone
    run_start = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")

    results: list[dict[str, Any]] = []

    for i, sample in enumerate(corpus):
        sid = sample.get("id", f"unknown-{i}")
        label = sample["label"]
        category = sample.get("category", "unknown")
        subcategory = sample.get("subcategory", "")
        text = sample["text"]

        print(f"[{i+1}/{len(corpus)}] {sid} ({label}/{category}) ", end="", flush=True)

        resp = send_request(text)
        print(f"-> HTTP {resp['status_code']} ", end="", flush=True)

        # Small delay to let async storage complete
        time.sleep(0.5)

        results.append({
            "id": sid,
            "label": label,
            "category": category,
            "subcategory": subcategory,
            "text_preview": text[:120],
            "http_status": resp["status_code"],
        })
        print("OK")

    # Wait for storage to flush
    print("\nWaiting 3s for storage flush...")
    time.sleep(3)

    # Fetch all findings and match them
    print("Fetching security findings from proxy...")
    findings = fetch_latest_findings(limit=200)
    print(f"Retrieved {len(findings)} spans with findings\n")

    for r in results:
        span = match_finding_to_sample(findings, r["text_preview"][:80], min_time=run_start)
        if span:
            r["security_score"] = span.get("security_score", 0)
            r["num_findings"] = len(span.get("security_findings", []))
            r["finding_types"] = [
                f.get("finding_type", "") for f in span.get("security_findings", [])
            ]
            ml_findings = [
                f for f in span.get("security_findings", [])
                if "ml_" in f.get("finding_type", "")
            ]
            r["ml_score"] = None
            if ml_findings:
                meta = ml_findings[0].get("metadata", {})
                score_str = meta.get("ml_score", "")
                if score_str:
                    r["ml_score"] = float(score_str)
                r["ml_label"] = meta.get("ml_label", "")
        else:
            r["security_score"] = 0
            r["num_findings"] = 0
            r["finding_types"] = []
            r["ml_score"] = None
            r["ml_label"] = ""

    # Classify correctness
    tp, tn, fp, fn = 0, 0, 0, 0
    threshold = 50  # security_score threshold for "flagged"

    for r in results:
        flagged = r["security_score"] >= threshold
        is_malicious = r["label"] == "malicious"

        if is_malicious and flagged:
            r["classification"] = "TP"
            tp += 1
        elif not is_malicious and not flagged:
            r["classification"] = "TN"
            tn += 1
        elif not is_malicious and flagged:
            r["classification"] = "FP"
            fp += 1
        else:
            r["classification"] = "FN"
            fn += 1

    # Print detailed report
    print("=" * 100)
    print("DETAILED RESULTS")
    print("=" * 100)
    print(f"{'ID':<16} {'Label':<10} {'Category':<22} {'Score':>5} {'#Find':>5} {'Class':>5} {'ML':>6}  Finding Types")
    print("-" * 100)

    for r in sorted(results, key=lambda x: (-x["security_score"], x["label"])):
        ml_str = f"{r['ml_score']:.2f}" if r["ml_score"] is not None else "  --"
        ftypes = ", ".join(set(r["finding_types"]))[:40] if r["finding_types"] else "--"
        print(
            f"{r['id']:<16} {r['label']:<10} {r['category']:<22} {r['security_score']:>5} "
            f"{r['num_findings']:>5} {r['classification']:>5} {ml_str:>6}  {ftypes}"
        )

    # Summary
    total = tp + tn + fp + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    accuracy = (tp + tn) / total if total > 0 else 0

    print()
    print("=" * 100)
    print("SUMMARY")
    print("=" * 100)
    print(f"Total samples:  {total}")
    print(f"True Positives:  {tp}  (malicious correctly flagged)")
    print(f"True Negatives:  {tn}  (benign correctly passed)")
    print(f"False Positives: {fp}  (benign incorrectly flagged)")
    print(f"False Negatives: {fn}  (malicious missed)")
    print()
    print(f"Accuracy:   {accuracy:.1%}")
    print(f"Precision:  {precision:.1%}")
    print(f"Recall:     {recall:.1%}")
    print(f"F1 Score:   {f1:.1%}")

    if fp > 0:
        print(f"\nFalse Positives (over-defense):")
        for r in results:
            if r["classification"] == "FP":
                print(f"  {r['id']}: score={r['security_score']}, text={r['text_preview'][:80]}...")

    if fn > 0:
        print(f"\nFalse Negatives (missed attacks):")
        for r in results:
            if r["classification"] == "FN":
                print(f"  {r['id']}: score={r['security_score']}, cat={r['category']}/{r.get('subcategory','')}")
                print(f"    text: {r['text_preview'][:100]}...")

    # Save results
    out_path = Path(__file__).parent.parent / "results" / "proxy_stress_test.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    main()
