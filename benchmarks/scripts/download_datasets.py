#!/usr/bin/env python3
"""Download external evaluation datasets from HuggingFace and convert to BenchmarkSample JSON.

Datasets:
  EV-011: xTRam1/safe-guard-prompt-injection (test split)
  EV-012: deepset/prompt-injections (train + test combined)
  EV-013: ivanleomk/prompt_injection_password (train split)

Output format matches BenchmarkSample:
  {id, text, label, category, source}
"""

import json
import sys
from pathlib import Path

from datasets import load_dataset, concatenate_datasets


def convert_sample(idx: int, text: str, label: int, source: str) -> dict:
    return {
        "id": f"{source}-{idx:05d}",
        "text": text,
        "label": "malicious" if label == 1 else "benign",
        "category": "prompt_injection" if label == 1 else "benign",
        "source": source,
    }


def download_safeguard(output_dir: Path) -> None:
    ds = load_dataset("xTRam1/safe-guard-prompt-injection", split="test")
    samples = [
        convert_sample(i, row["text"], row["label"], "safeguard")
        for i, row in enumerate(ds)
    ]
    path = output_dir / "safeguard_test.json"
    path.write_text(json.dumps(samples, indent=2, ensure_ascii=False))

    benign = sum(1 for s in samples if s["label"] == "benign")
    malicious = len(samples) - benign
    print(f"safeguard_test.json: {len(samples)} samples ({benign} benign, {malicious} malicious)")


def download_deepset(output_dir: Path) -> None:
    ds_train = load_dataset("deepset/prompt-injections", split="train")
    ds_test = load_dataset("deepset/prompt-injections", split="test")
    ds = concatenate_datasets([ds_train, ds_test])
    samples = [
        convert_sample(i, row["text"], row["label"], "deepset")
        for i, row in enumerate(ds)
    ]
    path = output_dir / "deepset_all.json"
    path.write_text(json.dumps(samples, indent=2, ensure_ascii=False))

    benign = sum(1 for s in samples if s["label"] == "benign")
    malicious = len(samples) - benign
    print(f"deepset_all.json: {len(samples)} samples ({benign} benign, {malicious} malicious)")


def download_ivanleomk(output_dir: Path) -> None:
    ds = load_dataset("ivanleomk/prompt_injection_password", split="train")
    samples = [
        convert_sample(i, row["text"], row["label"], "ivanleomk")
        for i, row in enumerate(ds)
    ]
    path = output_dir / "ivanleomk_all.json"
    path.write_text(json.dumps(samples, indent=2, ensure_ascii=False))

    benign = sum(1 for s in samples if s["label"] == "benign")
    malicious = len(samples) - benign
    print(f"ivanleomk_all.json: {len(samples)} samples ({benign} benign, {malicious} malicious)")


def main() -> None:
    output_dir = Path(__file__).resolve().parent.parent / "datasets" / "external"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Output directory: {output_dir}\n")

    download_safeguard(output_dir)
    download_deepset(output_dir)
    download_ivanleomk(output_dir)

    print("\nDone.")


if __name__ == "__main__":
    main()
