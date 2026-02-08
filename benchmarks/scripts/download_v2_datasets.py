#!/usr/bin/env python3
"""Download v2 (English-only filtered) evaluation datasets from HuggingFace.

v2 datasets follow the DMPI-PMHFE paper (arXiv 2506.06384) specification:
  EV-012: Deepset    -- English-only (German removed via langdetect)
  EV-013: IvanLeoMK  -- English-only (German removed via langdetect)

SafeGuard (EV-011) is NOT included here because its test split is already
entirely English -- the existing safeguard_test.json (v1) is used directly.

Existing v1 files are left untouched for backwards compatibility.

Output format matches BenchmarkSample:
  {id, text, label, category, source}

Requirements:
  pip install datasets langdetect

Reproducibility:
  - DetectorFactory.seed is set to 0 for deterministic langdetect results.
  - HuggingFace dataset revisions are pinned by commit SHA.
  - Row-count assertions guard against silent data drift.
"""

import json
import sys
from pathlib import Path

from datasets import concatenate_datasets, load_dataset
from langdetect import DetectorFactory, LangDetectException, detect

# Pin langdetect RNG for deterministic results across runs.
DetectorFactory.seed = 0

# Pinned HuggingFace dataset revisions for reproducibility.
DEEPSET_REVISION = "4f61ecb038e9c3fb77e21034b22511b523772cdd"
IVANLEOMK_REVISION = "07858746d34ad8c6a5dad1d94b02ba75aec844e5"

# Expected sample counts after English-only filtering.
# If upstream data or langdetect behavior changes, these assertions catch it.
EXPECTED_DEEPSET_V2 = 355
EXPECTED_IVANLEOMK_V2 = 610


def is_english(text: str) -> bool:
    """Return True if langdetect classifies the text as English."""
    try:
        return detect(text) == "en"
    except LangDetectException:
        return False


def convert_sample(idx: int, text: str, label: int, source: str) -> dict:
    return {
        "id": f"{source}-v2-{idx:05d}",
        "text": text,
        "label": "malicious" if label == 1 else "benign",
        "category": "prompt_injection" if label == 1 else "benign",
        "source": source,
    }


def print_distribution(name: str, samples: list[dict]) -> None:
    """Print label distribution summary for a dataset."""
    benign = sum(1 for s in samples if s["label"] == "benign")
    malicious = len(samples) - benign
    benign_pct = benign / len(samples) * 100 if samples else 0
    malicious_pct = malicious / len(samples) * 100 if samples else 0
    print(f"  {name}: {len(samples)} samples")
    print(f"    benign:    {benign:>4} ({benign_pct:.1f}%)")
    print(f"    malicious: {malicious:>4} ({malicious_pct:.1f}%)")


def download_deepset_v2(output_dir: Path) -> None:
    """EV-012: Deepset train+test, filtered to English-only."""
    print("Downloading Deepset v2 (English-only)...")
    ds_train = load_dataset(
        "deepset/prompt-injections", split="train", revision=DEEPSET_REVISION,
    )
    ds_test = load_dataset(
        "deepset/prompt-injections", split="test", revision=DEEPSET_REVISION,
    )
    ds = concatenate_datasets([ds_train, ds_test])
    total = len(ds)

    samples = []
    filtered = 0
    for row in ds:
        if not is_english(row["text"]):
            filtered += 1
            continue
        samples.append(convert_sample(len(samples), row["text"], row["label"], "deepset"))

    print(f"  Filtered {filtered}/{total} non-English samples")
    assert len(samples) == EXPECTED_DEEPSET_V2, (
        f"Expected {EXPECTED_DEEPSET_V2} Deepset v2 samples, got {len(samples)}. "
        f"Upstream data or langdetect behavior may have changed."
    )

    path = output_dir / "deepset_v2.json"
    path.write_text(json.dumps(samples, indent=2, ensure_ascii=False))
    print_distribution("deepset_v2.json", samples)


def download_ivanleomk_v2(output_dir: Path) -> None:
    """EV-013: IvanLeoMK train split, filtered to English-only."""
    print("Downloading IvanLeoMK v2 (English-only)...")
    ds = load_dataset(
        "ivanleomk/prompt_injection_password", split="train", revision=IVANLEOMK_REVISION,
    )
    total = len(ds)

    samples = []
    filtered = 0
    for row in ds:
        if not is_english(row["text"]):
            filtered += 1
            continue
        samples.append(convert_sample(len(samples), row["text"], row["label"], "ivanleomk"))

    print(f"  Filtered {filtered}/{total} non-English samples")
    assert len(samples) == EXPECTED_IVANLEOMK_V2, (
        f"Expected {EXPECTED_IVANLEOMK_V2} IvanLeoMK v2 samples, got {len(samples)}. "
        f"Upstream data or langdetect behavior may have changed."
    )

    path = output_dir / "ivanleomk_v2.json"
    path.write_text(json.dumps(samples, indent=2, ensure_ascii=False))
    print_distribution("ivanleomk_v2.json", samples)


def main() -> None:
    output_dir = Path(__file__).resolve().parent.parent / "datasets" / "external"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Output directory: {output_dir}")
    print(f"DetectorFactory.seed: {DetectorFactory.seed}")
    print(f"Deepset revision: {DEEPSET_REVISION}")
    print(f"IvanLeoMK revision: {IVANLEOMK_REVISION}\n")

    download_deepset_v2(output_dir)
    print()
    download_ivanleomk_v2(output_dir)

    print("\nDone.")


if __name__ == "__main__":
    main()
