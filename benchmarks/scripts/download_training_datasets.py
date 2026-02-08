#!/usr/bin/env python3
"""Download and curate training dataset for fusion classifier (ML-014).

Merges HuggingFace datasets with existing local and external benchmark samples,
deduplicates by SHA-256 hash of normalized text, and outputs a single JSON file
in BenchmarkSample format.

Target composition: ~61K benign + ~16K malicious (accepts what's available).

Sources -- Benign:
  - tatsu-lab/alpaca (52K instructions)
  - databricks/databricks-dolly-15k (15K instructions)
  - Existing local: benign_samples, notinject_samples, encoding benign
  - Existing external: safeguard, deepset, ivanleomk benign splits

Sources -- Malicious:
  - Existing local: injection_samples, encoding malicious
  - Existing external: safeguard, deepset, ivanleomk, cyberseceval2, injecagent, asb, bipia malicious splits
  - hackaprompt/hackaprompt-dataset (~1.2K jailbreak prompts)
  - rubend18/ChatGPT-Jailbreak-Prompts (~100 prompts)

Output: benchmarks/datasets/training/training_dataset.json
"""

import hashlib
import json
import random
import sys
from pathlib import Path

from datasets import load_dataset


SEED = 42
TARGET_BENIGN = 61_000
TARGET_MALICIOUS = 16_000


def normalize_text(text: str) -> str:
    return " ".join(text.split()).strip().lower()


def dedup_hash(text: str) -> str:
    return hashlib.sha256(normalize_text(text).encode("utf-8")).hexdigest()


def make_sample(idx: int, text: str, label: str, source: str, category: str = "") -> dict:
    return {
        "id": f"train-{source}-{idx:06d}",
        "text": text.strip(),
        "label": label,
        "category": category or ("prompt_injection" if label == "malicious" else "benign"),
        "source": source,
    }


def load_local_samples(datasets_dir: Path) -> list[dict]:
    """Load existing local benchmark datasets."""
    samples = []
    local_files = {
        "benign_samples.json": "benign",
        "injection_samples.json": "malicious",
        "notinject_samples.json": "benign",
        "encoding_evasion.json": None,  # mixed labels
        "jailbreak_samples.json": "malicious",
    }

    for filename, forced_label in local_files.items():
        path = datasets_dir / filename
        if not path.exists():
            print(f"  [skip] {filename} not found")
            continue

        with open(path) as f:
            data = json.load(f)

        for item in data:
            label = forced_label or item.get("label", "benign")
            samples.append({
                "text": item["text"].strip(),
                "label": label,
                "source": f"local-{filename.replace('.json', '')}",
                "category": item.get("category", ""),
            })

    return samples


def load_external_samples(external_dir: Path) -> list[dict]:
    """Load existing external benchmark datasets."""
    samples = []
    external_files = [
        "safeguard_test.json",
        "deepset_all.json",
        "ivanleomk_all.json",
        "cyberseceval2_pi.json",
        "injecagent_attacks.json",
        "asb_attacks.json",
        "bipia_indirect.json",
        "harmbench_behaviors.json",
        "ailuminate_demo.json",
    ]

    for filename in external_files:
        path = external_dir / filename
        if not path.exists():
            print(f"  [skip] external/{filename} not found")
            continue

        with open(path) as f:
            data = json.load(f)

        for item in data:
            samples.append({
                "text": item["text"].strip(),
                "label": item["label"],
                "source": f"external-{item.get('source', filename.replace('.json', ''))}",
                "category": item.get("category", ""),
            })

    return samples


def download_alpaca() -> list[dict]:
    """Download tatsu-lab/alpaca instruction dataset (~52K benign)."""
    print("  Downloading tatsu-lab/alpaca...")
    ds = load_dataset("tatsu-lab/alpaca", split="train")
    samples = []
    for row in ds:
        text = row.get("instruction", "").strip()
        inp = row.get("input", "").strip()
        if inp:
            text = f"{text}\n{inp}"
        if text:
            samples.append({
                "text": text,
                "label": "benign",
                "source": "hf-alpaca",
                "category": "instruction",
            })
    print(f"    -> {len(samples)} samples")
    return samples


def download_dolly() -> list[dict]:
    """Download databricks-dolly-15k (~15K benign instructions)."""
    print("  Downloading databricks/databricks-dolly-15k...")
    ds = load_dataset("databricks/databricks-dolly-15k", split="train")
    samples = []
    for row in ds:
        text = row.get("instruction", "").strip()
        context = row.get("context", "").strip()
        if context:
            text = f"{text}\n{context}"
        if text:
            samples.append({
                "text": text,
                "label": "benign",
                "source": "hf-dolly",
                "category": row.get("category", "instruction"),
            })
    print(f"    -> {len(samples)} samples")
    return samples


def download_hackaprompt() -> list[dict]:
    """Download hackaprompt/hackaprompt-dataset (~1.2K jailbreak prompts)."""
    print("  Downloading hackaprompt/hackaprompt-dataset...")
    try:
        ds = load_dataset("hackaprompt/hackaprompt-dataset", split="train")
    except Exception as e:
        print(f"    [warn] Failed to download hackaprompt: {e}")
        return []

    samples = []
    for row in ds:
        text = row.get("user_input", "").strip()
        if text and len(text) > 10:
            samples.append({
                "text": text,
                "label": "malicious",
                "source": "hf-hackaprompt",
                "category": "jailbreak",
            })
    print(f"    -> {len(samples)} samples")
    return samples


def download_jailbreak_prompts() -> list[dict]:
    """Download rubend18/ChatGPT-Jailbreak-Prompts (~100 prompts)."""
    print("  Downloading rubend18/ChatGPT-Jailbreak-Prompts...")
    try:
        ds = load_dataset("rubend18/ChatGPT-Jailbreak-Prompts", split="train")
    except Exception as e:
        print(f"    [warn] Failed to download jailbreak prompts: {e}")
        return []

    samples = []
    for row in ds:
        text = row.get("Prompt", "").strip()
        if text and len(text) > 10:
            samples.append({
                "text": text,
                "label": "malicious",
                "source": "hf-jailbreak-prompts",
                "category": "jailbreak",
            })
    print(f"    -> {len(samples)} samples")
    return samples


def deduplicate(samples: list[dict]) -> list[dict]:
    """Deduplicate samples by SHA-256 of normalized text."""
    seen: set[str] = set()
    unique = []
    for s in samples:
        h = dedup_hash(s["text"])
        if h not in seen:
            seen.add(h)
            unique.append(s)
    removed = len(samples) - len(unique)
    if removed > 0:
        print(f"  Deduplication: removed {removed} duplicates ({len(samples)} -> {len(unique)})")
    return unique


def balance_and_format(
    benign: list[dict],
    malicious: list[dict],
    target_benign: int,
    target_malicious: int,
    seed: int,
) -> list[dict]:
    """Downsample to target sizes if needed, shuffle, and format as BenchmarkSample."""
    rng = random.Random(seed)

    if len(benign) > target_benign:
        rng.shuffle(benign)
        benign = benign[:target_benign]
    else:
        rng.shuffle(benign)

    if len(malicious) > target_malicious:
        rng.shuffle(malicious)
        malicious = malicious[:target_malicious]
    else:
        rng.shuffle(malicious)

    all_samples = []
    for i, s in enumerate(benign):
        all_samples.append(make_sample(i, s["text"], "benign", s["source"], s.get("category", "")))
    for i, s in enumerate(malicious):
        all_samples.append(make_sample(i, s["text"], "malicious", s["source"], s.get("category", "")))

    rng.shuffle(all_samples)
    return all_samples


def main() -> None:
    datasets_dir = Path(__file__).resolve().parent.parent / "datasets"
    external_dir = datasets_dir / "external"
    output_dir = datasets_dir / "training"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "training_dataset.json"

    print(f"Datasets dir: {datasets_dir}")
    print(f"Output: {output_path}\n")

    all_benign: list[dict] = []
    all_malicious: list[dict] = []

    # Local datasets
    print("Loading local datasets...")
    local = load_local_samples(datasets_dir)
    for s in local:
        if s["label"] == "benign":
            all_benign.append(s)
        else:
            all_malicious.append(s)
    print(f"  Local: {len(all_benign)} benign, {len(all_malicious)} malicious\n")

    # External datasets
    print("Loading external datasets...")
    external = load_external_samples(external_dir)
    for s in external:
        if s["label"] == "benign":
            all_benign.append(s)
        else:
            all_malicious.append(s)
    print(f"  After external: {len(all_benign)} benign, {len(all_malicious)} malicious\n")

    # HuggingFace benign
    print("Downloading HuggingFace benign datasets...")
    all_benign.extend(download_alpaca())
    all_benign.extend(download_dolly())
    print(f"  After HF benign: {len(all_benign)} benign\n")

    # HuggingFace malicious
    print("Downloading HuggingFace malicious datasets...")
    all_malicious.extend(download_hackaprompt())
    all_malicious.extend(download_jailbreak_prompts())
    print(f"  After HF malicious: {len(all_malicious)} malicious\n")

    # Deduplicate
    print("Deduplicating...")
    all_benign = deduplicate(all_benign)
    all_malicious = deduplicate(all_malicious)
    print(f"  After dedup: {len(all_benign)} benign, {len(all_malicious)} malicious\n")

    # Balance and format
    print(f"Balancing (target: {TARGET_BENIGN} benign, {TARGET_MALICIOUS} malicious)...")
    samples = balance_and_format(
        all_benign, all_malicious, TARGET_BENIGN, TARGET_MALICIOUS, SEED
    )

    benign_count = sum(1 for s in samples if s["label"] == "benign")
    malicious_count = len(samples) - benign_count

    print(f"\nFinal dataset: {len(samples)} samples ({benign_count} benign, {malicious_count} malicious)")
    print(f"Writing to {output_path}...")

    output_path.write_text(json.dumps(samples, indent=2, ensure_ascii=False))
    print("Done.")


if __name__ == "__main__":
    main()
