#!/usr/bin/env python3
"""Download external evaluation datasets from HuggingFace and convert to BenchmarkSample JSON.

Datasets:
  EV-011: xTRam1/safe-guard-prompt-injection (test split)
  EV-012: deepset/prompt-injections (train + test combined)
  EV-013: ivanleomk/prompt_injection_password (train split)
  EV-006: CyberSecEval 2 prompt injection subset (137 English attack samples)
  EV-015: HarmBench harmful behaviors (centerforaisafety/HarmBench)
  EV-007: MLCommons AILuminate demo prompts (mlcommons/ailuminate)
  EV-003: InjecAgent indirect prompt injection (uiuc-kang-lab/InjecAgent)
  EV-004: ASB agent security attack tools (agiresearch/ASB)
  EV-014: BIPIA indirect prompt injection benchmark (microsoft/BIPIA)

Output format matches BenchmarkSample:
  {id, text, label, category, source}
"""

import csv
import io
import json
import random
import sys
import urllib.request
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


def download_cyberseceval2(output_dir: Path) -> None:
    url = (
        "https://raw.githubusercontent.com/meta-llama/PurpleLlama/"
        "main/CybersecurityBenchmarks/datasets/prompt_injection/prompt_injection.json"
    )
    with urllib.request.urlopen(url) as resp:
        raw = json.loads(resp.read().decode("utf-8"))

    samples = []
    for entry in raw:
        prompt_id = entry["prompt_id"]
        samples.append({
            "id": f"cyberseceval2-{prompt_id:05d}",
            "text": entry["user_input"],
            "label": "malicious",
            "category": entry["injection_variant"],
            "source": "cyberseceval2",
        })

    path = output_dir / "cyberseceval2_pi.json"
    path.write_text(json.dumps(samples, indent=2, ensure_ascii=False))
    print(f"cyberseceval2_pi.json: {len(samples)} samples (all malicious)")


def download_harmbench(output_dir: Path) -> None:
    """EV-015: HarmBench harmful behaviors (CSV from centerforaisafety/HarmBench)."""
    url = (
        "https://raw.githubusercontent.com/centerforaisafety/HarmBench/"
        "main/data/behavior_datasets/harmbench_behaviors_text_all.csv"
    )
    with urllib.request.urlopen(url) as resp:
        text = resp.read().decode("utf-8")

    reader = csv.DictReader(io.StringIO(text))
    samples = []
    for i, row in enumerate(reader):
        behavior = row["Behavior"].strip()
        if not behavior:
            continue
        samples.append({
            "id": f"harmbench-{row.get('BehaviorID', f'{i:05d}')}",
            "text": behavior,
            "label": "malicious",
            "category": row.get("SemanticCategory", "unknown"),
            "subcategory": row.get("FunctionalCategory", ""),
            "source": "harmbench",
        })

    path = output_dir / "harmbench_behaviors.json"
    path.write_text(json.dumps(samples, indent=2, ensure_ascii=False))
    print(f"harmbench_behaviors.json: {len(samples)} samples (all malicious)")


def download_ailuminate(output_dir: Path) -> None:
    """EV-007: MLCommons AILuminate demo prompts (CSV from mlcommons/ailuminate)."""
    url = (
        "https://raw.githubusercontent.com/mlcommons/ailuminate/"
        "main/airr_official_1.0_demo_en_us_prompt_set_release.csv"
    )
    with urllib.request.urlopen(url) as resp:
        text = resp.read().decode("utf-8")

    reader = csv.DictReader(io.StringIO(text))
    samples = []
    for i, row in enumerate(reader):
        prompt = row["prompt_text"].strip()
        if not prompt:
            continue
        samples.append({
            "id": f"ailuminate-{row.get('release_prompt_id', f'{i:05d}')}",
            "text": prompt,
            "label": "malicious",
            "category": row.get("hazard", "unknown"),
            "subcategory": row.get("persona", ""),
            "source": "ailuminate",
        })

    path = output_dir / "ailuminate_demo.json"
    path.write_text(json.dumps(samples, indent=2, ensure_ascii=False))
    print(f"ailuminate_demo.json: {len(samples)} samples (all malicious)")


def download_injecagent(output_dir: Path) -> None:
    """EV-003: InjecAgent indirect prompt injection test cases."""
    base_url = (
        "https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/data/"
    )
    files = [
        "test_cases_dh_base.json",
        "test_cases_dh_enhanced.json",
        "test_cases_ds_base.json",
        "test_cases_ds_enhanced.json",
    ]

    samples = []
    idx = 0
    for fname in files:
        url = base_url + fname
        with urllib.request.urlopen(url) as resp:
            cases = json.loads(resp.read().decode("utf-8"))

        variant = fname.replace("test_cases_", "").replace(".json", "")
        for case in cases:
            instruction = case.get("Attacker Instruction", "").strip()
            if not instruction:
                continue
            samples.append({
                "id": f"injecagent-{variant}-{idx:05d}",
                "text": instruction,
                "label": "malicious",
                "category": case.get("Attack Type", "unknown"),
                "subcategory": variant,
                "source": "injecagent",
            })
            idx += 1

    path = output_dir / "injecagent_attacks.json"
    path.write_text(json.dumps(samples, indent=2, ensure_ascii=False))
    print(f"injecagent_attacks.json: {len(samples)} samples (all malicious)")


def download_asb(output_dir: Path) -> None:
    """EV-004: Agent Security Bench attack tools (JSONL from agiresearch/ASB)."""
    url = (
        "https://raw.githubusercontent.com/agiresearch/ASB/"
        "main/data/all_attack_tools.jsonl"
    )
    with urllib.request.urlopen(url) as resp:
        lines = resp.read().decode("utf-8").strip().split("\n")

    samples = []
    for i, line in enumerate(lines):
        entry = json.loads(line)
        instruction = entry.get("Attacker Instruction", "").strip()
        if not instruction:
            continue
        samples.append({
            "id": f"asb-{i:05d}",
            "text": instruction,
            "label": "malicious",
            "category": entry.get("Attack Type", "unknown"),
            "subcategory": entry.get("Corresponding Agent", ""),
            "source": "asb",
        })

    path = output_dir / "asb_attacks.json"
    path.write_text(json.dumps(samples, indent=2, ensure_ascii=False))
    print(f"asb_attacks.json: {len(samples)} samples (all malicious)")


def download_bipia(output_dir: Path) -> None:
    """EV-014: BIPIA indirect prompt injection benchmark.

    Creates combined samples: benign contexts + contexts with injected attack texts.
    Uses email, code, and table tasks (QA and summarization require external data).
    """
    random.seed(42)

    base_url = "https://raw.githubusercontent.com/microsoft/BIPIA/main/benchmark/"

    contexts: list[dict] = []
    for task in ["email", "code", "table"]:
        url = base_url + f"{task}/test.jsonl"
        with urllib.request.urlopen(url) as resp:
            lines = resp.read().decode("utf-8").strip().split("\n")
        for line in lines:
            entry = json.loads(line)
            raw_ctx = entry.get("context", "")
            if isinstance(raw_ctx, list):
                ctx = "\n".join(str(s) for s in raw_ctx).strip()
            else:
                ctx = str(raw_ctx).strip()
            raw_q = entry.get("question", "")
            if isinstance(raw_q, list):
                q = "\n".join(str(s) for s in raw_q).strip()
            else:
                q = str(raw_q).strip()
            if ctx:
                contexts.append({"context": ctx, "question": q, "task": task})

    attacks: list[dict] = []
    for attack_file in ["text_attack_test.json", "code_attack_test.json"]:
        url = base_url + attack_file
        with urllib.request.urlopen(url) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        for category, prompts in data.items():
            for prompt in prompts:
                text = prompt.strip() if isinstance(prompt, str) else str(prompt).strip()
                if text:
                    attacks.append({"text": text, "category": category})

    samples = []

    for i, ctx in enumerate(contexts):
        combined = f"{ctx['context']}\n\n{ctx['question']}"
        samples.append({
            "id": f"bipia-benign-{ctx['task']}-{i:05d}",
            "text": combined,
            "label": "benign",
            "category": f"benign_{ctx['task']}",
            "source": "bipia",
        })

    for i, ctx in enumerate(contexts):
        attack = random.choice(attacks)
        injected = f"{ctx['context']}\n\n{attack['text']}\n\n{ctx['question']}"
        samples.append({
            "id": f"bipia-attack-{ctx['task']}-{i:05d}",
            "text": injected,
            "label": "malicious",
            "category": attack["category"],
            "subcategory": ctx["task"],
            "source": "bipia",
        })

    path = output_dir / "bipia_indirect.json"
    path.write_text(json.dumps(samples, indent=2, ensure_ascii=False))

    benign = sum(1 for s in samples if s["label"] == "benign")
    malicious = len(samples) - benign
    print(f"bipia_indirect.json: {len(samples)} samples ({benign} benign, {malicious} malicious)")


def main() -> None:
    output_dir = Path(__file__).resolve().parent.parent / "datasets" / "external"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Output directory: {output_dir}\n")

    download_safeguard(output_dir)
    download_deepset(output_dir)
    download_ivanleomk(output_dir)
    download_cyberseceval2(output_dir)
    download_harmbench(output_dir)
    download_ailuminate(output_dir)
    download_injecagent(output_dir)
    download_asb(output_dir)
    download_bipia(output_dir)

    print("\nDone.")


if __name__ == "__main__":
    main()
