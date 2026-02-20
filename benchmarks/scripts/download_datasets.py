#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["datasets", "huggingface-hub"]
# ///
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
  EV-022: WildJailbreak adversarial + vanilla (allenai/wildjailbreak) [gated]
  EV-023: HackAPrompt competition attacks (hackaprompt/hackaprompt-dataset) [gated]
  EV-024: In-the-wild jailbreak prompts (TrustAIRLab/in-the-wild-jailbreak-prompts)
  EV-025: Mindgard evaded injection/jailbreak (Mindgard/evaded-...) [gated]
  EV-026: XSTest over-refusal test (paul-rottger/xstest on GitHub)
  EV-027: JailbreakBench behaviors (JailbreakBench/JBB-Behaviors)
  EV-028: AdvBench harmful behaviors (llm-attacks/llm-attacks on GitHub)
  EV-029: SPML Chatbot Prompt Injection (reshabhs/SPML_Chatbot_Prompt_Injection)
  EV-030: Rubend18 ChatGPT Jailbreak Prompts (rubend18/ChatGPT-Jailbreak-Prompts)
  EV-031: SaTML CTF attack interactions (ethz-spylab/ctf-satml24)

Output format matches BenchmarkSample:
  {id, text, label, category, source}
"""

import csv
import io
import json
import random
import sys
import urllib.request
from collections.abc import Callable
from pathlib import Path

from datasets import load_dataset, concatenate_datasets

# Pinned commit SHAs for reproducibility (fetched 2026-02-08).
_COMMITS = {
    # GitHub repos
    "PurpleLlama": "31a82e49871c6457c9dfa559f69b7f811666aa30",
    "HarmBench": "8e1604d1171fe8a48d8febecd22f600e462bdcdd",
    "ailuminate": "769cc2be9d20c8d4fb26ce53b68865ed41dfb8e2",
    "InjecAgent": "f19c9f2c79a41046eb13c03c51a24c567a8ffa07",
    "ASB": "eac7bcf38c116f42b46e6d480e56e599b99e73c2",
    "BIPIA": "a004b69ec0dd446e0afd461d98cb5e96e120a5d0",
    "llm_attacks": "098262edf85f807224e70ecd87b9d83716bf6b73",
    "xstest_github": "d7bb5bd738c1fcbc36edd83d5e7d1b71a3e2d84d",
    # HuggingFace datasets
    "safeguard_hf": "a3a877d608f37b7d20d9945671902df895ecdb46",
    "deepset_hf": "4f61ecb038e9c3fb77e21034b22511b523772cdd",
    "ivanleomk_hf": "07858746d34ad8c6a5dad1d94b02ba75aec844e5",
    "tensor_trust_hf": "4de2b2fe01ba0cb6fbf7cbb9f1a3fabaf8157372",
    # Harelix dataset deleted from HuggingFace (EV-020 blocked).
    # "harelix_hf": "4bb1d6df694c08bddc71c6eba20ca80b109ee30c",
    "jackhhao_hf": "2f2ceeb39658696fd3f462403562b6eea5306287",
    "wildjailbreak_hf": "5ddc12a7894f842b0619b8e1c7ee496b198af009",
    "hackaprompt_hf": "25b87fbedfb86840abaf8cd09af7a029208a971a",
    "in_the_wild_hf": "a10aab8eff1c73165a442d4464dce192bd28b9c5",
    "mindgard_hf": "ec63ffb26ba6f29ca1095fabb2e9f9be5f8b9d34",
    "jailbreakbench_hf": "886acc352a31533ffbcf4ef22c744658688086fc",
    "spml_hf": "02ce8084e979bc7d4c24ee35d22ecb7f2db96ff5",
    "rubend18_hf": "b93e4982f8f8ad2d82c6d35e3c00d161844ad70a",
    "satml_hf": "11426babe61ee16b0efe7b55e0430359e0fc4235",
}

# Expected sample counts for integrity verification (pinned to commit SHAs above).
# If these assertions fail, upstream data changed or a commit SHA was updated.
_EXPECTED_COUNTS = {
    "safeguard_test.json": 2060,
    "deepset_all.json": 662,
    "ivanleomk_all.json": 917,
    "cyberseceval2_pi.json": 251,
    "harmbench_behaviors.json": 400,
    "ailuminate_demo.json": 1200,
    "injecagent_attacks.json": 2108,
    "asb_attacks.json": 400,
    "bipia_indirect.json": 400,
    "tensor_trust_attacks.json": 1000,
    # "harelix_mixed.json": 1174,  # EV-020 blocked: dataset deleted from HuggingFace
    "jackhhao_jailbreak.json": 1306,
    "wildjailbreak.json": 5000,
    "hackaprompt.json": 1200,
    "in_the_wild_jailbreak.json": 2071,
    "mindgard_evasion.json": 1560,
    "xstest.json": 450,
    "jailbreakbench.json": 200,
    "advbench_harmful.json": 520,
    "spml_chatbot.json": 5000,
    "rubend18_jailbreak.json": 79,
    "satml_ctf.json": 5000,
}


def _assert_count(filename: str, actual: int) -> None:
    expected = _EXPECTED_COUNTS[filename]
    assert actual == expected, (
        f"{filename}: expected {expected} samples, got {actual}. "
        f"Upstream data or commit SHA may have changed."
    )


def convert_sample(idx: int, text: str, label: int, source: str) -> dict:
    return {
        "id": f"{source}-{idx:05d}",
        "text": text,
        "label": "malicious" if label == 1 else "benign",
        "category": "prompt_injection" if label == 1 else "benign",
        "source": source,
    }


def _download_hf_dataset(
    output_dir: Path,
    hf_name: str,
    splits: list[str],
    source_label: str,
    output_filename: str,
    commit_key: str,
) -> None:
    """Download a HuggingFace dataset, convert to BenchmarkSample JSON, and write."""
    datasets_list = [
        load_dataset(hf_name, split=s, revision=_COMMITS[commit_key])
        for s in splits
    ]
    ds = concatenate_datasets(datasets_list) if len(datasets_list) > 1 else datasets_list[0]
    samples = [
        convert_sample(i, row["text"], row["label"], source_label)
        for i, row in enumerate(ds)
    ]
    _assert_count(output_filename, len(samples))
    path = output_dir / output_filename
    path.write_text(json.dumps(samples, indent=2, ensure_ascii=False))

    benign = sum(1 for s in samples if s["label"] == "benign")
    malicious = len(samples) - benign
    print(f"{output_filename}: {len(samples)} samples ({benign} benign, {malicious} malicious)")


def download_safeguard(output_dir: Path) -> None:
    _download_hf_dataset(
        output_dir, "xTRam1/safe-guard-prompt-injection",
        ["test"], "safeguard", "safeguard_test.json", "safeguard_hf",
    )


def download_deepset(output_dir: Path) -> None:
    _download_hf_dataset(
        output_dir, "deepset/prompt-injections",
        ["train", "test"], "deepset", "deepset_all.json", "deepset_hf",
    )


def download_ivanleomk(output_dir: Path) -> None:
    _download_hf_dataset(
        output_dir, "ivanleomk/prompt_injection_password",
        ["train"], "ivanleomk", "ivanleomk_all.json", "ivanleomk_hf",
    )


def download_cyberseceval2(output_dir: Path) -> None:
    url = (
        "https://raw.githubusercontent.com/meta-llama/PurpleLlama/"
        f"{_COMMITS['PurpleLlama']}/CybersecurityBenchmarks/datasets/prompt_injection/prompt_injection.json"
    )
    with urllib.request.urlopen(url, timeout=30) as resp:
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

    _assert_count("cyberseceval2_pi.json", len(samples))
    path = output_dir / "cyberseceval2_pi.json"
    path.write_text(json.dumps(samples, indent=2, ensure_ascii=False))
    print(f"cyberseceval2_pi.json: {len(samples)} samples (all malicious)")


def download_harmbench(output_dir: Path) -> None:
    """EV-015: HarmBench harmful behaviors (CSV from centerforaisafety/HarmBench)."""
    url = (
        "https://raw.githubusercontent.com/centerforaisafety/HarmBench/"
        f"{_COMMITS['HarmBench']}/data/behavior_datasets/harmbench_behaviors_text_all.csv"
    )
    with urllib.request.urlopen(url, timeout=30) as resp:
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

    _assert_count("harmbench_behaviors.json", len(samples))
    path = output_dir / "harmbench_behaviors.json"
    path.write_text(json.dumps(samples, indent=2, ensure_ascii=False))
    print(f"harmbench_behaviors.json: {len(samples)} samples (all malicious)")


def download_ailuminate(output_dir: Path) -> None:
    """EV-007: MLCommons AILuminate demo prompts (CSV from mlcommons/ailuminate)."""
    url = (
        "https://raw.githubusercontent.com/mlcommons/ailuminate/"
        f"{_COMMITS['ailuminate']}/airr_official_1.0_demo_en_us_prompt_set_release.csv"
    )
    with urllib.request.urlopen(url, timeout=30) as resp:
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

    _assert_count("ailuminate_demo.json", len(samples))
    path = output_dir / "ailuminate_demo.json"
    path.write_text(json.dumps(samples, indent=2, ensure_ascii=False))
    print(f"ailuminate_demo.json: {len(samples)} samples (all malicious)")


def download_injecagent(output_dir: Path) -> None:
    """EV-003: InjecAgent indirect prompt injection test cases."""
    base_url = (
        f"https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/{_COMMITS['InjecAgent']}/data/"
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
        with urllib.request.urlopen(url, timeout=30) as resp:
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

    _assert_count("injecagent_attacks.json", len(samples))
    path = output_dir / "injecagent_attacks.json"
    path.write_text(json.dumps(samples, indent=2, ensure_ascii=False))
    print(f"injecagent_attacks.json: {len(samples)} samples (all malicious)")


def download_asb(output_dir: Path) -> None:
    """EV-004: Agent Security Bench attack tools (JSONL from agiresearch/ASB)."""
    url = (
        "https://raw.githubusercontent.com/agiresearch/ASB/"
        f"{_COMMITS['ASB']}/data/all_attack_tools.jsonl"
    )
    with urllib.request.urlopen(url, timeout=30) as resp:
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

    _assert_count("asb_attacks.json", len(samples))
    path = output_dir / "asb_attacks.json"
    path.write_text(json.dumps(samples, indent=2, ensure_ascii=False))
    print(f"asb_attacks.json: {len(samples)} samples (all malicious)")


def download_bipia(output_dir: Path) -> None:
    """EV-014: BIPIA indirect prompt injection benchmark.

    Creates combined samples: benign contexts + contexts with injected attack texts.
    Uses email, code, and table tasks (QA and summarization require external data).
    """
    random.seed(42)

    base_url = f"https://raw.githubusercontent.com/microsoft/BIPIA/{_COMMITS['BIPIA']}/benchmark/"

    contexts: list[dict] = []
    for task in ["email", "code", "table"]:
        url = base_url + f"{task}/test.jsonl"
        with urllib.request.urlopen(url, timeout=30) as resp:
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
        with urllib.request.urlopen(url, timeout=30) as resp:
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

    _assert_count("bipia_indirect.json", len(samples))
    path = output_dir / "bipia_indirect.json"
    path.write_text(json.dumps(samples, indent=2, ensure_ascii=False))

    benign = sum(1 for s in samples if s["label"] == "benign")
    malicious = len(samples) - benign
    print(f"bipia_indirect.json: {len(samples)} samples ({benign} benign, {malicious} malicious)")


def download_tensor_trust(output_dir: Path) -> None:
    """EV-019: Tensor Trust prompt hijacking/extraction attacks (sampled 1000).

    Loads hijacking (776) and extraction (570) robustness benchmark files,
    tags each with its category, then samples 1000 from the combined pool.
    """
    random.seed(42)
    revision = _COMMITS["tensor_trust_hf"]

    hijack_ds = load_dataset(
        "qxcv/tensor-trust",
        data_files="benchmarks/hijacking-robustness/v1/hijacking_robustness_dataset.jsonl",
        split="train",
        revision=revision,
    )
    extract_ds = load_dataset(
        "qxcv/tensor-trust",
        data_files="benchmarks/extraction-robustness/v1/extraction_robustness_dataset.jsonl",
        split="train",
        revision=revision,
    )

    pool: list[tuple[str, str]] = []
    for row in hijack_ds:
        pool.append((row["attack"], "prompt_hijacking"))
    for row in extract_ds:
        pool.append((row["attack"], "prompt_extraction"))

    random.shuffle(pool)
    selected = pool[:1000]

    samples = []
    for i, (text, category) in enumerate(selected):
        samples.append({
            "id": f"tensor_trust-{i:05d}",
            "text": text,
            "label": "malicious",
            "category": category,
            "source": "tensor_trust",
        })

    _assert_count("tensor_trust_attacks.json", len(samples))
    path = output_dir / "tensor_trust_attacks.json"
    path.write_text(json.dumps(samples, indent=2, ensure_ascii=False))
    print(f"tensor_trust_attacks.json: {len(samples)} samples (all malicious)")


def download_jackhhao(output_dir: Path) -> None:
    """EV-021: Jackhhao jailbreak-classification (balanced benign/jailbreak)."""
    revision = _COMMITS["jackhhao_hf"]
    ds = concatenate_datasets([
        load_dataset("jackhhao/jailbreak-classification", split="train", revision=revision),
        load_dataset("jackhhao/jailbreak-classification", split="test", revision=revision),
    ])
    samples = []
    for i, row in enumerate(ds):
        prompt_type = row.get("type", "").strip().lower()
        is_malicious = prompt_type == "jailbreak"
        samples.append({
            "id": f"jackhhao-{i:05d}",
            "text": row["prompt"],
            "label": "malicious" if is_malicious else "benign",
            "category": "jailbreak" if is_malicious else "benign",
            "source": "jackhhao",
        })

    _assert_count("jackhhao_jailbreak.json", len(samples))
    path = output_dir / "jackhhao_jailbreak.json"
    path.write_text(json.dumps(samples, indent=2, ensure_ascii=False))

    benign = sum(1 for s in samples if s["label"] == "benign")
    malicious = len(samples) - benign
    print(f"jackhhao_jailbreak.json: {len(samples)} samples ({benign} benign, {malicious} malicious)")


def download_wildjailbreak(output_dir: Path) -> None:
    """EV-022: WildJailbreak adversarial + vanilla (sampled 5000). Gated dataset."""
    random.seed(42)
    revision = _COMMITS["wildjailbreak_hf"]
    ds = load_dataset("allenai/wildjailbreak", split="train", revision=revision)

    pool: list[tuple[str, bool, str]] = []
    for row in ds:
        data_type = row.get("data_type", "")
        if "adversarial" in data_type:
            text = (row.get("adversarial") or "").strip()
        else:
            text = (row.get("vanilla") or "").strip()
        if not text:
            continue
        is_malicious = "harmful" in data_type
        pool.append((text, is_malicious, data_type))

    random.shuffle(pool)
    selected = pool[:5000]

    samples = []
    for i, (text, is_mal, dtype) in enumerate(selected):
        samples.append({
            "id": f"wildjailbreak-{i:05d}",
            "text": text,
            "label": "malicious" if is_mal else "benign",
            "category": "jailbreak" if is_mal else "benign",
            "subcategory": dtype,
            "source": "wildjailbreak",
        })

    _assert_count("wildjailbreak.json", len(samples))
    path = output_dir / "wildjailbreak.json"
    path.write_text(json.dumps(samples, indent=2, ensure_ascii=False))

    benign = sum(1 for s in samples if s["label"] == "benign")
    malicious = len(samples) - benign
    print(f"wildjailbreak.json: {len(samples)} samples ({benign} benign, {malicious} malicious)")


def download_hackaprompt(output_dir: Path) -> None:
    """EV-023: HackAPrompt competition attacks (deduplicated). Gated dataset."""
    ds = load_dataset(
        "hackaprompt/hackaprompt-dataset", split="train",
        revision=_COMMITS["hackaprompt_hf"],
    )

    seen: set[str] = set()
    samples: list[dict] = []
    idx = 0
    for row in ds:
        user_input = (row.get("user_input") or "").strip()
        if not user_input or len(user_input) < 5:
            continue
        if row.get("error", False):
            continue
        if user_input in seen:
            continue
        seen.add(user_input)
        samples.append({
            "id": f"hackaprompt-{idx:05d}",
            "text": user_input,
            "label": "malicious",
            "category": "jailbreak",
            "subcategory": f"level_{row.get('level', 'unknown')}",
            "source": "hackaprompt",
        })
        idx += 1

    _assert_count("hackaprompt.json", len(samples))
    path = output_dir / "hackaprompt.json"
    path.write_text(json.dumps(samples, indent=2, ensure_ascii=False))
    print(f"hackaprompt.json: {len(samples)} samples (all malicious)")


def download_in_the_wild_jailbreak(output_dir: Path) -> None:
    """EV-024: In-the-wild jailbreak prompts (all jailbreak configs combined)."""
    revision = _COMMITS["in_the_wild_hf"]
    configs = ["jailbreak_2023_05_07", "jailbreak_2023_12_25"]

    pool: list[tuple[str, str]] = []
    for config in configs:
        ds = load_dataset(
            "TrustAIRLab/in-the-wild-jailbreak-prompts",
            config, split="train", revision=revision,
        )
        for row in ds:
            text = (row.get("prompt") or "").strip()
            if not text:
                continue
            pool.append((text, row.get("platform", "")))

    samples = []
    for i, (text, platform) in enumerate(pool):
        samples.append({
            "id": f"in_the_wild-{i:05d}",
            "text": text,
            "label": "malicious",
            "category": "jailbreak",
            "subcategory": platform,
            "source": "in_the_wild_jailbreak",
        })

    _assert_count("in_the_wild_jailbreak.json", len(samples))
    path = output_dir / "in_the_wild_jailbreak.json"
    path.write_text(json.dumps(samples, indent=2, ensure_ascii=False))
    print(f"in_the_wild_jailbreak.json: {len(samples)} samples (all malicious)")


def download_mindgard_evasion(output_dir: Path) -> None:
    """EV-025: Mindgard evaded prompt injection/jailbreak samples. Gated dataset."""
    ds = load_dataset(
        "Mindgard/evaded-prompt-injection-and-jailbreak-samples",
        split="train", revision=_COMMITS["mindgard_hf"],
    )

    samples = []
    for i, row in enumerate(ds):
        text = (row.get("modified_sample") or "").strip()
        if not text:
            continue
        samples.append({
            "id": f"mindgard-{i:05d}",
            "text": text,
            "label": "malicious",
            "category": "evasion",
            "subcategory": row.get("attack_name", ""),
            "source": "mindgard",
        })

    _assert_count("mindgard_evasion.json", len(samples))
    path = output_dir / "mindgard_evasion.json"
    path.write_text(json.dumps(samples, indent=2, ensure_ascii=False))
    print(f"mindgard_evasion.json: {len(samples)} samples (all malicious)")


def download_xstest(output_dir: Path) -> None:
    """EV-026: XSTest over-refusal test prompts (CSV from paul-rottger/xstest)."""
    url = (
        "https://raw.githubusercontent.com/paul-rottger/xstest/"
        f"{_COMMITS['xstest_github']}/xstest_prompts.csv"
    )
    with urllib.request.urlopen(url, timeout=30) as resp:
        text = resp.read().decode("utf-8")

    reader = csv.DictReader(io.StringIO(text))
    samples = []
    for i, row in enumerate(reader):
        prompt = row.get("prompt", "").strip()
        if not prompt:
            continue
        samples.append({
            "id": f"xstest-{row.get('id', f'{i:05d}')}",
            "text": prompt,
            "label": "benign",
            "category": "over_defense",
            "subcategory": row.get("type", ""),
            "source": "xstest",
        })

    _assert_count("xstest.json", len(samples))
    path = output_dir / "xstest.json"
    path.write_text(json.dumps(samples, indent=2, ensure_ascii=False))
    print(f"xstest.json: {len(samples)} samples (all benign / over-defense)")


def download_jailbreakbench(output_dir: Path) -> None:
    """EV-027: JailbreakBench behaviors (harmful + benign splits)."""
    revision = _COMMITS["jailbreakbench_hf"]
    harmful = load_dataset(
        "JailbreakBench/JBB-Behaviors", "behaviors",
        split="harmful", revision=revision,
    )
    benign = load_dataset(
        "JailbreakBench/JBB-Behaviors", "behaviors",
        split="benign", revision=revision,
    )

    samples = []
    for i, row in enumerate(harmful):
        text = (row.get("Goal") or "").strip()
        if not text:
            continue
        samples.append({
            "id": f"jailbreakbench-harmful-{i:05d}",
            "text": text,
            "label": "malicious",
            "category": "jailbreak",
            "subcategory": row.get("Category", ""),
            "source": "jailbreakbench",
        })
    for i, row in enumerate(benign):
        text = (row.get("Goal") or "").strip()
        if not text:
            continue
        samples.append({
            "id": f"jailbreakbench-benign-{i:05d}",
            "text": text,
            "label": "benign",
            "category": "benign",
            "source": "jailbreakbench",
        })

    _assert_count("jailbreakbench.json", len(samples))
    path = output_dir / "jailbreakbench.json"
    path.write_text(json.dumps(samples, indent=2, ensure_ascii=False))

    benign_n = sum(1 for s in samples if s["label"] == "benign")
    malicious_n = len(samples) - benign_n
    print(f"jailbreakbench.json: {len(samples)} samples ({benign_n} benign, {malicious_n} malicious)")


def download_advbench(output_dir: Path) -> None:
    """EV-028: AdvBench harmful behaviors (CSV from llm-attacks/llm-attacks)."""
    url = (
        "https://raw.githubusercontent.com/llm-attacks/llm-attacks/"
        f"{_COMMITS['llm_attacks']}/data/advbench/harmful_behaviors.csv"
    )
    with urllib.request.urlopen(url, timeout=30) as resp:
        text = resp.read().decode("utf-8")

    reader = csv.DictReader(io.StringIO(text))
    samples = []
    for i, row in enumerate(reader):
        goal = row.get("goal", "").strip()
        if not goal:
            continue
        samples.append({
            "id": f"advbench-{i:05d}",
            "text": goal,
            "label": "malicious",
            "category": "jailbreak",
            "source": "advbench",
        })

    _assert_count("advbench_harmful.json", len(samples))
    path = output_dir / "advbench_harmful.json"
    path.write_text(json.dumps(samples, indent=2, ensure_ascii=False))
    print(f"advbench_harmful.json: {len(samples)} samples (all malicious)")


def download_spml(output_dir: Path) -> None:
    """EV-029: SPML Chatbot Prompt Injection (sampled 5000)."""
    random.seed(42)
    ds = load_dataset(
        "reshabhs/SPML_Chatbot_Prompt_Injection", split="train",
        revision=_COMMITS["spml_hf"],
    )

    pool: list[tuple[str, bool]] = []
    for row in ds:
        text = (row.get("User Prompt") or "").strip()
        if not text:
            continue
        is_injection = row.get("Prompt injection", 0) == 1
        pool.append((text, is_injection))

    random.shuffle(pool)
    selected = pool[:5000]

    samples = []
    for i, (text, is_inj) in enumerate(selected):
        samples.append({
            "id": f"spml-{i:05d}",
            "text": text,
            "label": "malicious" if is_inj else "benign",
            "category": "prompt_injection" if is_inj else "benign",
            "source": "spml",
        })

    _assert_count("spml_chatbot.json", len(samples))
    path = output_dir / "spml_chatbot.json"
    path.write_text(json.dumps(samples, indent=2, ensure_ascii=False))

    benign = sum(1 for s in samples if s["label"] == "benign")
    malicious = len(samples) - benign
    print(f"spml_chatbot.json: {len(samples)} samples ({benign} benign, {malicious} malicious)")


def download_rubend18(output_dir: Path) -> None:
    """EV-030: Rubend18 ChatGPT Jailbreak Prompts."""
    ds = load_dataset(
        "rubend18/ChatGPT-Jailbreak-Prompts", split="train",
        revision=_COMMITS["rubend18_hf"],
    )

    samples = []
    for i, row in enumerate(ds):
        text = (row.get("Prompt") or "").strip()
        if not text:
            continue
        samples.append({
            "id": f"rubend18-{i:05d}",
            "text": text,
            "label": "malicious",
            "category": "jailbreak",
            "source": "rubend18",
        })

    _assert_count("rubend18_jailbreak.json", len(samples))
    path = output_dir / "rubend18_jailbreak.json"
    path.write_text(json.dumps(samples, indent=2, ensure_ascii=False))
    print(f"rubend18_jailbreak.json: {len(samples)} samples (all malicious)")


def download_satml_ctf(output_dir: Path) -> None:
    """EV-031: SaTML CTF attack interactions (sampled 5000)."""
    random.seed(42)
    ds = load_dataset(
        "ethz-spylab/ctf-satml24", "interaction_chats",
        split="attack", revision=_COMMITS["satml_hf"],
    )

    pool: list[str] = []
    for row in ds:
        if not row.get("is_attack", False):
            continue
        history = row.get("history", [])
        if isinstance(history, str):
            try:
                history = json.loads(history)
            except (json.JSONDecodeError, TypeError):
                continue
        user_msgs = []
        for msg in history:
            if not isinstance(msg, dict):
                continue
            if msg.get("role") == "user":
                content = (msg.get("content") or "").strip()
                if content:
                    user_msgs.append(content)
        if not user_msgs:
            continue
        pool.append("\n".join(user_msgs))

    random.shuffle(pool)
    selected = pool[:5000]

    samples = []
    for i, text in enumerate(selected):
        samples.append({
            "id": f"satml_ctf-{i:05d}",
            "text": text,
            "label": "malicious",
            "category": "jailbreak",
            "source": "satml_ctf",
        })

    _assert_count("satml_ctf.json", len(samples))
    path = output_dir / "satml_ctf.json"
    path.write_text(json.dumps(samples, indent=2, ensure_ascii=False))
    print(f"satml_ctf.json: {len(samples)} samples (all malicious)")


def main() -> None:
    output_dir = Path(__file__).resolve().parent.parent / "datasets" / "external"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Output directory: {output_dir}\n")

    downloaders: list[tuple[str, Callable[[Path], None]]] = [
        ("SafeGuard", download_safeguard),
        ("Deepset", download_deepset),
        ("IvanLeoMK", download_ivanleomk),
        ("CyberSecEval2", download_cyberseceval2),
        ("HarmBench", download_harmbench),
        ("AILuminate", download_ailuminate),
        ("InjecAgent", download_injecagent),
        ("ASB", download_asb),
        ("BIPIA", download_bipia),
        ("Tensor Trust", download_tensor_trust),
        # Harelix: EV-020 blocked -- dataset deleted from HuggingFace.
        ("Jackhhao", download_jackhhao),
        ("WildJailbreak", download_wildjailbreak),
        ("HackAPrompt", download_hackaprompt),
        ("In-the-Wild Jailbreak", download_in_the_wild_jailbreak),
        ("Mindgard Evasion", download_mindgard_evasion),
        ("XSTest", download_xstest),
        ("JailbreakBench", download_jailbreakbench),
        ("AdvBench", download_advbench),
        ("SPML", download_spml),
        ("Rubend18", download_rubend18),
        ("SaTML CTF", download_satml_ctf),
    ]

    failures: list[str] = []
    for name, fn in downloaders:
        try:
            fn(output_dir)
        except Exception as e:
            failures.append(f"{name}: {e}")
            print(f"ERROR: {name} download failed: {e}", file=sys.stderr)

    passed = len(downloaders) - len(failures)
    print(f"\nDone: {passed}/{len(downloaders)} datasets downloaded successfully.")
    if failures:
        print(f"Failed ({len(failures)}):", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
