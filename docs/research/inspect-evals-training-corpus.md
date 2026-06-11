# Inspect Evals — Training Corpus for the Security Judge

- Sister doc: `inspect-evals-aisi-evaluation-framework.md` (catalogue & framework)
- Local mirror: `benchmarks/datasets/inspect_evals/`
- Manifest: `benchmarks/datasets/inspect_evals/MANIFEST.json`
- Collected: 2026-06-02

## Why this exists

The security-judge article notes that LLMTrace's ensemble (regex + DeBERTa
+ InjecGuard + jailbreak classifiers) hit 99 % recall on known jailbreak
sets but missed 498 attacks on a 12,000-prompt adversarial run — most
of them from the SaTML CTF corpus that drove recall to 92 %. The
remediation chosen was an async second-level judge fine-tuned with
SFT + GRPO on Ministral-3B. The bottleneck for that pipeline is **labelled
training data**, especially for label types we currently underrepresent
(multilingual PI, over-refusal counter-examples, agent-surface attacks,
paired adversarial-benign with explicit rubrics).

Inspect Evals catalogues exactly this kind of data, but only as
fetch URLs and HF references inside its `dataset.py` files. This
corpus consolidates those upstream sources into a single, structured,
SHA-pinned mirror in the repo so the judge pipeline can consume them
without re-discovering URLs every time.

## What's in the mirror

- **24 datasets** spanning 7 label-types (binary injection / over-refusal /
  harm refusal / agent OWASP-tagged / code & interpreter abuse / MCQ
  knowledge / multi-turn social-eng).
- Roughly **108,000 records total** (heavy weight on Sycophancy + BBQ
  which are robustness/bias diagnostics rather than primary judge
  training).
- **~50,000 directly judge-relevant samples** (the rest are MCQ
  knowledge or bias diagnostics).
- **115 MB on disk**, 310 files.
- All sources MIT / CC-BY / permissive. `cais/MASK` is HF-gated and
  documented under `mask/README.md` for future fetch.

See `MANIFEST.json` for the per-dataset breakdown — schema, record count,
license, pinned SHA, and `training_use` recommendation.

## How each label type maps to the SFT/GRPO pipeline

### Binary injection (judge says "this is an injection")

- `cyse4_multilingual_pi` (1,004) — 15 variants × translated languages.
  **Directly addresses the SaTML CTF recall gap.**
- `cse2_prompt_injection` (251) — the original PurpleLlama PI set.
- `ipi_coding_agent` (45) — canary-string ground truth for coding-agent
  contexts. Small, but a unique surface (issue text / code comments /
  README / config).

Sample records carry a `judge_question` (e.g. "Did the response reveal
the secret?") that becomes the judge's positive label.

### Over-refusal counter-balance (judge says "this is benign, don't refuse")

- `mitre_frr` (750) — security-themed but malicious-flag mixed. Each
  record has `is_malicious` boolean — perfect SFT label.
- `xstest` (450) — 18 paired types (homonyms / figurative language /
  safe targets / definitions / privacy_fictional…). Every category
  has a `contrast_X` twin set, 25 prompts each.
- `coconot` (1,001 original + 379 contrast + 927 preference pairs) —
  Allen AI's structured non-compliance set. `pref_train` has
  chosen / rejected pairs ready for DPO/GRPO.
- `fortress` (500, **paired**) — every row has BOTH `adversarial_prompt`
  AND `benign_prompt` plus a 4–7-question binary `rubric`. This is the
  cleanest SFT input we have because the polarity is row-paired and the
  grading criteria are explicit.

This category is the most important addition relative to our current
corpus — the article calls out that "over-refusal on a background judge is
worse than a miss" and we currently have no large paired adversarial-vs-
benign set with built-in rubrics.

### Harm / refusal targets

- `strong_reject` (323 forbidden + 60 small) — categorised
  ("Cybersecurity", "Disinformation", "Hate speech", …).
- `agentharm` (44 base × 4 augmentations = 176 harmful + matching benign +
  chat scenarios in test+validation). UK AISI's flagship agent-harm
  corpus.
- `air_bench_2024` (21 of 47 categories pulled) — Stanford CRFM's
  regulation-aligned taxonomy.
- `wmdp` (1,273 bio + 408 chem + 1,987 cyber MCQ) — dangerous-knowledge
  measurement; useful as "should refuse at the knowledge level" signal.

### Agent-surface, OWASP-tagged

- `agent_threat_bench` (10 + 6 + 8) — OWASP Agentic Top-10 IDs;
  per-sample `attack_marker`, `forbidden_actions`,
  `expected_categorizations`, `sensitive_fields`,
  `authorized_recipients`. Sample count is small but the ground-truth
  fidelity is unusually high.
- `b3/threat_snapshots` (20 across 10 app archetypes) — paired
  `_0` / `_1` (no-defense / with-defense) variants; lets us measure
  detector lift directly.
- `agentdojo/suites/` (5 task suites — slack, workspace,
  workspace_plus, banking, travel) — environments + injection vector
  templates; needs the Inspect harness to enumerate concrete samples.

These are small in raw count but rich in metadata — they should be held
out as agent-surface eval rather than mixed into SFT training.

### Code / interpreter abuse

- `cyse4_instruct` (1,916) — "write me insecure code" prompts.
- `cyse4_autocomplete` (1,916) — completion variant.
- `cse2_interpreter` (500) — interpreter-abuse on a code-executing model.
- `cyse4_insecure_code_detector_rules` — semgrep + regex across 13
  languages, drop-in to the deterministic detector layer of the ensemble.

### MCQ knowledge backbone

- `cybermetric` 80 / 500 / 2,000 / 10,000 — 9 cybersecurity domains.
- `sec_qa` v1 (110) + v2 (100).

Use as a domain-knowledge prior; the judge needs to understand the
language of the attacks it's grading.

### Multi-turn / social engineering

- `cyse4_multiturn_phishing` (856) — target profile + goal + platform.
  Multi-turn SE is currently absent from our corpus.

### CTI / threat intelligence

- `cyse4_threat_intel_reasoning` (588) — multi-modal CTI QA.
- `cyse4_malware_analysis` (609) — malware report QA.
- `sevenllm` (1,299 test, bilingual en/zh) — train.jsonl (180 MB) not
  fetched; pull on demand.

### Sycophancy / robustness

- `sycophancy/` (`are_you_sure` 4,887 + `answer` 7,267 + `feedback`
  8,500). Useful as a robustness eval — does the judge soften under
  push-back?

### Bias diagnostics

- `bbq/` (11 demographic subsets, 58,492 records) — for ensuring the
  judge's refusal logic doesn't encode demographic bias.

## Suggested training mix

A first-cut SFT mix (post de-dup, ~10k–20k examples):

| Source                       | Sampling                                      | Approx. count |
| ---------------------------- | --------------------------------------------- | ------------- |
| `cyse4_multilingual_pi`      | all (multilingual coverage is the point)      | 1,004         |
| `cse2_prompt_injection`      | all                                           | 251           |
| `fortress` (both polarities) | all 500 rows × 2 (adv + benign)               | 1,000         |
| `coconot` original + contrast | all (1,001 + 379)                            | 1,380         |
| `xstest`                     | all                                           | 450           |
| `mitre_frr`                  | all                                           | 750           |
| `strong_reject` (full + small) | all                                          | 383           |
| `agentharm` harmful + benign | test_public + validation                      | ~400          |
| `ipi_coding_agent`           | 35 injected, hold 10 benign for eval          | 35            |
| Held-out for eval            | `agent_threat_bench` + `b3` + `agentdojo`     | (eval only)   |

A first-cut GRPO reward mix:

- Positive reward: refusal on `strong_reject` + `agentharm` harmful + `mitre_frr.is_malicious=true` + `fortress.adversarial_prompt`.
- Negative reward: refusal on `xstest` + `coconot.contrast` + `mitre_frr.is_malicious=false` + `fortress.benign_prompt`.
- Tie-break / robustness: sample from `sycophancy/are_you_sure` to
  penalise judge flip-flops under pressure.

The article cautions that early GRPO runs scored well on paper because
95 % of training steps had zero gradient signal. The above mix has more
varied refusal contexts and explicit polarity pairing (FORTRESS, XSTest
contrast, CoCoNot contrast), which should reduce that failure mode.

## Re-fetch / refresh procedure

```bash
# All sources are SHA-pinned in MANIFEST.json. To refresh a single dataset:
cd benchmarks/datasets/inspect_evals
jq -r '.datasets.cyberseceval_4_multilingual_prompt_injection.source' MANIFEST.json
# then curl -L -o <target_path> <that URL>
```

For HF parquet: `https://huggingface.co/datasets/{repo}/resolve/main/{file}`
For gated `cais/MASK`: see `mask/README.md`.

## See also

- `inspect-evals-aisi-evaluation-framework.md` — framework-level catalogue
- `benchmarks-and-tools-landscape.md` — overall LLMTrace eval landscape
- `llmtrace-security-judge/article.md` — the judge training context
  this corpus is sourced for
- `injecguard-over-defence-mitigation.md` — over-refusal background
- `bipia-indirect-prompt-injection-benchmark.md` — IPI baseline
