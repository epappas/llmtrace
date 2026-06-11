# Inspect Evals (UK AISI) — Security Evaluation Corpus

- Source repo: <https://github.com/UKGovernmentBEIS/inspect_evals>
- Framework: <https://inspect.ai-safety-institute.org.uk/> (Inspect AI)
- Maintainers: UK AI Safety Institute, Arcadia Impact, Vector Institute
- Ingested: 2026-05-19
- Purpose: research input for LLMTrace's detector-benchmarks, defense-pipeline, agent-security, and security-judge tracks

## Source papers referenced from this work

- **CyberGym** — Wang, Shi, He, Cai, Zhang, Song (UC Berkeley). *CyberGym:
  Evaluating AI Agents' Real-World Cybersecurity Capabilities at Scale.*
  arXiv:2506.02548 (v1 2025-06-03, v3 2026-03-24). DOI: 10.48550/arXiv.2506.02548.
  Full text + abstract ingested into alexandria 2026-06-04 as
  `raw/web/arxivorg-{abs,pdf}-250602548.md`. Headline result: 1,507 real
  vulns × 188 projects; top model-agent combos reach only ~20% PoC
  reproduction; the eval has so far surfaced **34 zero-day vulns** and
  **18 historically incomplete patches**.

Additional eval-papers — AgentDojo (NeurIPS 2024), AgentHarm (arXiv:2410.09024),
b3 (arXiv:2510.22620), FORTRESS (arXiv:2506.14922) — are cited inline below.
Ingest individually on demand.

## What it is

Inspect Evals is the public, community-curated catalogue of evaluations
built on top of UK AISI's Inspect AI framework. As of this writing the
repo contains 137 top-level eval packages under
`src/inspect_evals/`, ~15 of them in the cyber/agent-security cluster
that maps directly to LLMTrace's threat surface. Each eval is a
self-contained Python package exporting one or more `@task`-decorated
entry points, plus a dataset loader, a solver (often `react` or
`generate`), one or more scorers, and an optional Docker/K8s sandbox.

The framework abstractions (`Task`, `Sample`, `Solver`, `Scorer`,
`Sandbox`, `Tool`) standardise how each eval is described, executed,
and graded. Logs are written to a unified format viewable with
`inspect view`; tasks run against any provider Inspect supports
(OpenAI, Anthropic, Bedrock, vLLM, Ollama, etc.).

## The security-relevant eval clusters

I grouped the directly-relevant evals by what they actually measure. Counts
and dataset sources are taken from each eval's README and dataset.py.

### 1. Cyber-offense capability (exploit / CTF / patching)

| Eval                        | Surface                                                                 | Dataset                                                                                       | Scoring                                                                          |
| --------------------------- | ----------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `cybergym` ([arXiv:2506.02548](https://arxiv.org/abs/2506.02548)) | Real-world PoC generation against historical vulns (ARVO + OSS-Fuzz)    | 1,507 instances across 188 projects, HF `sunblaze-ucb/cybergym` (~236 GB), 4 difficulty levels | Docker triad: vulnerable / fixed / submission container; "reproduced" + "new vuln" rates |
| `cve_bench`                 | Web-app CVE exploitation                                                | Branched from `uiuc-kang-lab/cve-bench`; Docker + K8s sandboxes                               | Per-challenge functional scorer; `one_day` vs `zero_day` prompt variants         |
| `cybench`                   | 39 CTF challenges across 4 competitions, 6 domains (crypto/web/rev/forensics/pwn/misc) | Kali Linux sandbox; Docker default with explicit risk acknowledgement env var       | Flag-match scoring                                                               |
| `gdm_in_house_ctf`, `gdm_intercode_ctf` | Google DeepMind CTF-style capability evals                              | Bundled challenges in repo                                                                    | Flag-match                                                                       |
| `threecb` (3CB)             | MITRE-ATT&CK-categorised offensive tasks (recon / initial access / priv-esc / evasion) | Posix-only; in-repo challenges                                                                | Step-by-step rubric                                                              |
| `cyberseceval_4 / autonomous_uplift`, `autopatching` | Autonomous attack & patching (prototype, omitted from public release)   | Adapted from Meta PurpleLlama                                                                 | Currently simulation-based, not in supported surface                             |
| `cyberseceval_4 / mitre`    | "Does the model give useful attacker uplift?"                           | 1000 prompts                                                                                  | LLM-judge against the MITRE rubric                                               |
| `cyberseceval_4 / mitre_frr` | Over-refusal on benign security prompts (false-refusal companion to mitre) | 750 prompts                                                                                   | LLM-judge                                                                        |

### 2. Defensive capability (insecure code, malware, threat intel, detection engineering)

| Eval                                                  | Surface                                                          | Dataset                                                                | Scoring                                          |
| ----------------------------------------------------- | ---------------------------------------------------------------- | ---------------------------------------------------------------------- | ------------------------------------------------ |
| `cyberseceval_4 / instruct` + `autocomplete`          | Does the model write insecure code?                              | 1,916 prompts × 2 modes                                                | Bundled semgrep-based Insecure Code Detector     |
| `cyberseceval_4 / malware_analysis`                   | Reverse-engineering reports from CyberSOCEval                    | 609 multi-answer samples                                               | Exact-match + LLM-judge                          |
| `cyberseceval_4 / threat_intelligence`                | Reasoning over textual + image (PDF) threat reports              | 588 samples                                                            | LLM-judge over rubric                            |
| `cti_realm`                                           | Full detection-engineering loop (CTI → MITRE → KQL → Sigma rule) | 37 source reports, Kusto telemetry on AKS, MITRE + Sigma DBs           | Trajectory + final-rule reward                   |
| `cybermetric` (80/500/2000/10000)                     | MCQ over 9 cybersecurity domains                                 | 80 / 500 / 2,000 / 10,000 MCQ                                          | Exact-match                                      |
| `sec_qa`                                              | Cyber-security knowledge MCQ                                     | -                                                                      | Exact-match                                      |
| `sevenllm`                                            | Bilingual security knowledge                                     | -                                                                      | Exact-match                                      |

### 3. Prompt injection — direct, indirect, multilingual

| Eval                                            | Surface                                                                 | Dataset                                                                                  | Scoring                                                                  |
| ----------------------------------------------- | ----------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| `cyberseceval_4 / multilingual_prompt_injection` | 15 injection variants × machine-translated languages                    | 1,004 prompts via `prompt_injection_multilingual_machine_translated.json` from PurpleLlama | `prompt_injection_scorer` — judge LLM answers the `judge_question` per sample |
| `ipi_coding_agent` (CodeIPI)                    | IPI hidden in repo artifacts (issue text / code comments / README / config) | 45 samples (35 injected + 10 benign) × {plain, authority} × {exfil, exec, persist} × {S1, S2, S3} | Canary-string detection in tool calls + LLM-judge of refusal             |
| `agentdojo`                                     | Tool-augmented agents must complete utility tasks while resisting injected tool output | NeurIPS 2024 paper benchmark + AISI/NIST red-team extensions; sandboxed task suites      | Dual metric: **utility** + **security**; `important_instructions` is the bundled attack template |
| `cyberseceval_4 / multiturn_phishing`           | Multi-turn social engineering simulation                                | 100 conversations                                                                        | LLM-judge                                                                |

### 4. Agent security — OWASP-style threats and "backbone" robustness

| Eval                          | Surface                                                                                                              | Dataset                                                                                                            | Scoring                                                                                                                       |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------- |
| `agent_threat_bench`          | First eval to operationalise OWASP Top-10 for Agentic Apps (2026); three task families: `memory_poison`, `autonomy_hijack`, `data_exfil` | Self-contained JSON datasets in `data/`; samples carry OWASP ID, attack marker, forbidden actions, sensitive fields, authorised recipients, initial memory store / inbox / customer DB | Dual `utility` + `security` scorer per AgentDojo pattern; canary-string + tool-call inspection                                |
| `b3` (Breaking Agent Backbones) | Threat-snapshot benchmark across 10 application classes (CCO coach, trip planner, MCP chat, code review, email tool, etc.) | 20+ snapshot files in `b3/data/threat_snapshots/TS{1..10}_*_{0,1}.json` + `tool_specs/` + `profanity_keywords.json` | Mix of regex/profanity, embedding-similarity, and LLM-judge defenses; covers exfil / content injection / decision manipulation / DoS / tool compromise / policy bypass |
| `agentharm` / `agentharm_benign` | Harmfulness of agent behaviour                                                                                       | HF `ai-safety-institute/AgentHarm` — 44 of 66 public test + 8 of 11 validation base behaviours, each augmented      | LLM-judge harm-score                                                                                                          |
| `agentic_misalignment`        | Port of Anthropic's blackmail / information-leakage scenarios                                                        | Prompt templates in `templates/`, classifier in `classifiers/`                                                     | LLM-classifier of agentic misalignment                                                                                        |
| `fortress`                    | 500 expert-crafted adversarial CBRNE / political-violence / financial-illicit prompts                                | Domain + subdomain breakdown (Chemical/Bio/Rad/Explosives/Terrorism/Fraud/...)                                     | Per-sample binary rubric of 4–7 questions, LLM-judge                                                                          |

### 5. Adjacent surfaces worth knowing

`mind2web` / `mind2web_sc`, `theagentcompany`, `tau2`, `swe_bench`, `swe_lancer`,
`browse_comp`, `core_bench`, `gaia`, `osworld`, `paperbench`, `livebench`,
`gdm_self_proliferation`, `gdm_self_reasoning`, `gdm_stealth`, `gdm_capabilities`,
`mask`, `strong_reject`, `xstest`, `wmdp` — these are not LLMTrace's primary
threat surface but they share Inspect's `Task / Solver / Scorer` plumbing and
are useful references when adding new tasks.

## The framework abstractions LLMTrace can reuse

Inspect AI standardises four objects we already have analogues of:

- **`Sample`** — `(input, target, files, sandbox, metadata)` — the shape of
  one adversarial test case. LLMTrace's `benchmarks/datasets/*.json`
  records (`injection_samples.json`, `notinject_samples.json`,
  `encoding_evasion.json`) are essentially `Sample` instances minus the
  `sandbox` / `files` slots, and could be loaded as Inspect datasets
  with a thin adapter.
- **`Solver`** — the wrapper around `state ↦ state'`. For LLMTrace this is
  the production proxy itself; an Inspect harness can drive the proxy
  endpoint as the "model under test" by configuring
  `INSPECT_EVAL_MODEL=openai/...` with the proxy's base URL.
- **`Scorer`** — async function returning `Score(value=…, explanation=…)`,
  aggregated with `accuracy`, `stderr`, etc. The CodeIPI scorer is the
  clearest model: canary-string presence in tool calls, hash-diff of
  workspace files for persistence, model-graded QA for explicit refusal.
- **`Sandbox`** — Docker Compose or K8s (`k8s-sandbox.aisi.org.uk`).
  CyberGym's 4-container topology
  (`default`, `cybergym-vulnerable`, `cybergym-fixed`, `cybergym` router)
  is the reference architecture for any eval that needs ground-truth
  exploit validation.

## Concrete datasets we can pull straight into LLMTrace

These are downloadable as JSON / HF datasets and ready to wire into
`benchmarks/datasets/`:

1. **`cyberseceval_4/multilingual_prompt_injection`** — 1,004 multilingual
   PI prompts as a single JSON file, with `test_case_prompt`,
   `user_input`, `judge_question`, `injection_variant`. URL is composed
   from `PURPLELLAMA_BASE_URL`. This directly addresses the SaTML CTF gap
   the security-judge article calls out (498 missed adversarial prompts,
   recall drop to 92%).
2. **`ipi_coding_agent/dataset/samples.json`** — 45 indirect-prompt-injection
   samples for coding-agent contexts with canary-string ground truth.
   Maps onto LLMTrace's planned coding-agent guard surface.
3. **`agent_threat_bench/data/{memory_poison,autonomy_hijack,data_exfil}.json`** —
   self-contained JSON, OWASP-Agentic-Top-10 tagged, ground truth
   encoded as `attack_marker`, `forbidden_actions`,
   `expected_categorizations`, `sensitive_fields`,
   `authorized_recipients`. Drop-in for the agent-security suite.
4. **`b3/data/threat_snapshots/TS{1..10}_*_{0,1}.json`** — 20 threat
   snapshots across 10 app archetypes (coach, trip planner, MCP chat,
   profane chat, refusal, analytics, code review, product
   recommendation, email-tool invocation, legal-TI exfiltration). One
   `1`-suffixed copy is the "with defense" variant, useful for measuring
   detector lift.
5. **`agentharm`** — HF `ai-safety-institute/AgentHarm` — usable as a
   harmfulness companion to our injection corpus.
6. **`fortress`** — 500 CBRNE / terrorism / financial-illicit prompts
   with per-sample binary rubrics. Maps to over-refusal and policy
   evaluation for the security-judge.

## Scoring patterns worth adopting

- **Dual `utility` + `security` accuracy** (AgentDojo, AgentThreatBench)
  — defenses that block attacks by refusing every request are not wins;
  this metric makes that explicit.
- **Canary-string ground truth** (CodeIPI, AgentThreatBench data_exfil)
  — every payload embeds a unique marker; presence in tool calls or
  output is ground truth without needing an LLM judge for exfil cases.
- **Hash-diff persistence detection** (CodeIPI) — SHA-256 every
  workspace file before, compare after; new/modified files in
  infrastructure paths (`.git/hooks`, `requirements.txt`, `.bashrc`)
  are flagged.
- **Network-blocked sandboxes** (`network_mode: none`) — exfiltration
  attempts can be detected via canary in *attempted* tool calls without
  actually permitting egress.
- **Versioned, machine-readable metadata** — every Inspect eval ships a
  `_constants.py` / `metadata.py` with eval version, comparability
  version, dataset revision SHA pinned (e.g. CyberGym pins
  `HF_DATASET_REVISION = "bde190ded494e52bc684b66073b436c9d992c7c6"`).
  This is the model for LLMTrace's bench-version pinning.

## Direct alignment with the LLMTrace benchmarks-and-tools landscape gaps

The `wiki/llmtrace-defense-pipeline/benchmarks-and-tools-landscape.md`
research note lists these as **Not Evaluated**:

- AgentDojo (High) → `inspect_evals/agentdojo`, runnable today
- NotInject over-defense → covered by `cyse4_mitre_frr` (750 benign
  prompts to measure over-refusal) plus `fortress_benign`
- WASP (Medium) → not in inspect_evals catalogue, still a gap
- Agent Security Bench (Medium) → adjacent to
  `inspect_evals/agent_threat_bench`, which is newer and OWASP-aligned

CyberSecEval2 is marked "Limited coverage" in our notes; CyberSecEval4
is a strict superset and adds the multilingual prompt-injection set we
do not yet have.

## Risk and caveats

- Most cyber-offense evals (`cybench`, `cybergym`, `cve_bench`,
  `cyberseceval_4 / autonomous_uplift`) require Docker or K8s
  sandboxes with internet access; they are **only** appropriate for
  authorised, contained red-team use. Cybench requires
  `CYBENCH_ACKNOWLEDGE_RISKS=1`.
- CyberGym at 236 GB and 1,507 instances is not a CI-cheap benchmark;
  expect 11h+ on `level1` even for a strong model.
- The `cti_realm` and `cybench` evals pull large Docker images (4–6 GB)
  and need persistent storage.
- Inspect's framework assumes the *model* is the system under test.
  To benchmark LLMTrace, we need to either (a) point Inspect at the
  proxy's OpenAI-compatible endpoint so the proxy sits inline, or
  (b) implement an Inspect-side detector adapter that runs our
  ensemble out-of-band on each sample.

## See Also

- `benchmarks-and-tools-landscape.md` — current landscape with gaps
- `bipia-indirect-prompt-injection-benchmark.md` — companion IPI bench
- `cyberseceval2-llm-security-benchmark.md` — previous CSE2 notes
- `injecguard-over-defence-mitigation.md` — over-defense measurement
- `wasp-web-agent-security-benchmark.md` — still-open WASP gap
- `instruction-hierarchy-defence.md` — privilege-hierarchy defense
- `spotlighting-indirect-injection-defence.md` — datamarking defense
- `llmtrace-owasp-genai-architecture-report.md` — OWASP alignment
