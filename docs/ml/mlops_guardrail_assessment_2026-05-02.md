# MLOps Guardrail Assessment — 2026-05-02

Scope: priority 5 from the project review; related to `OPS-001` through `OPS-008` in `docs/TODO.md` Loop 23.

## Decision

Do not start DeBERTa fine-tuning, Qwen judge deployment, or default model swaps until the first two guardrails land together:

1. `OPS-002` — pin every HuggingFace model to an immutable revision.
2. `OPS-004` — add a version manifest that records model id, revision, expected artifact checksums, and rollout timestamp.

These must be paired. A manifest without immutable revisions does not prevent silent upstream model drift, and revisions without a manifest do not give operators a rollback surface.

## Current State

- Runtime config exposes model ids and cache dirs for the primary ML detector, NER, InjecGuard, PIGuard, and DeBERTa judge.
- The config does not yet carry revision SHAs or artifact checksums.
- The repository does not contain the exact HuggingFace commit SHAs for the current production model set.

## Blocker

The required revision SHAs and SafeTensors checksums are external facts. Do not invent them. They must be collected from the actual model artifacts used in deployment or from a trusted model-pinning pass against HuggingFace Hub.

## First Implementation PR

Recommended minimal PR scope:

- Add config fields for model revision pins for each model currently loaded from HuggingFace.
- Update model download paths to pass those revisions into `hf-hub` fetches.
- Add a checked-in manifest containing only verified model ids, revision SHAs, and checksums.
- Fail startup when a configured checksum does not match the downloaded SafeTensors file.
- Add unit tests for config deserialization and checksum mismatch handling.

## Why Not a Smaller Guardrail

- `OPS-001` alone only makes thresholds configurable; it does not protect against silent model drift.
- `OPS-003` metrics are valuable, but metrics after a silent model change only detect the drift after traffic is affected.
- `OPS-005` CI gates need pinned artifacts first, otherwise CI can pass against a moving model target.

## Next Action

Collect model revisions and checksums for:

- `protectai/deberta-v3-base-prompt-injection-v2`
- `dslim/bert-base-NER`
- `leolee99/InjecGuard`
- `leolee99/PIGuard`
- any configured DeBERTa fast-judge model if different from the primary detector

After that, implement `OPS-002` + `OPS-004` as a single PR.
