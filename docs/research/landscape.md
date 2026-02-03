# LLMTrace Research Landscape

Last updated: 2026-02-03

This landscape highlights tools, models, and resources relevant to LLMTrace's mission: security-aware observability for LLM systems.

## Curated Defense Resources

Prompt Injection Defenses (tldrsec) is a curated repository that centralizes practical and proposed defenses against prompt injection. This is useful for keeping LLMTrace's taxonomy aligned with current mitigation patterns. Source: https://github.com/tldrsec/prompt-injection-defenses

## Commercial Guardrail Platforms

Lakera Guard documents prompt defenses and additional guardrails such as content moderation, data leakage prevention, and malicious link detection. LLMTrace can normalize these policy signals as external guardrail telemetry. Source: https://docs.lakera.ai/docs/defenses

## Open-Source Guardrail Toolkits

LLM Guard (Protect AI) is a security toolkit for LLM interactions. LLMTrace can integrate its outputs as observability signals. Source: https://github.com/protectai/llm-guard

NeMo Guardrails (NVIDIA) is an open-source toolkit for adding programmable guardrails to LLM-based conversational systems. It is relevant for capturing guardrail decisions and policy flow as telemetry. Source: https://github.com/NVIDIA-NeMo/Guardrails

## Prompt Injection Detection Models

ProtectAI DeBERTa Prompt-Injection v2 is a fine-tuned DeBERTa-v3-base model for prompt injection detection, with a text-classification model card on Hugging Face. It can serve as a baseline detector for LLMTrace pipelines. Source: https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2

Meta Prompt-Guard-86M is a Prompt Guard text-classification model hosted on Hugging Face with a detailed model card describing its use as a classifier for prompt attacks. It can be evaluated as a compact guard model for low-latency scenarios. Source: https://huggingface.co/meta-llama/Prompt-Guard-86M

Meta Llama-Guard-3-8B is a Llama-3.1-8B model fine-tuned for content safety classification, with a model card describing prompt and response classification behavior. It can serve as a high-accuracy guard baseline to compare against smaller detectors in LLMTrace telemetry. Source: https://huggingface.co/meta-llama/Llama-Guard-3-8B

## Research Implementations

InjecGuard provides official code, data, and model weights for the InjecGuard prompt guard model and documents its benchmark focus on benign, malicious, and over-defense accuracy. LLMTrace can use it as a reference model for false-positive calibration. Source: https://github.com/InjecGuard/InjecGuard

