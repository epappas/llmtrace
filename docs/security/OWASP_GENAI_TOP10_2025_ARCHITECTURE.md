# LLMTrace Security Architecture Report: OWASP GenAI Top 10 (2025)

**Date**: 2026-03-07
**Classification**: Internal -- Architecture Reference
**Scope**: Threat model mapping, coverage assessment, defense-in-depth recommendations

---

## 1. Executive Summary

LLMTrace occupies a unique position in the LLM security landscape: a transparent, Rust-native proxy that sits on the critical path between clients, LLM providers, and tool endpoints. This architecture provides unmatched observability over the full request/response lifecycle, making it a natural enforcement point for the OWASP GenAI Top 10 (2025) threat model.

**Current posture**: LLMTrace provides strong coverage for 4 of 10 OWASP categories, partial coverage for 4, and has limited or no coverage for 2. The strongest areas are prompt injection detection (LLM01) and sensitive information disclosure (LLM02), where the multi-model ensemble with regex, DeBERTa, InjecGuard, and PIGuard provides layered detection. The weakest areas are vector/embedding weaknesses (LLM08) and misinformation (LLM09), where the proxy's position provides structural opportunity but no detection logic exists in production today.

**Overall OWASP 2025 coverage score: 6.5/10**

---

## 2. OWASP GenAI Top 10 (2025) -- Category-by-Category Analysis

### 2.1 LLM01: Prompt Injection

**Current Coverage: STRONG (8/10)**

#### 2.1.1 Code References

| Component | File | Function |
|-----------|------|----------|
| Regex injection patterns (40+ patterns) | `crates/llmtrace-security/src/lib.rs` | `build_injection_patterns()` |
| Synonym-expanded patterns | `crates/llmtrace-security/src/lib.rs` | `build_synonym_patterns()` |
| Base64 encoding attack detection | `crates/llmtrace-security/src/lib.rs` | `detect_base64_injection()` |
| Many-shot attack detection | `crates/llmtrace-security/src/lib.rs` | `detect_many_shot_attack()` |
| Repetition attack detection | `crates/llmtrace-security/src/lib.rs` | `detect_repetition_attack()` |
| P2SQL injection patterns | `crates/llmtrace-security/src/lib.rs` | `build_p2sql_patterns()` |
| Header injection patterns | `crates/llmtrace-security/src/lib.rs` | `build_header_patterns()` |
| DeBERTa ML classifier | `crates/llmtrace-security/src/ml_detector.rs` | `MLSecurityAnalyzer` |
| Ensemble analyzer (majority voting) | `crates/llmtrace-security/src/ensemble.rs` | `EnsembleSecurityAnalyzer` |
| InjecGuard auxiliary model | `crates/llmtrace-security/src/injecguard.rs` | `InjecGuardAnalyzer` |
| PIGuard (reduced over-defense) | `crates/llmtrace-security/src/piguard.rs` | `PIGuardAnalyzer` |
| Unicode normalisation (anti-evasion) | `crates/llmtrace-security/src/normalise.rs` | `normalise_text()` |
| Feature-level fusion classifier | `crates/llmtrace-security/src/fusion_classifier.rs` | `FusionClassifier` |
| Feature extraction (heuristic) | `crates/llmtrace-security/src/feature_extraction.rs` | `extract_heuristic_features()` |
| Basic stemming | `crates/llmtrace-security/src/lib.rs` | `basic_stem()`, `stem_text()` |
| Adversarial defense pipeline | `crates/llmtrace-security/src/adversarial_defense.rs` | `AdversarialDefense` |
| FPR calibration | `crates/llmtrace-security/src/fpr_calibration.rs` | `ThresholdCalibrator` |
| FPR drift monitoring | `crates/llmtrace-security/src/fpr_monitor.rs` | `FprMonitor` |
| Jailbreak detector | `crates/llmtrace-security/src/jailbreak_detector.rs` | `JailbreakDetector` |
| Operating point thresholds | `crates/llmtrace-security/src/thresholds.rs` | `OperatingPoint`, `ResolvedThresholds` |
| MCP protocol monitoring | `crates/llmtrace-security/src/mcp_monitor.rs` | `McpMonitor` |
| Streaming security monitor | `crates/llmtrace-proxy/src/streaming.rs` | `StreamingSecurityMonitor` |
| Pre-request enforcement | `crates/llmtrace-proxy/src/enforcement.rs` | `evaluate_enforcement()` |

#### 2.1.2 Threat Scenarios Where Proxy Position is Uniquely Valuable

**Direct injection via user messages**: LLMTrace intercepts every user message before it reaches the LLM provider. The ensemble pipeline (regex + DeBERTa + optional InjecGuard/PIGuard) analyses the full message content after Unicode normalisation, providing defense that is independent of the LLM provider's own safety mechanisms. This is valuable because provider-side defenses vary widely and are opaque.

**Indirect injection via tool outputs**: The `ToolOutputSanitizer` in `crates/llmtrace-security/src/tool_firewall.rs` scans tool responses for embedded injection instructions before they are passed back to the agent. Since LLMTrace mediates tool calls, it can strip malicious content at the trust boundary -- the exact approach that the ServiceNow/Mila paper demonstrated achieves 0% ASR.

**Encoding-based evasion**: The `detect_base64_injection()` method decodes base64 candidates and scans the decoded content, catching encoding attacks that bypass text-level analysis. The Unicode normalisation layer in `normalise.rs` defeats homoglyph, zero-width, Braille, upside-down text, diacritics, and emoji-smuggling attacks.

**Multi-turn extraction**: The `SessionAnalyzer` in `crates/llmtrace-security/src/session_analyzer.rs` tracks cross-request state per session, detecting progressive escalation, topic shifts correlating with rising risk scores, and cumulative risk thresholds.

**Streaming injection**: The `StreamingSecurityMonitor` runs regex-based analysis incrementally during SSE streaming, catching injection patterns as they arrive rather than waiting for the complete response.

#### 2.1.3 Detection Strategies to Implement

1. **Perplexity-based anomaly detection for GCG strings**: The Agent-as-a-Proxy paper (arXiv 2602.05066, Feb 2026) demonstrates that GCG-optimized adversarial strings bypass monitoring-based defenses at 90%+ ASR. These strings have characteristically high perplexity. Implementing a perplexity scorer as a pre-filter would detect adversarial suffixes before they reach the ML classifiers.

2. **Boundary token injection**: The BIPIA benchmark shows that injecting `<data>`/`</data>` boundary tokens around external content reduces indirect injection ASR by 1064% in ablation studies. LLMTrace's proxy position allows it to inject these tokens transparently.

3. **Position-aware detection weighting**: BIPIA's analysis shows end-of-content injections are most effective. Applying higher risk scores to injection patterns detected near the end of tool outputs or retrieved content would improve detection of the most dangerous injection placement.

4. **Multi-language injection expansion**: The current `multilingual_ignore` pattern covers 4 languages. Extending to cover Mandarin, Japanese, Korean, Arabic, and Portuguese injection patterns would close a gap against multilingual evasion.

#### 2.1.4 Defense-in-Depth Recommendations

- **Layer 1 (Pre-processing)**: Unicode normalisation (already implemented in `normalise.rs`).
- **Layer 2 (Heuristic)**: Regex + synonym + stemmed pattern matching (already implemented).
- **Layer 3 (ML Classification)**: DeBERTa ensemble with InjecGuard/PIGuard (already implemented).
- **Layer 4 (Feature Fusion)**: Feature-level fusion via `FusionClassifier` for improved recall (+6% F1 on hard datasets).
- **Layer 5 (Policy Enforcement)**: `evaluate_enforcement()` in `enforcement.rs` supports log/block/flag modes with per-category overrides.
- **Layer 6 (Structural Defense)**: Boundary token injection at tool-call boundaries (to implement).
- **Layer 7 (Session-level)**: `SessionAnalyzer` for multi-turn extraction detection.
- **Layer 8 (Async Review)**: LLM-judge models for high-risk requests flagged by the ensemble (to implement).

#### 2.1.5 Gaps That LLMTrace Cannot Address

- **Model-internal safety alignment**: LLMTrace cannot modify the LLM's internal representation of instructions. If an injection reaches the model after all proxy-level checks, the model's own alignment is the final defense.
- **Semantic injection without syntactic markers**: Attacks that achieve goal hijacking through pure semantic manipulation (no detectable keywords, no structural patterns) will evade both regex and pattern-trained ML classifiers. Only LLM-judge models can catch these, at significant latency cost.
- **Provider-side prompt caching**: If the upstream provider caches poisoned prompts from a prior session, LLMTrace cannot detect or clear that state.

---

### 2.2 LLM02: Sensitive Information Disclosure

**Current Coverage: STRONG (8/10)**

#### 2.2.1 Code References

| Component | File |
|-----------|------|
| PII regex patterns (email, phone, SSN, CC, IBAN, UK NIN, EU passports, international phone, NHS, Canadian SIN, Australian TFN) | `crates/llmtrace-security/src/lib.rs` -- `build_pii_patterns()` |
| PII validation (Luhn, IBAN checksum) | `crates/llmtrace-security/src/pii_validation.rs` |
| NER-based PII detection (BERT NER) | `crates/llmtrace-security/src/ner_detector.rs` |
| Secret scanning (JWT, AWS keys, GitHub tokens, GCP SA, Slack, SSH private keys, generic API keys) | `crates/llmtrace-security/src/lib.rs` -- `build_leakage_patterns()` |
| Data leakage response scanning | `crates/llmtrace-security/src/lib.rs` -- `analyze_response()` |
| Output analyzer (PII + secrets in responses) | `crates/llmtrace-security/src/output_analyzer.rs` |
| Compliance reporting (SOC2, GDPR, HIPAA) | `crates/llmtrace-proxy/src/compliance.rs` |

#### 2.2.2 Threat Scenarios Where Proxy Position is Uniquely Valuable

**PII leakage in LLM responses**: LLMTrace scans both request and response content for PII patterns. Since the proxy sees the full response before it reaches the client, it can detect and optionally redact PII that the LLM generated -- this is something application-level SDK guards cannot do for streaming responses.

**Credential exfiltration**: The secret scanning patterns detect JWT tokens, AWS access keys, GitHub tokens, SSH private keys, and other credentials. When applied to response content, this catches cases where the LLM inadvertently includes credentials from its training data or context.

**Cross-tenant data leakage**: LLMTrace's multi-tenant architecture with tenant isolation via `TenantId` ensures that security findings and audit trails are scoped per tenant. The rate limiter and cost cap systems also operate per-tenant, preventing one tenant's traffic from affecting another's.

#### 2.2.3 Detection Strategies to Implement

1. **Context-aware PII confidence boosting**: Following the Presidio approach, when a PII pattern match occurs near contextual keywords (e.g., "customer ID" near a 10-digit number), boost confidence. When the same pattern appears in a code context (e.g., a hex constant), suppress confidence.

2. **PII in structured output fields**: Scan JSON response fields for PII in structured output (function call results, tool_use blocks), not just prose text.

3. **Gradual disclosure detection**: Track PII disclosure across a session. If an LLM reveals partial PII in turn 1 and the remainder in turn 3, the `SessionAnalyzer` should flag the cumulative disclosure.

#### 2.2.4 Defense-in-Depth Recommendations

- **Input-side**: Detect PII in user messages (warn or redact before sending to LLM).
- **Response-side**: Scan LLM responses for PII and secrets; block or redact critical findings.
- **Storage-side**: Hash or redact PII in audit logs (configurable via storage settings).
- **Compliance**: Use `compliance.rs` reporting endpoints to generate SOC2/GDPR/HIPAA evidence.

#### 2.2.5 Gaps

- **Contextual PII in natural language**: "My friend John who lives on Oak Street" -- named entity PII embedded in prose without structural markers is partially addressed by NER but has lower recall than structured PII.
- **Image/multimodal PII**: No support for detecting PII in image inputs (e.g., screenshots of documents).
- **Custom entity types**: No plugin architecture for organization-specific sensitive data (e.g., internal project codes, customer account formats).

---

### 2.3 LLM03: Supply Chain

**Current Coverage: MINIMAL (2/10) -- Structurally Out of Scope**

#### 2.3.1 Code References

LLMTrace does not directly address supply chain security. However, several architectural features provide partial mitigation:

| Component | Relevance |
|-----------|-----------|
| `deny.toml` (cargo-deny config) | Dependency vulnerability scanning for the proxy itself |
| `Dockerfile` hardening (non-root user) | Container supply chain integrity |
| ML model download from HuggingFace Hub with cache dir | Model provenance, but no integrity verification |

#### 2.3.2 Threat Scenarios Where Proxy Position is Uniquely Valuable

**Model swapping detection**: LLMTrace can log the model identifier returned by the upstream provider in each response. If the provider silently swaps a model version (e.g., from gpt-4o to a fine-tuned variant), the proxy could detect the discrepancy.

**Plugin/tool enumeration**: The `ToolRegistry` in `crates/llmtrace-security/src/tool_registry.rs` maintains a registered tool inventory. The `McpMonitor` validates MCP server URIs against an allowlist, detecting unauthorized tool sources.

#### 2.3.3 Detection Strategies to Implement

1. **Model fingerprinting**: Compare response characteristics (vocabulary distribution, response length patterns, token probabilities if available) against expected baselines for the declared model. Anomalies could indicate model substitution.

2. **Model integrity hashing**: For locally loaded ML models (DeBERTa, InjecGuard, etc.), verify SHA-256 checksums of model weights at load time against pinned values in configuration.

3. **Dependency attestation**: Integrate SLSA or Sigstore verification for model artifacts downloaded from HuggingFace Hub.

#### 2.3.4 Defense-in-Depth Recommendations

- LLMTrace should not be the primary supply chain control. Pair with: cargo-deny/cargo-audit for Rust dependencies, container image scanning (Trivy) in CI, SBOM generation, and provider contract SLAs for model version guarantees.

#### 2.3.5 Gaps

- LLMTrace cannot verify the integrity of upstream LLM provider models or training data.
- No runtime detection of compromised plugins or data sources beyond MCP server allowlisting.
- Model weight integrity verification at download time is not currently enforced.

---

### 2.4 LLM04: Data and Model Poisoning

**Current Coverage: MINIMAL (2/10) -- Structurally Limited**

#### 2.4.1 Code References

No direct implementation. Partial mitigation through:

| Component | Relevance |
|-----------|-----------|
| `ToolOutputSanitizer` | Strips malicious content from tool outputs before they reach the model context |
| `ToolInputMinimizer` | Reduces attack surface by stripping unnecessary context from tool inputs |
| `McpMonitor` schema validation | Detects injection in tool descriptions that could poison agent behavior |

#### 2.4.2 Threat Scenarios Where Proxy Position is Uniquely Valuable

**RAG content poisoning at retrieval time**: When agents use retrieval tools, LLMTrace mediates the retrieved content. The `ToolOutputSanitizer` can strip injection patterns from retrieved documents, preventing poisoned RAG content from corrupting the model's response generation.

**Training data leakage detection**: While LLMTrace cannot prevent training data poisoning, it can detect when a model generates content that appears to be memorized training data (e.g., verbatim reproduction of copyrighted text, exact code from open-source repos with license-incompatible use).

#### 2.4.3 Detection Strategies to Implement

1. **Retrieval quality monitoring**: Log similarity scores between queries and retrieved documents. Anomalously high or low similarity may indicate embedding manipulation.

2. **Output consistency checking**: For deterministic queries, compare responses across time. Significant drift may indicate model poisoning or unauthorized fine-tuning.

#### 2.4.4 Defense-in-Depth Recommendations

- Data poisoning defense primarily requires controls at the training pipeline level, which is outside LLMTrace's scope.
- LLMTrace's contribution is at the runtime inference boundary: sanitizing inputs to and outputs from models, and logging all interactions for forensic analysis.

#### 2.4.5 Gaps

- Cannot detect backdoors or trojans in model weights.
- Cannot verify training data integrity.
- No statistical analysis of response distribution shifts over time.

---

### 2.5 LLM05: Improper Output Handling

**Current Coverage: MODERATE (6/10)**

#### 2.5.1 Code References

| Component | File |
|-----------|------|
| Output analyzer (composite pipeline) | `crates/llmtrace-security/src/output_analyzer.rs` |
| Toxicity detection (BERT-based, 6 categories) | `crates/llmtrace-security/src/toxicity_detector.rs` |
| Hallucination detection (cross-encoder) | `crates/llmtrace-security/src/hallucination_detector.rs` |
| Code security analysis (SQL injection, command injection, XSS, hardcoded creds, insecure crypto) | `crates/llmtrace-security/src/code_security.rs` |
| Data leakage in responses (system prompt leak, credential leak) | `crates/llmtrace-security/src/lib.rs` -- `build_leakage_patterns()` |
| Streaming output analysis | `crates/llmtrace-proxy/src/streaming.rs` -- `StreamingSecurityMonitor` |
| Enforcement (block critical findings in responses) | `crates/llmtrace-proxy/src/enforcement.rs` |

#### 2.5.2 Threat Scenarios Where Proxy Position is Uniquely Valuable

**XSS via LLM output**: If an LLM generates HTML/JavaScript that a downstream application renders without sanitization, XSS is possible. The `code_security.rs` module detects `innerHTML`, `document.write()`, and `dangerouslySetInnerHTML` patterns in code blocks within responses.

**Command injection via generated code**: The code security analyzer detects `os.system()`, `eval()`, `subprocess.run()` with shell=True, and similar patterns in LLM-generated code, flagging code that a downstream system might execute unsafely.

**SSRF via generated URLs**: When the LLM generates URLs that a downstream system will fetch, the proxy can detect internal IP ranges (`10.x`, `172.16.x`, `192.168.x`, `169.254.x`) and localhost references in response content.

#### 2.5.3 Detection Strategies to Implement

1. **SQL injection in generated queries**: Extend code security analysis to detect UNION-based, boolean-based, and time-based SQL injection patterns in SQL code blocks the LLM generates.

2. **Path traversal in file paths**: Detect `../` sequences in file paths the LLM suggests, particularly in tool call arguments.

3. **Structured output schema validation**: When the API response contains structured JSON (function calls, tool_use), validate that output conforms to the declared schema. Unexpected fields or types may indicate output manipulation.

#### 2.5.4 Defense-in-Depth Recommendations

- **Proxy layer**: LLMTrace scans response content for dangerous patterns before forwarding to the client.
- **Application layer**: Applications must still sanitize LLM output before rendering (HTML escaping, parameterized queries, sandboxed code execution). LLMTrace cannot guarantee application-level safety.
- **Content-Security-Policy**: Applications receiving LLM output should set strict CSP headers independent of proxy-level scanning.

#### 2.5.5 Gaps

- **No real-time output blocking during streaming**: The streaming monitor detects patterns but does not currently terminate the SSE stream on detection. Early-stopping capability is designed but not fully deployed.
- **No SSRF detection in response content**: Missing detection for internal IP ranges and localhost in generated URLs.
- **Template injection**: No detection for server-side template injection patterns (Jinja2, Moustache, etc.) in LLM output.

---

### 2.6 LLM06: Excessive Agency

**Current Coverage: STRONG (7/10)**

#### 2.6.1 Code References

| Component | File |
|-----------|------|
| Tool firewall (input minimizer + output sanitizer + format constraints) | `crates/llmtrace-security/src/tool_firewall.rs` |
| Tool registry (categories, rate limiting, allowlisting) | `crates/llmtrace-security/src/tool_registry.rs` |
| Action policy engine (allowlist enforcement, context minimization) | `crates/llmtrace-security/src/action_policy.rs` |
| Action correlator (multi-step action tracking) | `crates/llmtrace-security/src/action_correlator.rs` |
| Multi-agent defense pipeline (trust levels, privilege boundaries) | `crates/llmtrace-security/src/multi_agent.rs` |
| MCP protocol monitor (server allowlist, tool shadowing, schema injection) | `crates/llmtrace-security/src/mcp_monitor.rs` |
| Agent action analysis in regex analyzer | `crates/llmtrace-security/src/lib.rs` -- dangerous command, URL, and file access detection |

#### 2.6.2 Threat Scenarios Where Proxy Position is Uniquely Valuable

**Unauthorized tool invocation**: The `PolicyEngine` in `action_policy.rs` enforces that agents can only invoke tools from a predefined allowlist. Since LLMTrace mediates all tool calls, unauthorized tool invocations are blocked before execution. The enforcement mode can be set to Audit, Enforce, or Adaptive.

**Privilege escalation across tool calls**: The `ActionCorrelator` tracks sequences of tool calls within a session. If an agent's tool usage pattern escalates in privilege (e.g., read -> write -> delete -> admin), the correlator flags the escalation.

**Multi-agent trust boundary violations**: The `MultiAgentDefensePipeline` assigns trust levels (Untrusted, Moderate, Trusted) to agents and applies proportional scanning intensity. Inter-agent communication is monitored for injection attempts.

**MCP tool shadowing**: The `McpMonitor` detects when a tool name is registered by multiple MCP servers, which could indicate a tool shadowing attack where a malicious server replaces a legitimate tool.

#### 2.6.3 Detection Strategies to Implement

1. **Intent verification**: Before executing high-risk tool calls (file writes, network requests, database mutations), verify that the tool call aligns with the user's original intent by comparing tool arguments against the user's prompt.

2. **Dynamic capability adjustment**: Reduce available tools as session risk score increases. If prompt injection is suspected, disable high-privilege tools for the remainder of the session.

3. **Confirmation gates for destructive actions**: The defense pipeline design document specifies "require confirmation" as an action type. Implementing this for destructive operations (delete, overwrite, send-email) would provide human-in-the-loop control.

#### 2.6.4 Defense-in-Depth Recommendations

- **Tool allowlisting**: Use `ActionPolicy::restrictive()` in production to deny-by-default.
- **Rate limiting per tool**: `ActionRateLimiter` in `tool_registry.rs` limits tool invocation frequency per tool per session.
- **Least privilege**: Use `ToolInputMinimizer` to strip unnecessary context from tool call arguments.
- **Output sanitization**: `ToolOutputSanitizer` removes injection patterns from tool responses before they return to the agent context.

#### 2.6.5 Gaps

- **No semantic intent matching**: The proxy cannot verify whether a tool call's semantic purpose matches the user's intent -- only whether the tool is on the allowlist and the arguments pass schema validation.
- **No rollback capability**: If a tool action has already been executed (e.g., email sent, file deleted), LLMTrace cannot undo it. The proxy can only prevent or flag, not remediate post-execution.

---

### 2.7 LLM07: System Prompt Leakage

**Current Coverage: MODERATE (7/10)**

#### 2.7.1 Code References

| Component | File |
|-----------|------|
| System prompt leak detection in responses | `crates/llmtrace-security/src/lib.rs` -- `system_prompt_leak` pattern |
| Prompt extraction attempt detection in requests | `crates/llmtrace-security/src/lib.rs` -- `reveal_system_prompt`, `prompt_extraction`, `system_prompt_says` patterns |
| Canary token system | `crates/llmtrace-security/src/canary.rs` |
| Session-based extraction probing detection | `crates/llmtrace-security/src/session_analyzer.rs` |

#### 2.7.2 Threat Scenarios Where Proxy Position is Uniquely Valuable

**Canary token detection**: The `CanaryTokenStore` in `canary.rs` generates cryptographically random tokens that are injected into system prompts. If any canary token appears in an LLM response, it is conclusive evidence of system prompt leakage. The proxy position allows automatic injection on the request side and automatic detection on the response side -- completely transparent to the application.

**Multi-turn extraction detection**: The `SessionAnalyzer` detects gradual extraction attacks where an attacker asks seemingly innocuous questions across multiple turns, each revealing a small piece of the system prompt. It tracks extraction probe patterns, topic shifts correlating with rising risk, and cumulative risk scores.

**Response-side leak detection**: The `system_prompt_leak` pattern in `build_leakage_patterns()` detects response content that explicitly frames itself as a system prompt disclosure (e.g., "My system prompt says:").

#### 2.7.3 Detection Strategies to Implement

1. **System prompt fingerprinting**: Hash the system prompt content and check if any significant substring of the hash-fingerprinted content appears in responses. This is more robust than canary tokens against paraphrased leakage.

2. **Semantic similarity between system prompt and response**: When the proxy has access to the system prompt (from the request), compute a similarity score between the system prompt and the response. High similarity indicates potential leakage even without exact text matches.

3. **Structured query defense**: Automatically wrap user messages in structured formats (e.g., XML tags, JSON) that make it harder for injection attacks to break out of the user context and access the system prompt.

#### 2.7.4 Defense-in-Depth Recommendations

- **Canary tokens** (implemented): Inject per-session canary tokens for definitive leakage detection.
- **Pattern detection** (implemented): Detect both extraction attempts in requests and leakage patterns in responses.
- **Session analysis** (implemented): Track multi-turn extraction probing.
- **Prompt isolation** (to implement): Automatically restructure requests to isolate system prompts from user-controllable content.

#### 2.7.5 Gaps

- **Paraphrased leakage**: If the model paraphrases the system prompt rather than quoting it verbatim, neither canary tokens nor regex patterns will detect it.
- **Indirect leakage via behavior**: An attacker can infer system prompt content by observing the model's behavioral constraints without the model ever explicitly disclosing the prompt text.

---

### 2.8 LLM08: Vector and Embedding Weaknesses

**Current Coverage: LOW (2/10)**

#### 2.8.1 Code References

No dedicated implementation. Partial relevance:

| Component | Relevance |
|-----------|-----------|
| `ToolOutputSanitizer` | Sanitizes content retrieved by RAG tools, mitigating poisoned retrieval |
| `McpMonitor` | Monitors for injection in tool schemas that could manipulate retrieval behavior |

#### 2.8.2 Threat Scenarios Where Proxy Position is Uniquely Valuable

**RAG poisoning at the retrieval boundary**: When agents retrieve documents via tools (vector search, web search), LLMTrace mediates the returned content. The `ToolOutputSanitizer` can strip embedded injection instructions from retrieved documents before they enter the model context. This is the most practical defense against embedding manipulation, since the proxy cannot inspect the vector database internals but can sanitize the output.

**Anomalous retrieval patterns**: The proxy can log similarity scores and document counts from retrieval tool calls. Statistical anomalies (e.g., retrieval returning unusually high similarity for a query, or returning documents with markedly different semantic content than the query) may indicate embedding poisoning.

#### 2.8.3 Detection Strategies to Implement

1. **Retrieval consistency monitoring**: Track the distribution of retrieval similarity scores per tenant over time. Alert on statistical deviations that may indicate embedding space manipulation.

2. **Document provenance tracking**: Log the source URIs/IDs of retrieved documents. Detect when previously unseen documents suddenly dominate retrieval results.

3. **Cross-encoder re-ranking validation**: Use a cross-encoder model (similar to the hallucination detector's architecture) to independently score the relevance of retrieved documents against the query. Discrepancies between the vector search ranking and cross-encoder ranking may indicate embedding manipulation.

#### 2.8.4 Defense-in-Depth Recommendations

- LLMTrace's primary contribution is at the retrieval output boundary: sanitizing retrieved content.
- Embedding integrity controls must be implemented at the vector database level (e.g., document provenance metadata, embedding versioning, access controls on vector write operations).
- Consider data tagging approaches from the BIPIA research -- wrapping retrieved content in explicit boundary tokens.

#### 2.8.5 Gaps

- Cannot inspect or validate embedding space integrity.
- Cannot detect embedding drift or manipulation within vector databases.
- No cross-encoder re-ranking for retrieval validation.

---

### 2.9 LLM09: Misinformation

**Current Coverage: MODERATE (5/10)**

#### 2.9.1 Code References

| Component | File |
|-----------|------|
| Hallucination detector (two-stage: sentinel + cross-encoder) | `crates/llmtrace-security/src/hallucination_detector.rs` |
| Output analyzer (integrates hallucination + toxicity + PII) | `crates/llmtrace-security/src/output_analyzer.rs` |

#### 2.9.2 Threat Scenarios Where Proxy Position is Uniquely Valuable

**Factual inconsistency detection**: The `HallucinationDetector` implements a two-stage pipeline. Stage 1 (sentinel) uses a lightweight heuristic to determine if a response needs fact-checking. Stage 2 splits the response into sentences and scores each against the user's prompt using a cross-encoder model (e.g., `vectara/hallucination_evaluation_model`), producing per-sentence factual-consistency scores.

**Tool-grounded fact verification**: As noted in the HaluGate research, a proxy that sees both tool-call results and LLM responses is in the ideal position to verify that the model's response is consistent with the data returned by its tools. This is a structural advantage over application-level guards.

#### 2.9.3 Detection Strategies to Implement

1. **Tool-output grounding**: Compare factual claims in the response against the actual data returned by tool calls in the same session. Flag responses that contradict their own data sources.

2. **Citation validation**: When the model claims sources or references, verify that cited URLs exist and that the claimed content matches the actual content (at least at a semantic level).

3. **Confidence calibration for factual claims**: Use the cross-encoder scores to assign confidence levels to factual claims. Low-confidence claims could be annotated rather than blocked.

#### 2.9.4 Defense-in-Depth Recommendations

- **Proxy layer**: Hallucination detection on response content, with configurable thresholds for blocking vs. flagging.
- **Application layer**: Applications should present LLM outputs with appropriate uncertainty indicators. LLMTrace can provide hallucination scores as response metadata.
- **Human review**: Flag responses with low factual-consistency scores for human review rather than automatically blocking.

#### 2.9.5 Gaps

- Hallucination detection is inherently incomplete: the cross-encoder can only detect inconsistency with the provided context, not factual incorrectness against world knowledge.
- No citation verification mechanism.
- High latency cost for per-sentence cross-encoder scoring on long responses.

---

### 2.10 LLM10: Unbounded Consumption

**Current Coverage: STRONG (7/10)**

#### 2.10.1 Code References

| Component | File |
|-----------|------|
| Per-tenant rate limiting (token bucket) | `crates/llmtrace-proxy/src/rate_limit.rs` |
| Cost cap enforcement (per-request token caps + budget caps) | `crates/llmtrace-proxy/src/cost_caps.rs` |
| Context flooding detection (length, repetition, entropy, invisible chars) | `crates/llmtrace-security/src/lib.rs` -- constants and detection at lines 318-337 |
| Circuit breaker (degrades to pass-through on failure) | `crates/llmtrace-proxy/src/circuit_breaker.rs` |
| Max request size enforcement | `config.yaml` -- `max_request_size_bytes` |
| Streaming metrics (TTFT, token count) | `crates/llmtrace-proxy/src/streaming.rs` |
| Cost tracking and accounting | `crates/llmtrace-proxy/src/cost.rs` |
| Anomaly detection | `crates/llmtrace-proxy/src/anomaly.rs` |

#### 2.10.2 Threat Scenarios Where Proxy Position is Uniquely Valuable

**Denial-of-wallet attacks**: The `CostCapEnforcer` in `cost_caps.rs` implements pre-request budget checks with configurable windows (hourly, daily, monthly). Hard limits reject requests that would exceed the budget; soft limits warn but allow. The proxy's position ensures that cost controls are enforced regardless of which application or user is making the request.

**Context window flooding**: The context flooding detection constants in `lib.rs` detect inputs exceeding 100K characters, word 3-gram repetition ratios above 0.60, Shannon entropy below 2.0 bits/char (indicating repetitive or low-information content), invisible character ratios above 0.30, and repeated lines appearing 20+ times.

**Rate limiting**: The token bucket rate limiter supports per-tenant overrides and is backed by Redis for cross-instance state sharing.

#### 2.10.3 Detection Strategies to Implement

1. **Token-level cost prediction**: Before forwarding a request, estimate the expected response token count based on the prompt type and model, and check whether the predicted cost would exceed remaining budget.

2. **Streaming cost accumulation**: Track token consumption during streaming responses and terminate the stream if the accumulated cost exceeds the per-request token cap.

3. **Anomalous usage pattern detection**: The `anomaly.rs` module can track per-tenant usage patterns and alert on statistical anomalies (e.g., sudden 10x increase in request volume, unusual model selection patterns).

#### 2.10.4 Defense-in-Depth Recommendations

- **Request-level**: Max request size, context flooding detection, token cap per request.
- **Session-level**: Rate limiting per tenant, cumulative cost tracking.
- **Budget-level**: Hard and soft budget caps with configurable windows.
- **Infrastructure-level**: Circuit breaker for proxy resilience under load.

#### 2.10.5 Gaps

- **No streaming cost cutoff**: During streaming, the proxy cannot currently terminate a response mid-stream based on accumulated token cost.
- **No predictive cost estimation**: Cannot estimate response cost before forwarding the request.
- **No per-model cost differentiation**: All models are treated equally for rate limiting; expensive models should have tighter limits.

---

## 3. Threat Model of LLMTrace Itself

LLMTrace is itself a security-critical component. Its compromise would undermine all downstream protections.

### 3.1 Attack Surface

| Surface | Threat | Current Mitigation | Residual Risk |
|---------|--------|--------------------|---------------|
| **Proxy listener (port 8080)** | Network-level attacks (DoS, packet injection) | Rate limiting, max request size, connection limits | Medium -- no WAF in front of proxy by default |
| **API key authentication** | Key theft, brute force | SHA-256 hashing, 256-bit random keys, RBAC per key | Low -- keys are strong, but no rotation automation |
| **ML model loading** | Model tampering, supply chain attack | HuggingFace Hub download with cache | Medium -- no integrity verification at load time |
| **Configuration file** | Config injection, permission escalation | File-system permissions | Low -- standard file security |
| **Storage backends (ClickHouse, Postgres, Redis)** | Data exfiltration, injection | Connection URLs in config, no at-rest encryption by default | Medium -- depends on deployment |
| **TLS termination** | MITM, certificate issues | Optional TLS for proxy listener; upstream TLS to providers | Medium -- TLS is optional, not mandatory |
| **Admin API endpoints** | Unauthorized access | API key with role-based access | Medium -- no IP allowlisting |
| **Regex engine** | ReDoS (Regular Expression Denial of Service) | Compiled regexes using the `regex` crate (no backtracking) | Low -- Rust `regex` crate uses finite automata |
| **Candle ML inference** | Adversarial model inputs causing crashes | Model input length limits, error handling | Low -- Candle is memory-safe |
| **SSE stream parsing** | Malformed SSE causing parser state corruption | Structured parsing in `streaming.rs` | Low |

### 3.2 Self-Protection Recommendations

1. **Mandatory TLS**: Make TLS mandatory for the proxy listener in production. The current config has `enable_tls: false` by default.

2. **Model integrity verification**: Pin SHA-256 checksums for all ML model weights in the configuration. Verify at load time before any inference.

3. **Admin API IP allowlisting**: Restrict admin/management API endpoints to specific IP ranges or require mTLS.

4. **API key rotation**: Implement automated key rotation with configurable expiry. Current keys have no expiration.

5. **Secrets management integration**: Store database URLs, API keys, and TLS certificates in a secrets manager (HashiCorp Vault, AWS Secrets Manager) rather than in config files.

6. **Audit logging for proxy operations**: Log all configuration changes, key generations, and enforcement mode changes as audit events.

7. **Resource limits**: Configure memory limits and CPU quotas for the proxy process to prevent resource exhaustion from adversarial inputs that trigger expensive ML inference.

---

## 4. Security Architecture Patterns

### 4.1 Defense-in-Depth with LLMTrace

```
                    Client Application
                           |
                    [WAF / API Gateway]     <-- L1: Network perimeter
                           |
                    [LLMTrace Proxy]        <-- L2: Security analysis + enforcement
                      |          |
              [LLM Provider] [Tools/RAG]    <-- L3: Provider-side safety
                      |          |
              [Response Analysis]           <-- L4: Output safety (toxicity, hallucination, PII)
                      |
              [Application Logic]           <-- L5: Application-level sanitization
                      |
                    End User
```

**L1 -- Network Perimeter**: Deploy a WAF or API gateway in front of LLMTrace for DDoS protection, IP-based access control, and TLS termination. LLMTrace should not be the first point of contact from the public internet.

**L2 -- Security Analysis**: LLMTrace provides the core security analysis layer: prompt injection detection, PII scanning, tool firewalling, rate limiting, cost caps, and enforcement decisions.

**L3 -- Provider Safety**: LLM providers have their own safety mechanisms (content filtering, RLHF alignment). LLMTrace's defenses are additive to, not replacements for, provider-side safety.

**L4 -- Output Safety**: LLMTrace's output analyzer, toxicity detector, hallucination detector, and code security analyzer provide response-side analysis.

**L5 -- Application Logic**: Applications must still implement input validation, output sanitization, parameterized queries, and sandboxed execution for LLM-generated content.

### 4.2 Deployment Topology

**Single-instance (development/testing)**:
- LLMTrace proxy on localhost:8080
- SQLite storage
- In-memory cache for rate limiting
- Direct upstream to LLM provider

**Production (recommended)**:
- Multiple LLMTrace proxy instances behind a load balancer
- Redis for shared rate limiting and cost cap state
- ClickHouse for trace storage and analytics
- PostgreSQL for structured data (audit logs, API keys, compliance reports)
- TLS everywhere (proxy listener, upstream connections, storage connections)

### 4.3 Zero-Trust Architecture for LLM Security

LLMTrace supports zero-trust principles through several mechanisms:

1. **Identity-based access**: Every request requires a valid API key that maps to a tenant and role (`auth.rs`). No implicit trust based on network position.

2. **Least privilege for tools**: The `ActionPolicy::restrictive()` mode denies all tool calls not on the explicit allowlist. Tools are registered with categories and rate limits.

3. **Trust levels for agents**: The `MultiAgentDefensePipeline` assigns trust levels (Untrusted, Moderate, Trusted) with proportional scanning depth.

4. **Continuous verification**: Every request is analyzed, every response is scanned, every tool call is validated -- regardless of prior session history or trust level.

5. **Data minimization**: The `ToolInputMinimizer` strips unnecessary context from tool call arguments, and the `ContextMinimizer` in the policy engine reduces the information available in the agent context.

6. **Encrypted communications**: TLS support for proxy listener, upstream connections to LLM providers use HTTPS by default.

---

## 5. Incident Response Integration

### 5.1 Detection to Response Pipeline

```
Finding Generated (SecurityFinding)
       |
  Enforcement Decision (log / flag / block)
       |
  +----+----+
  |         |
 Log     Alert
  |         |
 Store   Webhook / SIEM
  |         |
 Audit   Incident Ticket
 Trail    |
          |
       Response Playbook
```

### 5.2 Integration Points

| Integration | Mechanism | Status |
|-------------|-----------|--------|
| **SIEM ingestion** | Structured JSON logs with finding metadata, trace IDs | Available via log output |
| **Alerting** | `crates/llmtrace-proxy/src/alerts.rs` | Implemented |
| **Audit trail** | Per-request findings stored in ClickHouse/Postgres | Implemented |
| **Compliance reporting** | SOC2/GDPR/HIPAA report endpoints | Implemented in `compliance.rs` |
| **OpenTelemetry** | `crates/llmtrace-proxy/src/otel.rs` | Implemented |
| **Metrics** | Prometheus-compatible metrics endpoint | Implemented in `metrics.rs` |

### 5.3 Recommended Incident Response Procedures

**Prompt Injection Detected (LLM01)**:
1. Log the finding with full context (trace ID, tenant, request hash, finding details).
2. If enforcement is in "block" mode, return 403 with sanitized error message.
3. Alert security team via SIEM integration for high-severity findings.
4. Review the session history via `SessionAnalyzer` to determine if this is a targeted attack.
5. If pattern is novel, add to regex patterns and retrain/re-threshold ensemble.

**PII Leakage Detected (LLM02)**:
1. Block or redact the response immediately.
2. Log the leakage event as a compliance incident.
3. Generate a GDPR/HIPAA incident report via the compliance API.
4. Notify the data protection officer if legally required.
5. Review whether the PII was from user input, model training data, or tool output.

**System Prompt Leakage Detected (LLM07)**:
1. Block the response.
2. Rotate the canary token for the affected tenant.
3. Investigate whether the extraction was successful or partially successful.
4. Consider rotating the system prompt if full extraction is confirmed.
5. Review session history for multi-turn extraction probing.

---

## 6. Compliance Mapping

### 6.1 SOC2 Trust Service Criteria

| SOC2 Criterion | LLMTrace Coverage |
|----------------|-------------------|
| **CC6.1**: Logical access controls | API key authentication with RBAC, per-tenant isolation |
| **CC6.3**: Access removal | API key revocation via management API |
| **CC7.1**: Detection of unauthorized changes | Audit logging of configuration changes, security findings |
| **CC7.2**: Monitoring | Real-time security analysis, streaming monitoring, alerting |
| **CC7.3**: Evaluation of events | Automated security analysis with severity classification |
| **CC8.1**: Change management | Configuration-driven policy, version-controlled config files |
| **A1.2**: Processing integrity monitoring | Request/response analysis, cost tracking, anomaly detection |
| **PI1.3**: Accuracy and completeness | Hallucination detection, factual consistency scoring |

### 6.2 GDPR Considerations

| GDPR Article | LLMTrace Relevance |
|--------------|-------------------|
| **Art. 5 (Data minimization)** | `ContextMinimizer` and `ToolInputMinimizer` reduce data exposure |
| **Art. 17 (Right to erasure)** | Audit logs with configurable retention; PII hashing in storage |
| **Art. 25 (Data protection by design)** | PII detection and redaction before storage; hash-first storage |
| **Art. 30 (Records of processing)** | GDPR compliance report endpoint; audit trail |
| **Art. 33 (Data breach notification)** | PII leakage detection enables prompt breach identification |
| **Art. 35 (DPIA)** | Security analysis metrics provide input for DPIAs |

### 6.3 EU AI Act Considerations

| AI Act Requirement | LLMTrace Relevance |
|--------------------|-------------------|
| **Risk management system** | Security analysis pipeline with configurable risk thresholds |
| **Data governance** | PII detection, data minimization, audit logging |
| **Technical documentation** | Trace storage provides complete interaction logs |
| **Transparency** | Finding metadata attached to responses (in flag mode); hallucination scores |
| **Human oversight** | "Require confirmation" enforcement action; compliance reports for human review |
| **Accuracy and robustness** | Multi-model ensemble with FPR calibration; adversarial defense module |

---

## 7. Red Team Testing Recommendations

### 7.1 Prompt Injection Testing

| Test Category | Method | Target | Expected Result |
|---------------|--------|--------|-----------------|
| **Direct injection** | Standard OWASP payloads | `EnsembleSecurityAnalyzer` | High detection rate (>90%) |
| **Unicode evasion** | Homoglyphs, zero-width chars, Braille, upside-down text | `normalise_text()` pipeline | Normalisation defeats evasion |
| **Encoding attacks** | Base64-encoded injections | `detect_base64_injection()` | Decoded content flagged |
| **Many-shot attacks** | 5+ Q&A pairs steering model | `detect_many_shot_attack()` | Flagged at threshold >= 3 |
| **GCG adversarial strings** | Optimized adversarial suffixes | ML ensemble | Known gap -- validate if perplexity detection helps |
| **Multilingual injection** | Injections in non-English languages | `multilingual_ignore` pattern | Partial coverage -- test CJK, Arabic |
| **Indirect injection via tools** | Embed injection in tool response content | `ToolOutputSanitizer` | Sanitization removes injection |
| **Multi-turn extraction** | Progressive system prompt extraction across turns | `SessionAnalyzer` | Escalation detection after N turns |
| **MCP tool shadowing** | Register duplicate tool from malicious server | `McpMonitor` | Shadowing alert generated |

### 7.2 Evasion Testing

| Technique | Description | Priority |
|-----------|-------------|----------|
| Character injection | Zero-width, homoglyphs, bidi controls | High -- already defended |
| Token splitting | Breaking keywords across token boundaries | Medium |
| Semantic paraphrasing | Same intent, different wording | High -- hardest to defend |
| Nested encoding | Base64-within-URL-encoding-within-HTML-entities | Medium |
| Context window manipulation | Burying injection in very long benign context | Medium |
| Adversarial ML attacks | TextFooler, BERT-Attack against DeBERTa | High |
| Format manipulation | Markdown, code blocks, tables to hide injection | Medium |

### 7.3 Benchmark Evaluation Priority

1. **NotInject** (false positive rate assessment) -- Critical for production viability
2. **AgentDojo** (97 tool-augmented agent scenarios) -- High for agent security validation
3. **BIPIA** (indirect prompt injection) -- High for RAG security validation
4. **InjecAgent** (adaptive attacks) -- High for robustness validation
5. **CyberSecEval 2** (Meta) -- Medium for broad security evaluation
6. **Agent-as-a-Proxy** (monitoring bypass) -- Critical for validating resilience against adaptive adversaries

---

## 8. OWASP Coverage Summary Matrix

| OWASP 2025 ID | Category | Coverage | Score | Primary Controls | Key Gaps |
|---------------|----------|----------|-------|-----------------|----------|
| **LLM01** | Prompt Injection | Strong | 8/10 | Regex ensemble, DeBERTa, InjecGuard, PIGuard, Unicode normalisation, session analysis, tool firewall | GCG adversarial strings, pure semantic injection |
| **LLM02** | Sensitive Information Disclosure | Strong | 8/10 | PII regex + NER, secret scanning, output analysis, compliance reporting | Contextual NLP-based PII, multimodal PII, custom entities |
| **LLM03** | Supply Chain | Minimal | 2/10 | cargo-deny, Docker hardening, MCP server allowlist | Model integrity verification, dependency attestation |
| **LLM04** | Data and Model Poisoning | Minimal | 2/10 | Tool output sanitization | Training pipeline controls, embedding integrity |
| **LLM05** | Improper Output Handling | Moderate | 6/10 | Code security analysis, toxicity detection, leakage patterns | Streaming output blocking, SSRF detection, template injection |
| **LLM06** | Excessive Agency | Strong | 7/10 | Tool firewall, action policy, action correlator, multi-agent pipeline, MCP monitor | Semantic intent verification, post-execution rollback |
| **LLM07** | System Prompt Leakage | Moderate | 7/10 | Canary tokens, extraction detection, response leak patterns, session analysis | Paraphrased leakage, behavioral inference |
| **LLM08** | Vector/Embedding Weaknesses | Low | 2/10 | Tool output sanitization | Embedding integrity, retrieval anomaly detection |
| **LLM09** | Misinformation | Moderate | 5/10 | Hallucination detector (sentinel + cross-encoder) | Citation verification, world-knowledge grounding |
| **LLM10** | Unbounded Consumption | Strong | 7/10 | Rate limiting, cost caps, context flooding detection, circuit breaker | Streaming cost cutoff, predictive cost estimation |

**Overall OWASP 2025 coverage: 5.4/10 (weighted by threat prevalence and exploitability)**

The strongest areas (LLM01, LLM02, LLM06, LLM10) align well with the threats most commonly encountered in production LLM deployments. The weakest areas (LLM03, LLM04, LLM08) are structurally difficult for a proxy to address and require complementary controls at the training pipeline, infrastructure, and vector database levels.

---

## 9. Priority Recommendations

### Immediate (Next 30 Days)

1. **Enable TLS by default in production configurations**. The current default of `enable_tls: false` leaves the proxy listener unencrypted.

2. **Add model weight integrity verification**. Pin SHA-256 checksums for all ML models in configuration and verify at load time.

3. **Evaluate against NotInject benchmark**. Measure the false positive rate of the current ensemble at production-realistic thresholds (0.1%, 0.5% FPR). This is the most impactful single test for production readiness.

4. **Implement streaming response early-stopping**. When the streaming output monitor detects critical toxicity or PII leakage, terminate the SSE stream immediately rather than logging after completion.

### Short-Term (60-90 Days)

5. **Implement boundary token injection for RAG content**. Automatically wrap tool-retrieved content in `<data>`/`</data>` boundary tokens to reduce indirect injection ASR (1064% improvement per BIPIA ablation).

6. **Add perplexity-based anomaly detection**. Score input text perplexity to detect GCG-optimized adversarial strings and other machine-generated attack payloads.

7. **Implement tool-grounded fact verification**. Compare factual claims in responses against data from tool calls in the same session.

8. **Integrate with a secrets manager** (Vault, AWS SSM) for storing database URLs, API keys, and TLS certificates rather than config files.

### Medium-Term (Q3-Q4 2026)

9. **Evaluate against AgentDojo and BIPIA benchmarks** for agent security and indirect injection defense.

10. **Implement retrieval anomaly monitoring** for LLM08 coverage: track similarity score distributions per tenant.

11. **Add SSRF and template injection detection** in response content for LLM05 coverage.

12. **Implement API key rotation automation** with configurable expiry periods.

---

## 10. Key File Paths for Reference

| File | Purpose |
|------|---------|
| `/root/workspace/spacejar/llmtrace/crates/llmtrace-security/src/lib.rs` | Core regex analyzer with all detection patterns |
| `/root/workspace/spacejar/llmtrace/crates/llmtrace-security/src/ensemble.rs` | Ensemble analyzer combining regex + ML |
| `/root/workspace/spacejar/llmtrace/crates/llmtrace-security/src/ml_detector.rs` | DeBERTa ML classifier |
| `/root/workspace/spacejar/llmtrace/crates/llmtrace-security/src/normalise.rs` | Unicode normalisation (anti-evasion) |
| `/root/workspace/spacejar/llmtrace/crates/llmtrace-security/src/tool_firewall.rs` | Tool-boundary firewalling |
| `/root/workspace/spacejar/llmtrace/crates/llmtrace-security/src/canary.rs` | System prompt leakage canary tokens |
| `/root/workspace/spacejar/llmtrace/crates/llmtrace-security/src/session_analyzer.rs` | Multi-turn session analysis |
| `/root/workspace/spacejar/llmtrace/crates/llmtrace-security/src/output_analyzer.rs` | Output safety pipeline |
| `/root/workspace/spacejar/llmtrace/crates/llmtrace-security/src/toxicity_detector.rs` | Toxicity detection |
| `/root/workspace/spacejar/llmtrace/crates/llmtrace-security/src/hallucination_detector.rs` | Hallucination detection |
| `/root/workspace/spacejar/llmtrace/crates/llmtrace-security/src/code_security.rs` | LLM-generated code security analysis |
| `/root/workspace/spacejar/llmtrace/crates/llmtrace-security/src/action_policy.rs` | Action policy enforcement |
| `/root/workspace/spacejar/llmtrace/crates/llmtrace-security/src/mcp_monitor.rs` | MCP protocol security |
| `/root/workspace/spacejar/llmtrace/crates/llmtrace-security/src/multi_agent.rs` | Multi-agent defense pipeline |
| `/root/workspace/spacejar/llmtrace/crates/llmtrace-security/src/adversarial_defense.rs` | Adversarial ML robustness |
| `/root/workspace/spacejar/llmtrace/crates/llmtrace-proxy/src/enforcement.rs` | Pre-request enforcement decisions |
| `/root/workspace/spacejar/llmtrace/crates/llmtrace-proxy/src/rate_limit.rs` | Per-tenant rate limiting |
| `/root/workspace/spacejar/llmtrace/crates/llmtrace-proxy/src/cost_caps.rs` | Cost cap enforcement |
| `/root/workspace/spacejar/llmtrace/crates/llmtrace-proxy/src/streaming.rs` | SSE streaming security |
| `/root/workspace/spacejar/llmtrace/crates/llmtrace-proxy/src/compliance.rs` | Compliance reporting |
| `/root/workspace/spacejar/llmtrace/crates/llmtrace-proxy/src/auth.rs` | Authentication and RBAC |
| `/root/workspace/spacejar/llmtrace/config.yaml` | Proxy configuration |
| `/root/workspace/spacejar/llmtrace/docs/research/llmtrace-defense-pipeline-design.md` | Defense pipeline architecture |
| `/root/workspace/spacejar/llmtrace/docs/research/security-state-of-art-2026.md` | Security state-of-art analysis |
| `/root/workspace/spacejar/llmtrace/docs/research/benchmarks-and-tools-landscape.md` | Benchmarks and tools landscape |
