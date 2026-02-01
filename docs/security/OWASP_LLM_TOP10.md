# OWASP Top 10 for LLM Applications — Test Coverage

This document maps the [OWASP Top 10 for Large Language Model Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) categories to concrete test coverage in LLMTrace's security analysis engine.

## Coverage Summary

| OWASP ID | Category | Status | Test File | Detection Engine |
|----------|----------|--------|-----------|-----------------|
| LLM01 | Prompt Injection | ✅ Covered | `owasp_llm_top10.rs` | `RegexSecurityAnalyzer` + ML ensemble |
| LLM02 | Insecure Output Handling | ✅ Covered | `owasp_llm_top10.rs` | `RegexSecurityAnalyzer` |
| LLM03 | Training Data Poisoning | ⬜ N/A | — | Out of scope (runtime proxy) |
| LLM04 | Model Denial of Service | ⬜ Partial | — | Cost caps + rate limiting |
| LLM05 | Supply Chain Vulnerabilities | ⬜ N/A | — | Out of scope (CI/CD concern) |
| LLM06 | Sensitive Information Disclosure | ✅ Covered | `owasp_llm_top10.rs` | `RegexSecurityAnalyzer` + NER |
| LLM07 | Insecure Plugin Design | ✅ Covered | `owasp_llm_top10.rs` | Agent action analysis |
| LLM08 | Excessive Agency | ⬜ Partial | — | Agent action tracing + anomaly detection |
| LLM09 | Overreliance | ⬜ N/A | — | Out of scope (UX concern) |
| LLM10 | Model Theft | ⬜ N/A | — | Out of scope (infrastructure concern) |

---

## LLM01: Prompt Injection

**Risk**: An attacker manipulates the LLM through crafted inputs to override system prompts, inject roles, or execute unintended instructions.

**Detection patterns**:

| Attack Type | Pattern | Tests | Severity |
|-------------|---------|-------|----------|
| System override | "ignore previous instructions", "forget everything", "disregard all" | `test_owasp_llm01_system_override_*` (7 tests) | High |
| Identity change | "you are now", "act as if you are" | `test_owasp_llm01_system_override_identity_change` | High |
| New instructions | "new instructions:" | `test_owasp_llm01_system_override_new_instructions` | High |
| Override directive | "override your instructions" | `test_owasp_llm01_system_override_*` | High |
| Prompt extraction | "reveal your system prompt" | `test_owasp_llm01_system_override_reveal_prompt` | High |
| Role injection | "system:", "assistant:", "user:" in user messages | `test_owasp_llm01_role_injection_*` (3 tests) | High/Medium |
| DAN jailbreak | "DAN" + "no restrictions" / "do anything" / "without limits" | `test_owasp_llm01_dan_*` (2 tests) | Critical |
| Delimiter injection | `---system:`, `===instructions:` | `test_owasp_llm01_delimiter_*` (2 tests) | High |
| Base64 encoding | Base64-encoded malicious instructions | `test_owasp_llm01_encoding_*` (3 tests) | High |
| Case evasion | Mixed case variants of attack phrases | `test_owasp_llm01_case_insensitive_detection` | — |
| False positive | Benign inputs | `test_owasp_llm01_benign_prompt_no_findings` | — |

**Total LLM01 tests**: 20

---

## LLM02: Insecure Output Handling

**Risk**: LLM outputs accepted without scrutiny may contain leaked system prompts, credentials, or other sensitive data.

**Detection patterns**:

| Leak Type | Pattern | Tests | Severity |
|-----------|---------|-------|----------|
| System prompt leak | "my system prompt is:" | `test_owasp_llm02_system_prompt_leak` | High |
| API key leak | `api_key: sk-...` | `test_owasp_llm02_credential_leak_api_key` | Critical |
| Password leak | `password=...` | `test_owasp_llm02_credential_leak_password` | Critical |
| Auth token leak | `auth_token: ...` | `test_owasp_llm02_credential_leak_auth_token` | Critical |
| Secret key leak | `secret_key=...` | `test_owasp_llm02_credential_leak_secret_key` | Critical |
| PII in response | Email, SSN in LLM output | `test_owasp_llm02_pii_leak_in_response` | Medium |
| Clean output | No false positives on benign responses | `test_owasp_llm02_clean_response_no_findings` | — |

**Total LLM02 tests**: 7

---

## LLM06: Sensitive Information Disclosure

**Risk**: LLM applications may inadvertently reveal PII or sensitive data.

**Detection patterns**:

| PII Type | Format | Tests | Confidence |
|----------|--------|-------|------------|
| Email | `user@domain.tld` | `test_owasp_llm06_pii_email` | 0.90 |
| US phone (dashes) | `555-123-4567` | `test_owasp_llm06_pii_phone_us_dashes` | 0.85 |
| US phone (parens) | `(555) 123-4567` | `test_owasp_llm06_pii_phone_us_parens` | 0.85 |
| US SSN | `456-78-9012` | `test_owasp_llm06_pii_ssn` | 0.95 |
| Credit card (spaces) | `4111 1111 1111 1111` | `test_owasp_llm06_pii_credit_card_spaces` | 0.90 |
| Credit card (dashes) | `4111-1111-1111-1111` | `test_owasp_llm06_pii_credit_card_dashes` | 0.90 |
| UK NIN | `AB 12 34 56 C` | `test_owasp_llm06_pii_uk_national_insurance` | 0.90 |
| IBAN (DE) | `DE89 3704 0044 0532 0130 00` | `test_owasp_llm06_pii_iban_de` | 0.85 |
| IBAN (GB) | `GB29 NWBK 6016 1331 9268 19` | `test_owasp_llm06_pii_iban_gb` | 0.85 |
| Intl phone (UK) | `+44 20 7946 0958` | `test_owasp_llm06_pii_intl_phone_uk` | 0.80 |
| Intl phone (DE) | `+49 30 123456` | `test_owasp_llm06_pii_intl_phone_de` | 0.80 |
| NHS number | `943 476 5919` | `test_owasp_llm06_pii_nhs_number` | 0.70 |
| Canadian SIN | `046-454-286` | `test_owasp_llm06_pii_canadian_sin` | 0.80 |
| Code block suppression | PII in ` ``` ` blocks | `test_owasp_llm06_pii_in_code_block_suppressed` | — |
| Multiple PII | Combined detection | `test_owasp_llm06_multiple_pii_types_detected` | — |

**Total LLM06 tests**: 15

---

## LLM07: Insecure Plugin Design

**Risk**: LLM plugins/tools may execute dangerous actions without proper validation or constraints.

**Detection patterns**:

| Action Type | Pattern | Tests | Severity |
|-------------|---------|-------|----------|
| Destructive command | `rm -rf`, `rm -fr` | `test_owasp_llm07_dangerous_command_rm_*` (2 tests) | Critical |
| Remote code execution | `curl \| sh`, `wget \| bash` | `test_owasp_llm07_dangerous_command_curl_*`, `_wget_*` (2 tests) | Critical |
| Encoded execution | `base64 -d \| sh` | `test_owasp_llm07_dangerous_command_base64_execute` | High |
| System command | `chmod 777` | `test_owasp_llm07_sensitive_system_command_chmod` | High |
| IP-based URL | `http://192.168.x.x/...` | `test_owasp_llm07_suspicious_url_ip_address` | Medium |
| Localhost exemption | `127.0.0.1` not flagged | `test_owasp_llm07_suspicious_url_localhost_allowed` | — |
| Suspicious domain | pastebin.com, transfer.sh | `test_owasp_llm07_suspicious_url_pastebin`, `_transfer_sh` (2 tests) | High |
| Sensitive file | `/etc/passwd`, `/etc/shadow`, `.ssh/`, `.aws/credentials`, `.env`, `.kube/config` | `test_owasp_llm07_sensitive_file_*` (6 tests) | High |
| Safe actions | Benign commands, URLs, files | `test_owasp_llm07_safe_*` (3 tests) | — |
| Multi-action attack | Combined scenario | `test_owasp_llm07_combined_attack_scenario` | — |
| Hidden arguments | Dangerous args in separate field | `test_owasp_llm07_command_with_arguments_field` | — |

**Total LLM07 tests**: 22

---

## Running the Tests

```bash
# Run all OWASP LLM Top 10 tests
cargo test --test owasp_llm_top10

# Run tests for a specific OWASP category
cargo test --test owasp_llm_top10 owasp_llm01    # Prompt Injection
cargo test --test owasp_llm_top10 owasp_llm02    # Insecure Output Handling
cargo test --test owasp_llm_top10 owasp_llm06    # Sensitive Information Disclosure
cargo test --test owasp_llm_top10 owasp_llm07    # Insecure Plugin Design
```

## Categories Not Covered (and Why)

| OWASP ID | Category | Reason |
|----------|----------|--------|
| LLM03 | Training Data Poisoning | LLMTrace is a runtime proxy — training-time concerns are out of scope. |
| LLM04 | Model Denial of Service | Partially mitigated by cost caps and rate limiting (tested elsewhere). |
| LLM05 | Supply Chain Vulnerabilities | CI/CD concern — handled by `cargo audit` and dependency scanning in GitHub Actions. |
| LLM08 | Excessive Agency | Partially mitigated by agent action tracing and anomaly detection (tested in their respective modules). |
| LLM09 | Overreliance | UX/behavioral concern — cannot be detected by a proxy. |
| LLM10 | Model Theft | Infrastructure/access-control concern — out of scope for a proxy. |
