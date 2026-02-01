# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| main    | ✅ Active          |
| < main  | ❌ Not supported   |

LLMTrace is pre-1.0. Only the latest commit on `main` receives security fixes.

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Instead, please report them privately:

- **Email:** [epappas@evalonlabs.com](mailto:epappas@evalonlabs.com)
- **GitHub:** Use [GitHub's private vulnerability reporting](https://github.com/epappas/llmtrace/security/advisories/new)

Include:
- Description of the vulnerability
- Steps to reproduce
- Affected component(s) (proxy, storage, security analysis, etc.)
- Impact assessment (if known)

## Response Timeline

| Stage              | Target     |
|--------------------|------------|
| Acknowledgement    | 48 hours   |
| Initial assessment | 5 days     |
| Fix or mitigation  | 30 days    |

We'll keep you informed throughout the process. If the issue is accepted, you'll be credited in the advisory (unless you prefer to remain anonymous).

## Security Architecture

LLMTrace is designed with security as a core concern:

- **Prompt injection detection** — Regex-based and ML-based (DeBERTa) analysis of all proxied requests/responses
- **PII detection & redaction** — International PII patterns (UK NIN, IBAN, EU passports, NHS, etc.) with configurable redaction
- **NER-based PII** — BERT-based named entity recognition for detecting names, organisations, and locations
- **Streaming security analysis** — Real-time incremental checks during SSE streaming
- **Statistical anomaly detection** — Per-tenant sliding window analysis with configurable sigma thresholds
- **OWASP LLM Top 10** — Built-in test coverage for all ten categories
- **Per-tenant rate limiting** — Token bucket rate limiting with Redis-backed isolation
- **Cost caps** — Per-agent budget enforcement with soft/hard limits
- **RBAC** — Role-based access control for tenant management
- **Secrets management** — No plaintext secrets in configuration; supports External Secrets Operator and Sealed Secrets

See [docs/guides/custom-policies.md](docs/guides/custom-policies.md) for configuration details.

## Dependencies

We use Dependabot for automated dependency monitoring. Security-critical updates are prioritised.

### Auditing

```bash
# Rust dependencies
cargo audit

# Container image
trivy image llmtrace-proxy:latest

# npm (dashboard)
cd dashboard && npm audit
```

## Disclosure Policy

- Vulnerabilities are disclosed after a fix is available
- CVE IDs are requested for significant issues
- Advisories are published via [GitHub Security Advisories](https://github.com/epappas/llmtrace/security/advisories)
