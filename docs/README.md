# LLMTrace Documentation

Welcome to the LLMTrace documentation. LLMTrace is a transparent proxy that captures, analyzes, and secures LLM interactions in real-time.

## Getting Started

- [Installation](getting-started/installation.md) -- build from source, Docker, or Kubernetes
- [Quick Start](getting-started/quickstart.md) -- get running in under 5 minutes
- [Configuration](getting-started/configuration.md) -- config file reference

## Guides

- [OpenAI SDK Integration](guides/integration-openai.md) -- Python and Node.js SDK setup
- [LangChain Integration](guides/integration-langchain.md) -- LangChain/LangGraph integration
- [curl / HTTP Integration](guides/integration-curl.md) -- raw HTTP and scripting examples
- [Custom Security Policies](guides/custom-policies.md) -- define and deploy custom detection rules
- [Pre-Request Enforcement](guides/enforcement.md) -- block, flag, or log requests before forwarding
- [Auth & Multi-Tenancy](guides/auth-tenancy.md) -- API keys, RBAC roles, tenant isolation
- [Dashboard](guides/dashboard.md) -- built-in Next.js dashboard usage
- [Monitoring & Observability](guides/monitoring.md) -- Prometheus metrics, health checks, alerting
- [Troubleshooting](guides/troubleshooting.md) -- common issues and diagnostic steps
- [Integration Tests](guides/integration-tests.md) -- testing your LLMTrace setup

## Security & ML

- [ML Model Reference](ml/models.md) -- DeBERTa, InjecGuard, PIGuard, jailbreak detector
- [Ensemble Detection](ml/ensemble.md) -- how multi-detector voting works
- [Threshold Tuning](ml/tuning.md) -- operating points, per-category thresholds, over-defence
- [Benchmark Methodology](ml/benchmarks.md) -- test corpus, results, reproduction steps
- [OWASP LLM Top 10](security/OWASP_LLM_TOP10.md) -- coverage mapping

## Deployment

- [Kubernetes](deployment/kubernetes.md) -- Helm charts, manifests, HA setup
- [Secrets Management](deployment/secrets-management.md) -- Vault, KMS, environment variables

## Architecture

- [System Architecture](architecture/SYSTEM_ARCHITECTURE.md) -- component overview and data flow
- [Transparent Proxy](architecture/TRANSPARENT_PROXY.md) -- how the proxy intercepts traffic

## API Reference

- [REST API](guides/API.md) -- endpoint reference
- **Swagger UI** -- available at `/swagger-ui` when the proxy is running

## Examples

The [`examples/`](../examples/) directory contains ready-to-use configuration files and integration scripts:

- `config.example.yaml` -- minimal proxy config
- `config.production.yaml` -- production-grade config
- `python/` -- Python SDK examples
- `node/` -- Node.js examples
- `curl/` -- shell scripts for testing

## Additional Resources

- [Feature Roadmap](FEATURE_ROADMAP.md)
- [Contributing Guide](../CONTRIBUTING.md)
- [License (MIT)](../LICENSE)
