# LLMTrace

[![CI](https://github.com/techlab-innov/llmtrace/actions/workflows/ci.yml/badge.svg)](https://github.com/techlab-innov/llmtrace/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/llmtracing.svg)](https://pypi.org/project/llmtracing/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

LLMTrace is a drop-in security and observability gateway for AI agents and
LLM applications. Point your OpenAI-compatible client at the proxy and get
prompt-injection detection, PII protection, tracing, and cost control in
front of OpenAI, Anthropic, or any provider — with no SDK changes.

## Where the code lives

From v0.4.0 the LLMTrace engine (proxy, security analyzers, dashboard) is
developed privately and distributed as public container images under the
[Elastic License 2.0](https://www.elastic.co/licensing/elastic-license):
free to run, self-host, and use commercially; not to be offered as a
competing managed service.

This repository hosts everything a user needs, under MIT:

- `crates/llmtrace-core` — core types and traits
- `crates/llmtrace-python` — the optional [`llmtracing`](https://pypi.org/project/llmtracing/) Python tracing helper
- `docs/` — the documentation site
- `deployments/`, `examples/`, `config.example.yaml` — install paths and configuration references

Versions up to and including v0.3.0 remain MIT as shipped (crates.io
`llmtrace` 0.3.0 is the last MIT release of the engine). Issues and
questions are welcome here.

## Quickstart (self-host)

```bash
cp config.example.yaml config.yaml   # set upstream_url + your provider key
docker compose up -d
```

Then point your client at the proxy — no code changes beyond the base URL:

```python
from openai import OpenAI

client = OpenAI(
    api_key="sk-...",                       # your provider key
    base_url="http://localhost:8080/v1",    # the LLMTrace proxy
)
```

The dashboard runs at `http://localhost:3000`. For the full production
stack (ClickHouse, Postgres, Redis, monitoring) see
`deployments/docker-compose/` and the [deployment docs](https://docs.llmtrace.io/deployment/docker-compose/).

Images: `ghcr.io/techlab-innov/llmtrace-proxy` and
`ghcr.io/techlab-innov/llmtrace-dashboard` (tags: `latest`, `main`, and
version tags from `0.3.0`).

## Optional Python tracing helper

```bash
pip install llmtracing
```

```python
import llmtrace

llmtrace.configure(endpoint="http://localhost:8080")
```

See `examples/` for Python, Node.js, and curl integrations.

## Managed service

[llmtrace.io](https://llmtrace.io) offers LLMTrace as a managed service:
per-tenant instances, provisioning, key management, and SLO dashboards.

## Documentation

Full docs at [docs.llmtrace.io](https://docs.llmtrace.io) — getting
started, configuration catalogue, integration guides, deployment, and
operations.

## License

This repository: [MIT](LICENSE). The LLMTrace engine from v0.4.0: Elastic
License 2.0, distributed as container images. Engine versions up to and
including v0.3.0: MIT as shipped.
