# LLMTrace Examples

Runnable examples demonstrating LLMTrace proxy usage, Python SDK integration, and security analysis.

## Prerequisites

```bash
# Build the proxy binary
cargo build --release

# For Python examples: install the native module
cd crates/llmtrace-python
maturin develop
cd ../..
```

## Examples

### `basic_proxy.sh` — Proxy Quick Start

Starts the proxy, sends non-streaming and streaming requests, and queries stored traces.

```bash
# Point at a real upstream (default: Ollama at localhost:11434)
./examples/basic_proxy.sh

# Or override the upstream URL:
UPSTREAM_URL=https://api.openai.com ./examples/basic_proxy.sh
```

**What it demonstrates:**
- Starting the proxy from a config file
- Health check endpoint
- Non-streaming `POST /v1/chat/completions`
- Streaming SSE request with `"stream": true`
- Prompt injection attempt (triggers security findings)
- Querying traces from SQLite

### `security_test.sh` — Prompt Injection Detection

Sends eight different attack patterns (plus one benign control) through the proxy and reports the resulting security findings from SQLite.

```bash
./examples/security_test.sh
```

**Attack patterns tested:**
1. System prompt override ("ignore previous instructions")
2. Identity override ("you are now…")
3. Role injection (injected `system:` in user content)
4. Instruction override ("override your instructions…")
5. Reveal system prompt
6. PII in prompt (SSN, email)
7. Forget/disregard previous context
8. Benign request (control — should have no findings)

### `python_sdk.py` — Python SDK Usage

Demonstrates the Python SDK: creating tracers, starting spans, recording prompts/responses, error handling, client instrumentation, and streaming TTFT tracking.

```bash
python examples/python_sdk.py
```

**What it demonstrates:**
- `llmtrace.configure()` — create a tracer from a dict
- `tracer.start_span()` — start a trace span
- `span.set_prompt()` / `span.set_response()` — record interactions
- `span.set_token_counts()` — record usage
- `span.set_error()` — record errors
- `span.to_json()` / `span.to_dict()` — serialization
- `llmtrace.instrument()` — wrap an LLM client with tracing
- TTFT tracking via `span.set_ttft_ms()`

## Notes

- Shell examples require `curl`, `sqlite3`, and `python3` on your `PATH`.
- The proxy must be able to reach the upstream LLM for request forwarding. If the upstream is unreachable, security analysis still runs but no response is stored.
- Traces are stored in a SQLite database (path configurable via config or `LLMTRACE_STORAGE_DATABASE_PATH` env var).
