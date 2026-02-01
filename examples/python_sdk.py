#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "llmtrace-python",
# ]
# [tool.uv.sources]
# llmtrace-python = { path = "../crates/llmtrace-python" }
# ///
"""
LLMTrace Python SDK — Usage Example
====================================

Demonstrates how to use the LLMTrace Python SDK to trace LLM calls,
create spans, attach security metadata, and inspect results.

Usage:
    uv run examples/python_sdk.py
"""

import json

# Import the LLMTrace Python bindings
import llmtrace_python as llmtrace


def main():
    print("=" * 60)
    print("LLMTrace Python SDK Example")
    print("=" * 60)

    # ── 1. Configure a tracer ────────────────────────────────────────────────
    print("\n▸ Creating tracer via configure()...")
    tracer = llmtrace.configure({
        "enable_security": True,
    })
    print(f"  Tracer: {tracer}")
    print(f"  Tenant ID: {tracer.tenant_id}")
    print(f"  Security enabled: {tracer.enable_security}")

    # ── 2. Create a trace span ───────────────────────────────────────────────
    print("\n▸ Starting a trace span...")
    span = tracer.start_span("chat_completion", "openai", "gpt-4")
    print(f"  Span: {span}")
    print(f"  Trace ID: {span.trace_id}")
    print(f"  Span ID:  {span.span_id}")

    # ── 3. Record prompt and response ────────────────────────────────────────
    print("\n▸ Recording prompt and response...")
    span.set_prompt("What is the meaning of life?")
    span.set_response("42, according to Douglas Adams.")
    span.set_token_counts(prompt_tokens=8, completion_tokens=7)
    span.add_tag("environment", "development")
    span.add_tag("user_id", "example-user")

    print(f"  Prompt: {span.prompt}")
    print(f"  Response: {span.response}")
    print(f"  Complete: {span.is_complete}")
    print(f"  Duration: {span.duration_ms}ms")
    print(f"  Tokens: {span.prompt_tokens}+{span.completion_tokens}={span.total_tokens}")

    # ── 4. Serialize to JSON ─────────────────────────────────────────────────
    print("\n▸ Serializing span to JSON...")
    span_json = span.to_json()
    parsed = json.loads(span_json)
    print(f"  Trace ID: {parsed['trace_id']}")
    print(f"  Model:    {parsed['model_name']}")
    print(f"  Tokens:   {parsed['total_tokens']}")

    # ── 5. Error handling span ───────────────────────────────────────────────
    print("\n▸ Creating an error span...")
    error_span = tracer.start_span("chat_completion", "anthropic", "claude-3")
    error_span.set_prompt("This request will fail")
    error_span.set_error("Rate limit exceeded", status_code=429)
    print(f"  Failed: {error_span.is_failed}")
    print(f"  Error:  {error_span.error_message}")
    print(f"  Status: {error_span.status_code}")

    # ── 6. Instrument a client object ────────────────────────────────────────
    print("\n▸ Instrumenting a mock client...")

    class MockOpenAIClient:
        """Simulates an OpenAI client for demonstration."""
        def __init__(self):
            self.api_key = "sk-demo"

        def __repr__(self):
            return "MockOpenAIClient()"

    client = MockOpenAIClient()
    instrumented = llmtrace.instrument(client, tracer=tracer)
    print(f"  Instrumented: {instrumented}")
    print(f"  Wrapped client API key: {instrumented.wrapped_client.api_key}")
    print(f"  Tracer tenant: {instrumented.tracer.tenant_id}")

    # Use start_span via the instrumented client
    api_span = instrumented.start_span("embedding", "openai", "text-embedding-3-small")
    api_span.set_prompt("Embed this text for similarity search")
    api_span.set_response("[0.023, -0.041, 0.089, ...]")
    api_span.set_token_counts(prompt_tokens=7, completion_tokens=0)
    print(f"  Embedding span: {api_span}")

    # ── 7. Streaming span with TTFT ──────────────────────────────────────────
    print("\n▸ Simulating a streaming span with TTFT...")
    stream_span = tracer.start_span("chat_completion_stream", "openai", "gpt-4")
    stream_span.set_prompt("Write a poem about Rust")
    stream_span.set_ttft_ms(42)
    stream_span.set_response("Memory safe and fast,\nBorrow checker guides the way,\nRust never rusts out.")
    stream_span.set_token_counts(prompt_tokens=6, completion_tokens=18)
    print(f"  TTFT: {stream_span.to_dict().get('time_to_first_token_ms')}ms")
    print(f"  Content: {stream_span.response}")

    # ── Done ─────────────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("✓ All examples complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
