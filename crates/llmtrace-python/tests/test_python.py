"""Tests for the llmtrace_python bindings.

Run with:
    pytest tests/test_python.py -v
"""

import json
import uuid

import pytest

import llmtrace


# ---------------------------------------------------------------------------
# Module-level checks
# ---------------------------------------------------------------------------


class TestModule:
    """Module metadata and exports."""

    def test_version_exists(self):
        assert hasattr(llmtrace, "__version__")
        assert isinstance(llmtrace.__version__, str)
        assert llmtrace.__version__ == "0.1.0"

    def test_exports_classes(self):
        assert hasattr(llmtrace, "LLMSecTracer")
        assert hasattr(llmtrace, "TraceSpan")
        assert hasattr(llmtrace, "InstrumentedClient")

    def test_exports_functions(self):
        assert callable(llmtrace.configure)
        assert callable(llmtrace.instrument)


# ---------------------------------------------------------------------------
# LLMSecTracer
# ---------------------------------------------------------------------------


class TestLLMSecTracer:
    """LLMSecTracer creation and properties."""

    def test_default_creation(self):
        tracer = llmtrace.LLMSecTracer()
        assert tracer.tenant_id is not None
        # tenant_id should be a valid UUID string
        uuid.UUID(tracer.tenant_id)

    def test_creation_with_tenant_id(self):
        tid = str(uuid.uuid4())
        tracer = llmtrace.LLMSecTracer(tenant_id=tid)
        assert tracer.tenant_id == tid

    def test_creation_with_endpoint(self):
        tracer = llmtrace.LLMSecTracer(endpoint="http://localhost:4318")
        assert tracer.endpoint == "http://localhost:4318"

    def test_creation_without_endpoint(self):
        tracer = llmtrace.LLMSecTracer()
        assert tracer.endpoint is None

    def test_security_enabled_by_default(self):
        tracer = llmtrace.LLMSecTracer()
        assert tracer.enable_security is True

    def test_security_can_be_disabled(self):
        tracer = llmtrace.LLMSecTracer(enable_security=False)
        assert tracer.enable_security is False

    def test_invalid_tenant_id_raises(self):
        with pytest.raises(ValueError, match="Invalid tenant_id UUID"):
            llmtrace.LLMSecTracer(tenant_id="not-a-uuid")

    def test_repr(self):
        tracer = llmtrace.LLMSecTracer()
        r = repr(tracer)
        assert "LLMSecTracer" in r
        assert tracer.tenant_id in r


# ---------------------------------------------------------------------------
# TraceSpan
# ---------------------------------------------------------------------------


class TestTraceSpan:
    """TraceSpan lifecycle and properties."""

    @pytest.fixture()
    def tracer(self):
        return llmtrace.LLMSecTracer()

    def test_start_span_returns_span(self, tracer):
        span = tracer.start_span("chat_completion", "openai", "gpt-4")
        assert isinstance(span, llmtrace.TraceSpan)

    def test_span_has_valid_ids(self, tracer):
        span = tracer.start_span("chat_completion", "openai", "gpt-4")
        uuid.UUID(span.trace_id)
        uuid.UUID(span.span_id)

    def test_span_properties(self, tracer):
        span = tracer.start_span("chat_completion", "openai", "gpt-4")
        assert span.operation_name == "chat_completion"
        assert span.model_name == "gpt-4"
        assert span.prompt == ""
        assert span.response is None
        assert span.is_complete is False
        assert span.is_failed is False

    def test_set_prompt(self, tracer):
        span = tracer.start_span("test", "openai", "gpt-4")
        span.set_prompt("Hello, world!")
        assert span.prompt == "Hello, world!"

    def test_set_response_completes_span(self, tracer):
        span = tracer.start_span("test", "openai", "gpt-4")
        span.set_prompt("Hello")
        span.set_response("Hi there!")
        assert span.response == "Hi there!"
        assert span.is_complete is True
        assert span.is_failed is False
        assert span.duration_ms is not None

    def test_set_error_marks_failed(self, tracer):
        span = tracer.start_span("test", "openai", "gpt-4")
        span.set_error("Connection timeout", 504)
        assert span.is_complete is True
        assert span.is_failed is True
        assert span.error_message == "Connection timeout"
        assert span.status_code == 504

    def test_set_error_without_status_code(self, tracer):
        span = tracer.start_span("test", "openai", "gpt-4")
        span.set_error("Unknown error")
        assert span.is_failed is True
        assert span.status_code is None

    def test_set_token_counts(self, tracer):
        span = tracer.start_span("test", "openai", "gpt-4")
        span.set_token_counts(prompt_tokens=10, completion_tokens=20)
        assert span.prompt_tokens == 10
        assert span.completion_tokens == 20
        assert span.total_tokens == 30

    def test_set_token_counts_partial(self, tracer):
        span = tracer.start_span("test", "openai", "gpt-4")
        span.set_token_counts(prompt_tokens=10)
        assert span.prompt_tokens == 10
        assert span.completion_tokens is None
        assert span.total_tokens is None

    def test_set_ttft(self, tracer):
        span = tracer.start_span("test", "openai", "gpt-4")
        span.set_ttft_ms(42)
        # ttft_ms is not directly exposed as a getter; verify via to_dict
        d = span.to_dict()
        assert d["time_to_first_token_ms"] == 42

    def test_add_tag(self, tracer):
        span = tracer.start_span("test", "openai", "gpt-4")
        span.add_tag("env", "production")
        d = span.to_dict()
        assert d["tags"]["env"] == "production"

    def test_security_score_initially_none(self, tracer):
        span = tracer.start_span("test", "openai", "gpt-4")
        assert span.security_score is None
        assert span.security_findings_count == 0

    def test_to_dict(self, tracer):
        span = tracer.start_span("chat_completion", "openai", "gpt-4")
        span.set_prompt("Hello")
        span.set_response("Hi")
        d = span.to_dict()
        assert isinstance(d, dict)
        assert d["operation_name"] == "chat_completion"
        assert d["model_name"] == "gpt-4"
        assert d["prompt"] == "Hello"
        assert d["response"] == "Hi"

    def test_to_json(self, tracer):
        span = tracer.start_span("test", "openai", "gpt-4")
        json_str = span.to_json()
        parsed = json.loads(json_str)
        assert parsed["operation_name"] == "test"

    def test_repr(self, tracer):
        span = tracer.start_span("chat_completion", "openai", "gpt-4")
        r = repr(span)
        assert "TraceSpan" in r
        assert "chat_completion" in r
        assert "gpt-4" in r

    def test_different_providers(self, tracer):
        providers = [
            "openai",
            "anthropic",
            "vllm",
            "sglang",
            "tgi",
            "ollama",
            "azure_openai",
            "azure-openai",
            "bedrock",
            "custom-provider",
        ]
        for provider in providers:
            span = tracer.start_span("test", provider, "model")
            assert span.operation_name == "test"


# ---------------------------------------------------------------------------
# configure()
# ---------------------------------------------------------------------------


class TestConfigure:
    """configure() function."""

    def test_empty_config(self):
        tracer = llmtrace.configure({})
        assert tracer.enable_security is True

    def test_with_tenant_id(self):
        tid = str(uuid.uuid4())
        tracer = llmtrace.configure({"tenant_id": tid})
        assert tracer.tenant_id == tid

    def test_with_endpoint(self):
        tracer = llmtrace.configure({"endpoint": "http://example.com"})
        assert tracer.endpoint == "http://example.com"

    def test_with_security_disabled(self):
        tracer = llmtrace.configure({"enable_security": False})
        assert tracer.enable_security is False

    def test_with_all_options(self):
        tid = str(uuid.uuid4())
        tracer = llmtrace.configure(
            {
                "tenant_id": tid,
                "endpoint": "http://collector:4318",
                "enable_security": True,
            }
        )
        assert tracer.tenant_id == tid
        assert tracer.endpoint == "http://collector:4318"
        assert tracer.enable_security is True

    def test_invalid_tenant_id_raises(self):
        with pytest.raises(ValueError):
            llmtrace.configure({"tenant_id": "bad"})


# ---------------------------------------------------------------------------
# instrument()
# ---------------------------------------------------------------------------


class TestInstrument:
    """instrument() function and InstrumentedClient."""

    def test_instrument_with_mock_client(self):
        class MockClient:
            pass

        client = MockClient()
        instrumented = llmtrace.instrument(client)
        assert isinstance(instrumented, llmtrace.InstrumentedClient)

    def test_instrument_with_tracer(self):
        class MockClient:
            pass

        tracer = llmtrace.LLMSecTracer()
        instrumented = llmtrace.instrument(MockClient(), tracer=tracer)
        assert instrumented.tracer.tenant_id == tracer.tenant_id

    def test_instrument_creates_default_tracer(self):
        class MockClient:
            pass

        instrumented = llmtrace.instrument(MockClient())
        assert instrumented.tracer is not None
        uuid.UUID(instrumented.tracer.tenant_id)

    def test_wrapped_client_accessible(self):
        class MockClient:
            value = 42

        client = MockClient()
        instrumented = llmtrace.instrument(client)
        assert instrumented.wrapped_client is client

    def test_attribute_delegation(self):
        class MockClient:
            name = "test-client"

            def hello(self):
                return "world"

        client = MockClient()
        instrumented = llmtrace.instrument(client)
        assert instrumented.name == "test-client"
        assert instrumented.hello() == "world"

    def test_start_span_shortcut(self):
        class MockClient:
            pass

        instrumented = llmtrace.instrument(MockClient())
        span = instrumented.start_span("test", "openai", "gpt-4")
        assert isinstance(span, llmtrace.TraceSpan)

    def test_repr(self):
        class MockClient:
            def __repr__(self):
                return "MockClient()"

        instrumented = llmtrace.instrument(MockClient())
        r = repr(instrumented)
        assert "InstrumentedClient" in r
        assert "MockClient()" in r


# ---------------------------------------------------------------------------
# End-to-end workflow
# ---------------------------------------------------------------------------


class TestEndToEnd:
    """Full tracing workflow."""

    def test_full_trace_lifecycle(self):
        # 1. Configure
        tracer = llmtrace.configure({"enable_security": True})

        # 2. Start span
        span = tracer.start_span("chat_completion", "openai", "gpt-4")
        span.set_prompt("What is 2+2?")
        span.add_tag("env", "test")

        # 3. Record response
        span.set_response("2+2 equals 4.")
        span.set_token_counts(prompt_tokens=5, completion_tokens=8)
        span.set_ttft_ms(150)

        # 4. Verify
        assert span.is_complete is True
        assert span.is_failed is False
        assert span.total_tokens == 13

        # 5. Serialise
        d = span.to_dict()
        assert d["prompt"] == "What is 2+2?"
        assert d["response"] == "2+2 equals 4."
        assert d["tags"]["env"] == "test"
        assert d["time_to_first_token_ms"] == 150

    def test_error_trace_lifecycle(self):
        tracer = llmtrace.LLMSecTracer()
        span = tracer.start_span("chat_completion", "anthropic", "claude-3")
        span.set_prompt("Hello")
        span.set_error("Rate limit exceeded", 429)

        assert span.is_complete is True
        assert span.is_failed is True
        assert span.error_message == "Rate limit exceeded"
        assert span.status_code == 429

    def test_instrumented_client_workflow(self):
        class FakeOpenAI:
            """Mimics a minimal OpenAI client."""

            def create_completion(self, prompt: str) -> str:
                return f"Response to: {prompt}"

        tracer = llmtrace.LLMSecTracer()
        client = llmtrace.instrument(FakeOpenAI(), tracer=tracer)

        # Use the client as normal
        result = client.create_completion("Hello")
        assert result == "Response to: Hello"

        # Meanwhile record traces via the attached tracer
        span = client.start_span("chat_completion", "openai", "gpt-4")
        span.set_prompt("Hello")
        span.set_response(result)
        assert span.is_complete is True
