//! Python bindings for LLMTrace
//!
//! This crate provides Python bindings via PyO3 to make LLMTrace accessible from Python.
//!
//! # Quick Start
//!
//! ```python
//! import llmtrace_python as llmtrace
//!
//! # Configure from a dict
//! tracer = llmtrace.configure({"tenant_id": "...", "enable_security": True})
//!
//! # Or create directly
//! tracer = llmtrace.LLMSecTracer(tenant_id="your-uuid-here")
//!
//! # Start a trace span
//! span = tracer.start_span("chat_completion", "openai", "gpt-4")
//! span.set_prompt("Hello, world!")
//! span.set_response("Hi there!")
//! span.set_token_counts(prompt_tokens=5, completion_tokens=3)
//!
//! # Instrument an LLM client
//! instrumented = llmtrace.instrument(client, tracer=tracer)
//! ```

use pyo3::prelude::*;
use pyo3::types::PyDict;

use llmtrace_core::{
    AgentAction, AgentActionType, LLMProvider, SecuritySeverity, TenantId, TraceSpan,
};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helper: parse a provider string into LLMProvider
// ---------------------------------------------------------------------------

/// Parse a provider name string into an [`LLMProvider`].
fn parse_provider(provider: &str) -> PyResult<LLMProvider> {
    match provider.to_lowercase().as_str() {
        "openai" => Ok(LLMProvider::OpenAI),
        "anthropic" => Ok(LLMProvider::Anthropic),
        "vllm" => Ok(LLMProvider::VLLm),
        "sglang" => Ok(LLMProvider::SGLang),
        "tgi" => Ok(LLMProvider::TGI),
        "ollama" => Ok(LLMProvider::Ollama),
        "azure_openai" | "azure-openai" | "azureopenai" => Ok(LLMProvider::AzureOpenAI),
        "bedrock" => Ok(LLMProvider::Bedrock),
        other => Ok(LLMProvider::Custom(other.to_string())),
    }
}

/// Parse an action type string into an [`AgentActionType`].
fn parse_action_type(s: &str) -> PyResult<AgentActionType> {
    match s {
        "tool_call" => Ok(AgentActionType::ToolCall),
        "skill_invocation" => Ok(AgentActionType::SkillInvocation),
        "command_execution" => Ok(AgentActionType::CommandExecution),
        "web_access" => Ok(AgentActionType::WebAccess),
        "file_access" => Ok(AgentActionType::FileAccess),
        other => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Invalid action_type: '{other}'. Expected one of: tool_call, skill_invocation, command_execution, web_access, file_access"
        ))),
    }
}

/// Convert a [`SecuritySeverity`] to a Python-friendly string.
fn severity_to_str(severity: &SecuritySeverity) -> &'static str {
    match severity {
        SecuritySeverity::Info => "info",
        SecuritySeverity::Low => "low",
        SecuritySeverity::Medium => "medium",
        SecuritySeverity::High => "high",
        SecuritySeverity::Critical => "critical",
    }
}

// ---------------------------------------------------------------------------
// PyTraceSpan — wraps llmtrace_core::TraceSpan
// ---------------------------------------------------------------------------

/// A single trace span representing one LLM interaction.
///
/// Created via [`LLMSecTracer.start_span`]. Use setters to record the
/// prompt, response, token counts, and completion status.
#[pyclass(name = "TraceSpan")]
struct PyTraceSpan {
    inner: TraceSpan,
}

#[pymethods]
impl PyTraceSpan {
    // -- read-only properties ------------------------------------------------

    /// Unique trace identifier (UUID string).
    #[getter]
    fn trace_id(&self) -> String {
        self.inner.trace_id.to_string()
    }

    /// Unique span identifier (UUID string).
    #[getter]
    fn span_id(&self) -> String {
        self.inner.span_id.to_string()
    }

    /// Operation name (e.g. ``"chat_completion"``).
    #[getter]
    fn operation_name(&self) -> &str {
        &self.inner.operation_name
    }

    /// Model name (e.g. ``"gpt-4"``).
    #[getter]
    fn model_name(&self) -> &str {
        &self.inner.model_name
    }

    /// The prompt text recorded for this span.
    #[getter]
    fn prompt(&self) -> &str {
        &self.inner.prompt
    }

    /// The response text, or ``None`` if not yet recorded.
    #[getter]
    fn response(&self) -> Option<&str> {
        self.inner.response.as_deref()
    }

    /// Whether the span has been completed (response or error recorded).
    #[getter]
    fn is_complete(&self) -> bool {
        self.inner.is_complete()
    }

    /// Whether the span ended with an error.
    #[getter]
    fn is_failed(&self) -> bool {
        self.inner.is_failed()
    }

    /// Duration in milliseconds, or ``None`` if still in progress.
    #[getter]
    fn duration_ms(&self) -> Option<u64> {
        self.inner.duration_ms
    }

    /// Prompt token count, or ``None`` if not set.
    #[getter]
    fn prompt_tokens(&self) -> Option<u32> {
        self.inner.prompt_tokens
    }

    /// Completion token count, or ``None`` if not set.
    #[getter]
    fn completion_tokens(&self) -> Option<u32> {
        self.inner.completion_tokens
    }

    /// Total token count, or ``None`` if not set.
    #[getter]
    fn total_tokens(&self) -> Option<u32> {
        self.inner.total_tokens
    }

    /// Overall security score (0–100), or ``None`` if not analysed.
    #[getter]
    fn security_score(&self) -> Option<u8> {
        self.inner.security_score
    }

    /// Error message if the span failed, or ``None``.
    #[getter]
    fn error_message(&self) -> Option<&str> {
        self.inner.error_message.as_deref()
    }

    /// HTTP status code of the response, or ``None``.
    #[getter]
    fn status_code(&self) -> Option<u16> {
        self.inner.status_code
    }

    /// Number of security findings attached to this span.
    #[getter]
    fn security_findings_count(&self) -> usize {
        self.inner.security_findings.len()
    }

    /// Security findings as a list of dicts.
    fn security_findings(&self, py: Python<'_>) -> PyResult<PyObject> {
        let findings: Vec<serde_json::Value> = self
            .inner
            .security_findings
            .iter()
            .map(|f| {
                serde_json::json!({
                    "id": f.id.to_string(),
                    "severity": severity_to_str(&f.severity),
                    "finding_type": f.finding_type,
                    "description": f.description,
                    "confidence_score": f.confidence_score,
                    "location": f.location,
                    "requires_alert": f.requires_alert,
                })
            })
            .collect();

        let json_str = serde_json::to_string(&findings)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

        let json_mod = py.import("json")?;
        let result = json_mod.call_method1("loads", (&json_str,))?;
        Ok(result.unbind())
    }

    // -- mutators ------------------------------------------------------------

    /// Set the prompt text for this span.
    fn set_prompt(&mut self, prompt: String) {
        self.inner.prompt = prompt;
    }

    /// Record a successful response and mark the span as complete.
    fn set_response(&mut self, response: String) {
        self.inner = self.inner.clone().finish_with_response(response);
    }

    /// Record an error and mark the span as complete.
    #[pyo3(signature = (error, status_code=None))]
    fn set_error(&mut self, error: String, status_code: Option<u16>) {
        self.inner = self.inner.clone().finish_with_error(error, status_code);
    }

    /// Set token counts for this span.
    #[pyo3(signature = (*, prompt_tokens=None, completion_tokens=None))]
    fn set_token_counts(&mut self, prompt_tokens: Option<u32>, completion_tokens: Option<u32>) {
        self.inner.prompt_tokens = prompt_tokens;
        self.inner.completion_tokens = completion_tokens;
        self.inner.total_tokens = match (prompt_tokens, completion_tokens) {
            (Some(p), Some(c)) => Some(p + c),
            _ => None,
        };
    }

    /// Set the time-to-first-token in milliseconds.
    fn set_ttft_ms(&mut self, ttft_ms: u64) {
        self.inner.time_to_first_token_ms = Some(ttft_ms);
    }

    /// Add a custom tag (key-value pair) to this span.
    fn add_tag(&mut self, key: String, value: String) {
        self.inner.tags.insert(key, value);
    }

    /// Report an agent action on this span.
    ///
    /// Args:
    ///     action_type: One of ``"tool_call"``, ``"skill_invocation"``,
    ///                  ``"command_execution"``, ``"web_access"``, ``"file_access"``.
    ///     name: Name of the tool, skill, command, URL, or file path.
    ///     arguments: Optional arguments or parameters.
    ///     result: Optional result (truncated to 4KB).
    ///     duration_ms: Optional duration in milliseconds.
    ///     success: Whether the action succeeded (default ``True``).
    ///
    /// Returns:
    ///     The action ID (UUID string).
    #[pyo3(signature = (action_type, name, *, arguments=None, result=None, duration_ms=None, success=None))]
    fn report_action(
        &mut self,
        action_type: &str,
        name: String,
        arguments: Option<String>,
        result: Option<String>,
        duration_ms: Option<u64>,
        success: Option<bool>,
    ) -> PyResult<String> {
        let at = parse_action_type(action_type)?;
        let mut action = AgentAction::new(at, name);
        if let Some(args) = arguments {
            action = action.with_arguments(args);
        }
        if let Some(res) = result {
            action = action.with_result(res);
        }
        if let Some(ms) = duration_ms {
            action = action.with_duration_ms(ms);
        }
        if let Some(false) = success {
            action = action.with_failure();
        }
        let action_id = action.id.to_string();
        self.inner.add_agent_action(action);
        Ok(action_id)
    }

    /// Number of agent actions recorded on this span.
    #[getter]
    fn agent_actions_count(&self) -> usize {
        self.inner.agent_actions.len()
    }

    // -- serialisation -------------------------------------------------------

    /// Serialise the span to a Python dictionary.
    fn to_dict(&self, py: Python<'_>) -> PyResult<PyObject> {
        let json_str = serde_json::to_string(&self.inner)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

        let json_mod = py.import("json")?;
        let result = json_mod.call_method1("loads", (&json_str,))?;
        Ok(result.unbind())
    }

    /// Serialise the span to a JSON string.
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string_pretty(&self.inner)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    fn __repr__(&self) -> String {
        format!(
            "TraceSpan(trace_id='{}', op='{}', model='{}', complete={})",
            self.inner.trace_id,
            self.inner.operation_name,
            self.inner.model_name,
            self.inner.is_complete(),
        )
    }
}

// ---------------------------------------------------------------------------
// LLMSecTracer — main tracer class
// ---------------------------------------------------------------------------

/// Security-aware LLM tracer.
///
/// Create one per application (or per tenant) and use it to start trace
/// spans for each LLM call.
#[pyclass(name = "LLMSecTracer")]
struct PyLLMSecTracer {
    tenant_id: TenantId,
    endpoint: Option<String>,
    enable_security: bool,
}

#[pymethods]
impl PyLLMSecTracer {
    /// Create a new tracer.
    ///
    /// Args:
    ///     tenant_id: UUID string identifying the tenant. Generated if omitted.
    ///     endpoint: Optional collector endpoint URL.
    ///     enable_security: Enable security analysis (default ``True``).
    #[new]
    #[pyo3(signature = (*, tenant_id=None, endpoint=None, enable_security=None))]
    fn new(
        tenant_id: Option<&str>,
        endpoint: Option<String>,
        enable_security: Option<bool>,
    ) -> PyResult<Self> {
        let tid = match tenant_id {
            Some(id_str) => {
                let uuid = Uuid::parse_str(id_str).map_err(|e| {
                    pyo3::exceptions::PyValueError::new_err(format!("Invalid tenant_id UUID: {e}"))
                })?;
                TenantId(uuid)
            }
            None => TenantId::new(),
        };

        Ok(Self {
            tenant_id: tid,
            endpoint,
            enable_security: enable_security.unwrap_or(true),
        })
    }

    /// Tenant identifier (UUID string).
    #[getter]
    fn tenant_id(&self) -> String {
        self.tenant_id.to_string()
    }

    /// Collector endpoint URL, or ``None``.
    #[getter]
    fn endpoint(&self) -> Option<&str> {
        self.endpoint.as_deref()
    }

    /// Whether security analysis is enabled.
    #[getter]
    fn enable_security(&self) -> bool {
        self.enable_security
    }

    /// Start a new trace span.
    ///
    /// Args:
    ///     operation_name: Name of the operation (e.g. ``"chat_completion"``).
    ///     provider: LLM provider string (``"openai"``, ``"anthropic"``, etc.).
    ///     model: Model name (e.g. ``"gpt-4"``).
    ///
    /// Returns:
    ///     A new :class:`TraceSpan` ready for recording.
    fn start_span(
        &self,
        operation_name: &str,
        provider: &str,
        model: &str,
    ) -> PyResult<PyTraceSpan> {
        let llm_provider = parse_provider(provider)?;

        let span = TraceSpan::new(
            Uuid::new_v4(),
            self.tenant_id,
            operation_name.to_string(),
            llm_provider,
            model.to_string(),
            String::new(),
        );

        Ok(PyTraceSpan { inner: span })
    }

    fn __repr__(&self) -> String {
        format!(
            "LLMSecTracer(tenant_id='{}', endpoint={:?}, security={})",
            self.tenant_id, self.endpoint, self.enable_security,
        )
    }
}

// ---------------------------------------------------------------------------
// InstrumentedClient — wraps a Python LLM client with tracing
// ---------------------------------------------------------------------------

/// A wrapper around a Python LLM client that attaches an [`LLMSecTracer`].
///
/// Attribute access is delegated to the wrapped client, so it can be used
/// as a drop-in replacement. The attached tracer is accessible via the
/// ``tracer`` property.
#[pyclass(name = "InstrumentedClient")]
struct PyInstrumentedClient {
    inner: PyObject,
    tracer: Py<PyLLMSecTracer>,
}

#[pymethods]
impl PyInstrumentedClient {
    /// The attached :class:`LLMSecTracer`.
    #[getter]
    fn tracer(&self, py: Python<'_>) -> Py<PyLLMSecTracer> {
        self.tracer.clone_ref(py)
    }

    /// The original (unwrapped) client object.
    #[getter]
    fn wrapped_client(&self, py: Python<'_>) -> PyObject {
        self.inner.clone_ref(py)
    }

    /// Start a trace span via the attached tracer (convenience shortcut).
    fn start_span(
        &self,
        py: Python<'_>,
        operation_name: &str,
        provider: &str,
        model: &str,
    ) -> PyResult<PyTraceSpan> {
        self.tracer
            .borrow(py)
            .start_span(operation_name, provider, model)
    }

    /// Delegate attribute access to the wrapped client.
    fn __getattr__(&self, py: Python<'_>, name: &str) -> PyResult<PyObject> {
        self.inner.getattr(py, name)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        let inner_repr: String = self.inner.call_method0(py, "__repr__")?.extract(py)?;
        Ok(format!("InstrumentedClient({inner_repr})"))
    }
}

// ---------------------------------------------------------------------------
// Module-level functions
// ---------------------------------------------------------------------------

/// Configure and create an :class:`LLMSecTracer` from a Python dictionary.
///
/// Supported keys:
///   - ``tenant_id`` (str): UUID string for the tenant.
///   - ``endpoint`` (str): Collector endpoint URL.
///   - ``enable_security`` (bool): Enable security analysis.
///
/// Returns:
///     A configured :class:`LLMSecTracer`.
#[pyfunction]
fn configure(config: &Bound<'_, PyDict>) -> PyResult<PyLLMSecTracer> {
    let tenant_id: Option<String> = config
        .get_item("tenant_id")?
        .map(|v| v.extract())
        .transpose()?;
    let endpoint: Option<String> = config
        .get_item("endpoint")?
        .map(|v| v.extract())
        .transpose()?;
    let enable_security: Option<bool> = config
        .get_item("enable_security")?
        .map(|v| v.extract())
        .transpose()?;

    PyLLMSecTracer::new(tenant_id.as_deref(), endpoint, enable_security)
}

/// Instrument a Python LLM client with automatic tracing.
///
/// Wraps the client in an :class:`InstrumentedClient` that delegates
/// attribute access to the original while attaching a tracer.
///
/// Args:
///     client: Any Python LLM client object (e.g. ``openai.OpenAI(...)``).
///     tracer: Optional pre-configured :class:`LLMSecTracer`. A default
///             tracer is created if omitted.
///
/// Returns:
///     An :class:`InstrumentedClient` wrapping the original client.
#[pyfunction]
#[pyo3(signature = (client, *, tracer=None))]
fn instrument(
    py: Python<'_>,
    client: PyObject,
    tracer: Option<Py<PyLLMSecTracer>>,
) -> PyResult<PyInstrumentedClient> {
    let tracer = match tracer {
        Some(t) => t,
        None => Py::new(py, PyLLMSecTracer::new(None, None, None)?)?,
    };

    Ok(PyInstrumentedClient {
        inner: client,
        tracer,
    })
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// LLMTrace Python bindings.
#[pymodule]
fn llmtrace_python(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;

    m.add_class::<PyLLMSecTracer>()?;
    m.add_class::<PyTraceSpan>()?;
    m.add_class::<PyInstrumentedClient>()?;

    m.add_function(wrap_pyfunction!(configure, m)?)?;
    m.add_function(wrap_pyfunction!(instrument, m)?)?;

    Ok(())
}
