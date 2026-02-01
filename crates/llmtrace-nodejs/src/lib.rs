//! Native Node.js bindings for LLMTrace via NAPI-RS.
//!
//! Exposes security analysis, cost estimation, tracing, and agent action
//! reporting to server-side JavaScript/TypeScript.

#![deny(clippy::all)]

use std::collections::HashMap;
use std::pin::pin;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use napi_derive::napi;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// JS-friendly finding type
// ---------------------------------------------------------------------------

/// A security finding returned to JavaScript.
#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Severity level: "Info", "Low", "Medium", "High", or "Critical".
    pub severity: String,
    /// Category: "prompt_injection", "pii_detected", "encoding_attack", etc.
    pub finding_type: String,
    /// Human-readable description.
    pub description: String,
    /// Confidence score (0.0–1.0).
    pub confidence: f64,
    /// Where in the input the issue was found.
    pub location: Option<String>,
}

impl From<llmtrace_core::SecurityFinding> for Finding {
    fn from(f: llmtrace_core::SecurityFinding) -> Self {
        Self {
            severity: f.severity.to_string(),
            finding_type: f.finding_type,
            description: f.description,
            confidence: f.confidence_score,
            location: f.location,
        }
    }
}

// ---------------------------------------------------------------------------
// JS-friendly agent action type
// ---------------------------------------------------------------------------

/// An agent action to report for security analysis.
#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentActionInput {
    /// Action type: "tool_call", "skill_invocation", "command_execution",
    /// "web_access", or "file_access".
    pub action_type: String,
    /// Name of the tool, command, URL, or file path.
    pub name: String,
    /// Arguments or parameters (optional).
    pub arguments: Option<String>,
    /// Result or output (optional, truncated to 4 KB internally).
    pub result: Option<String>,
    /// Duration in milliseconds (optional).
    pub duration_ms: Option<f64>,
    /// Whether the action succeeded (defaults to true).
    pub success: Option<bool>,
    /// Exit code for command executions (optional).
    pub exit_code: Option<i32>,
    /// HTTP method for web access (optional).
    pub http_method: Option<String>,
    /// HTTP status code for web access (optional).
    pub http_status: Option<u32>,
    /// File operation: "read", "write", or "delete" (optional).
    pub file_operation: Option<String>,
}

/// Convert a JS action type string to the core enum.
fn parse_action_type(s: &str) -> napi::Result<llmtrace_core::AgentActionType> {
    match s {
        "tool_call" => Ok(llmtrace_core::AgentActionType::ToolCall),
        "skill_invocation" => Ok(llmtrace_core::AgentActionType::SkillInvocation),
        "command_execution" => Ok(llmtrace_core::AgentActionType::CommandExecution),
        "web_access" => Ok(llmtrace_core::AgentActionType::WebAccess),
        "file_access" => Ok(llmtrace_core::AgentActionType::FileAccess),
        _ => Err(napi::Error::from_reason(format!(
            "Unknown action type: {s}. Expected one of: tool_call, skill_invocation, \
             command_execution, web_access, file_access"
        ))),
    }
}

/// Convert a JS `AgentActionInput` to the core `AgentAction`.
fn convert_action(input: &AgentActionInput) -> napi::Result<llmtrace_core::AgentAction> {
    let action_type = parse_action_type(&input.action_type)?;
    let mut action = llmtrace_core::AgentAction::new(action_type, input.name.clone());

    if let Some(ref args) = input.arguments {
        action = action.with_arguments(args.clone());
    }
    if let Some(ref result) = input.result {
        action = action.with_result(result.clone());
    }
    if let Some(ms) = input.duration_ms {
        action = action.with_duration_ms(ms as u64);
    }
    if let Some(false) = input.success {
        action = action.with_failure();
    }
    if let Some(code) = input.exit_code {
        action = action.with_exit_code(code);
    }
    if let Some(ref method) = input.http_method {
        let status = input.http_status.unwrap_or(0) as u16;
        action = action.with_http(method.clone(), status);
    }
    if let Some(ref op) = input.file_operation {
        action = action.with_file_operation(op.clone());
    }

    Ok(action)
}

// ---------------------------------------------------------------------------
// JS-friendly span info (returned from tracer)
// ---------------------------------------------------------------------------

/// Information about a recorded trace span.
#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanInfo {
    /// Unique span ID.
    pub span_id: String,
    /// Trace ID this span belongs to.
    pub trace_id: String,
    /// Operation name.
    pub operation_name: String,
    /// LLM provider.
    pub provider: String,
    /// Model name.
    pub model_name: String,
    /// Duration in milliseconds (if complete).
    pub duration_ms: Option<f64>,
    /// Security score (0–100, if analysed).
    pub security_score: Option<u32>,
    /// Number of security findings.
    pub findings_count: u32,
    /// Estimated cost in USD (if available).
    pub estimated_cost_usd: Option<f64>,
}

// ---------------------------------------------------------------------------
// SecurityAnalyzer class
// ---------------------------------------------------------------------------

/// Security analyzer for LLM prompts and responses.
///
/// Wraps the regex-based `RegexSecurityAnalyzer` from `llmtrace-security`.
/// All analysis is synchronous and CPU-only.
#[napi]
pub struct SecurityAnalyzer {
    inner: llmtrace_security::RegexSecurityAnalyzer,
}

#[napi]
impl SecurityAnalyzer {
    /// Create a new security analyzer with all built-in detection patterns.
    #[napi(constructor)]
    pub fn new() -> napi::Result<Self> {
        let inner = llmtrace_security::RegexSecurityAnalyzer::new()
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Analyze a prompt for injection attacks and PII.
    #[napi]
    pub fn analyze_prompt(&self, prompt: String) -> napi::Result<Vec<Finding>> {
        let findings = self.run_analyze_request(&prompt)?;
        Ok(findings)
    }

    /// Analyze a response for PII leakage and data exfiltration.
    #[napi]
    pub fn analyze_response(&self, response: String) -> napi::Result<Vec<Finding>> {
        let findings = self.run_analyze_response(&response)?;
        Ok(findings)
    }

    /// Analyze both prompt and response, returning combined findings.
    #[napi]
    pub fn analyze_interaction(
        &self,
        prompt: String,
        response: String,
    ) -> napi::Result<Vec<Finding>> {
        let mut findings = self.run_analyze_request(&prompt)?;
        findings.extend(self.run_analyze_response(&response)?);
        Ok(findings)
    }

    /// Analyze a list of agent actions for suspicious patterns.
    ///
    /// Checks for dangerous commands, suspicious URLs, and sensitive file access.
    #[napi]
    pub fn analyze_agent_actions(
        &self,
        actions: Vec<AgentActionInput>,
    ) -> napi::Result<Vec<Finding>> {
        let core_actions: Vec<llmtrace_core::AgentAction> = actions
            .iter()
            .map(convert_action)
            .collect::<napi::Result<Vec<_>>>()?;
        let findings = self.inner.analyze_agent_actions(&core_actions);
        Ok(findings.into_iter().map(Finding::from).collect())
    }

    /// Get the analyzer name.
    #[napi(getter)]
    pub fn name(&self) -> String {
        use llmtrace_core::SecurityAnalyzer;
        self.inner.name().to_string()
    }

    /// Get the analyzer version.
    #[napi(getter)]
    pub fn version(&self) -> String {
        use llmtrace_core::SecurityAnalyzer;
        self.inner.version().to_string()
    }

    /// Get the list of finding types this analyzer can detect.
    #[napi]
    pub fn supported_finding_types(&self) -> Vec<String> {
        use llmtrace_core::SecurityAnalyzer;
        self.inner.supported_finding_types()
    }
}

impl SecurityAnalyzer {
    fn run_analyze_request(&self, prompt: &str) -> napi::Result<Vec<Finding>> {
        use llmtrace_core::SecurityAnalyzer as _;
        let ctx = make_analysis_context();
        let findings = block_on(self.inner.analyze_request(prompt, &ctx))
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;
        Ok(findings.into_iter().map(Finding::from).collect())
    }

    fn run_analyze_response(&self, response: &str) -> napi::Result<Vec<Finding>> {
        use llmtrace_core::SecurityAnalyzer as _;
        let ctx = make_analysis_context();
        let findings = block_on(self.inner.analyze_response(response, &ctx))
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;
        Ok(findings.into_iter().map(Finding::from).collect())
    }
}

// ---------------------------------------------------------------------------
// CostEstimator class (standalone, same as WASM)
// ---------------------------------------------------------------------------

/// Pricing entry: cost per 1 million input/output tokens.
#[derive(Debug, Clone, Copy)]
struct Pricing {
    input_per_million: f64,
    output_per_million: f64,
}

/// Cost estimator for LLM API requests.
///
/// Ships with built-in pricing for common commercial models (OpenAI, Anthropic).
/// Custom pricing can be added via `addCustomModel`.
#[napi]
pub struct CostEstimator {
    builtin: HashMap<&'static str, Pricing>,
    custom: HashMap<String, Pricing>,
}

#[napi]
impl CostEstimator {
    /// Create a new cost estimator with built-in pricing.
    #[napi(constructor)]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            builtin: builtin_pricing(),
            custom: HashMap::new(),
        }
    }

    /// Estimate cost in USD for a request.
    ///
    /// Returns the estimated cost, or `null` if the model is not recognised.
    #[napi]
    pub fn estimate(
        &self,
        model: String,
        prompt_tokens: u32,
        completion_tokens: u32,
    ) -> Option<f64> {
        let pricing = self.lookup(&model)?;
        let input_cost = prompt_tokens as f64 * pricing.input_per_million / 1_000_000.0;
        let output_cost = completion_tokens as f64 * pricing.output_per_million / 1_000_000.0;
        Some(input_cost + output_cost)
    }

    /// Add custom pricing for a model (per 1 million tokens).
    #[napi]
    pub fn add_custom_model(
        &mut self,
        model: String,
        input_per_million: f64,
        output_per_million: f64,
    ) {
        self.custom.insert(
            model.to_lowercase(),
            Pricing {
                input_per_million,
                output_per_million,
            },
        );
    }

    /// List all known model names (built-in + custom).
    #[napi]
    pub fn known_models(&self) -> Vec<String> {
        let mut models: Vec<String> = self.builtin.keys().map(|k| (*k).to_string()).collect();
        for key in self.custom.keys() {
            if !models.contains(key) {
                models.push(key.clone());
            }
        }
        models.sort();
        models
    }
}

impl CostEstimator {
    fn lookup(&self, model: &str) -> Option<Pricing> {
        let lower = model.to_lowercase();

        if let Some(p) = self.custom.get(&lower) {
            return Some(*p);
        }
        if let Some(p) = self.builtin.get(lower.as_str()) {
            return Some(*p);
        }

        // Prefix match (longest wins)
        let mut best: Option<(&str, Pricing)> = None;
        for (&prefix, &pricing) in &self.builtin {
            if lower.starts_with(prefix) {
                match best {
                    Some((bp, _)) if prefix.len() <= bp.len() => {}
                    _ => best = Some((prefix, pricing)),
                }
            }
        }
        best.map(|(_, p)| p)
    }
}

/// Built-in pricing table for well-known commercial models.
fn builtin_pricing() -> HashMap<&'static str, Pricing> {
    let mut m = HashMap::new();
    m.insert(
        "gpt-4o-mini",
        Pricing {
            input_per_million: 0.15,
            output_per_million: 0.60,
        },
    );
    m.insert(
        "gpt-4o",
        Pricing {
            input_per_million: 2.50,
            output_per_million: 10.0,
        },
    );
    m.insert(
        "gpt-4",
        Pricing {
            input_per_million: 30.0,
            output_per_million: 60.0,
        },
    );
    m.insert(
        "gpt-3.5-turbo",
        Pricing {
            input_per_million: 0.50,
            output_per_million: 1.50,
        },
    );
    m.insert(
        "claude-3-5-sonnet",
        Pricing {
            input_per_million: 3.0,
            output_per_million: 15.0,
        },
    );
    m.insert(
        "claude-3.5-sonnet",
        Pricing {
            input_per_million: 3.0,
            output_per_million: 15.0,
        },
    );
    m.insert(
        "claude-3-5-haiku",
        Pricing {
            input_per_million: 0.80,
            output_per_million: 4.0,
        },
    );
    m.insert(
        "claude-3.5-haiku",
        Pricing {
            input_per_million: 0.80,
            output_per_million: 4.0,
        },
    );
    m.insert(
        "claude-3-opus",
        Pricing {
            input_per_million: 15.0,
            output_per_million: 75.0,
        },
    );
    m
}

// ---------------------------------------------------------------------------
// LLMSecTracer class — main tracing interface
// ---------------------------------------------------------------------------

/// LLM Security Tracer for instrumenting LLM calls.
///
/// Provides methods to create trace spans, record completions, attach
/// security findings, and report agent actions.
///
/// ```js
/// const tracer = new LlmSecTracer({ tenantId: "my-tenant" });
/// const span = tracer.startSpan({
///   operationName: "chat_completion",
///   provider: "OpenAI",
///   modelName: "gpt-4o",
///   prompt: "Hello, world!"
/// });
/// // ... make LLM call ...
/// tracer.finishSpan(span.spanId, { response: "Hi there!" });
/// const summary = tracer.getSummary();
/// ```
#[napi]
pub struct LlmSecTracer {
    tenant_id: String,
    analyzer: llmtrace_security::RegexSecurityAnalyzer,
    cost_estimator: CostEstimator,
    spans: HashMap<String, llmtrace_core::TraceSpan>,
    finished_spans: Vec<llmtrace_core::TraceSpan>,
}

/// Options for creating a new tracer.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct TracerOptions {
    /// Tenant identifier (used for all spans created by this tracer).
    pub tenant_id: Option<String>,
}

/// Options for starting a new span.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct StartSpanOptions {
    /// Operation name (e.g., "chat_completion", "embedding").
    pub operation_name: String,
    /// LLM provider name (e.g., "OpenAI", "Anthropic").
    pub provider: String,
    /// Model name (e.g., "gpt-4o", "claude-3-5-sonnet").
    pub model_name: String,
    /// The input prompt or messages.
    pub prompt: String,
    /// Optional parent span ID.
    pub parent_span_id: Option<String>,
}

/// Options for finishing a span.
#[napi(object)]
#[derive(Debug, Clone)]
pub struct FinishSpanOptions {
    /// The LLM response text.
    pub response: Option<String>,
    /// Error message if the request failed.
    pub error: Option<String>,
    /// HTTP status code.
    pub status_code: Option<u32>,
    /// Number of prompt tokens.
    pub prompt_tokens: Option<u32>,
    /// Number of completion tokens.
    pub completion_tokens: Option<u32>,
    /// Time to first token in milliseconds.
    pub time_to_first_token_ms: Option<f64>,
}

/// Summary of all traced spans.
#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerSummary {
    /// Total number of spans (active + finished).
    pub total_spans: u32,
    /// Number of active (unfinished) spans.
    pub active_spans: u32,
    /// Number of finished spans.
    pub finished_spans: u32,
    /// Total security findings across all spans.
    pub total_findings: u32,
    /// Total estimated cost in USD.
    pub total_cost_usd: f64,
    /// Highest security score across all spans.
    pub max_security_score: Option<u32>,
}

#[napi]
impl LlmSecTracer {
    /// Create a new LLM security tracer.
    #[napi(constructor)]
    pub fn new(options: Option<TracerOptions>) -> napi::Result<Self> {
        let tenant_id = options
            .and_then(|o| o.tenant_id)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        let analyzer = llmtrace_security::RegexSecurityAnalyzer::new()
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;

        Ok(Self {
            tenant_id,
            analyzer,
            cost_estimator: CostEstimator::new(),
            spans: HashMap::new(),
            finished_spans: Vec::new(),
        })
    }

    /// Start a new trace span. Returns span info including the generated span ID.
    #[napi]
    pub fn start_span(&mut self, options: StartSpanOptions) -> napi::Result<SpanInfo> {
        let provider = parse_provider(&options.provider);
        let tenant_id =
            llmtrace_core::TenantId(uuid::Uuid::parse_str(&self.tenant_id).unwrap_or_else(|_| {
                uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_DNS, self.tenant_id.as_bytes())
            }));
        let trace_id = uuid::Uuid::new_v4();

        let mut span = llmtrace_core::TraceSpan::new(
            trace_id,
            tenant_id,
            options.operation_name,
            provider,
            options.model_name,
            options.prompt.clone(),
        );

        if let Some(ref parent_id) = options.parent_span_id {
            span.parent_span_id = uuid::Uuid::parse_str(parent_id).ok();
        }

        // Run security analysis on the prompt
        let findings = self.analyze_prompt_internal(&options.prompt)?;
        for finding in findings {
            span.add_security_finding(finding);
        }

        let span_id = span.span_id.to_string();
        let info = SpanInfo {
            span_id: span_id.clone(),
            trace_id: span.trace_id.to_string(),
            operation_name: span.operation_name.clone(),
            provider: format!("{:?}", span.provider),
            model_name: span.model_name.clone(),
            duration_ms: None,
            security_score: span.security_score.map(|s| s as u32),
            findings_count: span.security_findings.len() as u32,
            estimated_cost_usd: None,
        };

        self.spans.insert(span_id, span);
        Ok(info)
    }

    /// Finish a span with a response or error.
    #[napi]
    pub fn finish_span(
        &mut self,
        span_id: String,
        options: FinishSpanOptions,
    ) -> napi::Result<SpanInfo> {
        let mut span = self
            .spans
            .remove(&span_id)
            .ok_or_else(|| napi::Error::from_reason(format!("Span not found: {span_id}")))?;

        // Finish the span
        if let Some(ref error) = options.error {
            span = span.finish_with_error(error.clone(), options.status_code.map(|c| c as u16));
        } else if let Some(ref response) = options.response {
            span = span.finish_with_response(response.clone());

            // Analyze the response for security issues
            let findings = self.analyze_response_internal(response)?;
            for finding in findings {
                span.add_security_finding(finding);
            }
        } else {
            // Just close the span without response
            span = span.finish_with_response(String::new());
        }

        // Set token counts
        if let Some(pt) = options.prompt_tokens {
            span.prompt_tokens = Some(pt);
        }
        if let Some(ct) = options.completion_tokens {
            span.completion_tokens = Some(ct);
        }
        if span.prompt_tokens.is_some() || span.completion_tokens.is_some() {
            span.total_tokens =
                Some(span.prompt_tokens.unwrap_or(0) + span.completion_tokens.unwrap_or(0));
        }
        if let Some(ttft) = options.time_to_first_token_ms {
            span.time_to_first_token_ms = Some(ttft as u64);
        }

        // Estimate cost
        if let (Some(pt), Some(ct)) = (span.prompt_tokens, span.completion_tokens) {
            span.estimated_cost_usd = self
                .cost_estimator
                .estimate(span.model_name.clone(), pt, ct);
        }

        let info = SpanInfo {
            span_id: span.span_id.to_string(),
            trace_id: span.trace_id.to_string(),
            operation_name: span.operation_name.clone(),
            provider: format!("{:?}", span.provider),
            model_name: span.model_name.clone(),
            duration_ms: span.duration_ms.map(|d| d as f64),
            security_score: span.security_score.map(|s| s as u32),
            findings_count: span.security_findings.len() as u32,
            estimated_cost_usd: span.estimated_cost_usd,
        };

        self.finished_spans.push(span);
        Ok(info)
    }

    /// Report agent actions for a span (analysed for security).
    #[napi]
    pub fn report_actions(
        &mut self,
        span_id: String,
        actions: Vec<AgentActionInput>,
    ) -> napi::Result<Vec<Finding>> {
        let span = self
            .spans
            .get_mut(&span_id)
            .ok_or_else(|| napi::Error::from_reason(format!("Span not found: {span_id}")))?;

        let core_actions: Vec<llmtrace_core::AgentAction> = actions
            .iter()
            .map(convert_action)
            .collect::<napi::Result<Vec<_>>>()?;

        // Analyze actions for security issues
        let findings = self.analyzer.analyze_agent_actions(&core_actions);

        // Add actions and findings to the span
        for action in core_actions {
            span.add_agent_action(action);
        }
        for finding in &findings {
            span.add_security_finding(finding.clone());
        }

        Ok(findings.into_iter().map(Finding::from).collect())
    }

    /// Get a summary of all traced spans.
    #[napi]
    pub fn get_summary(&self) -> TracerSummary {
        let active = self.spans.len() as u32;
        let finished = self.finished_spans.len() as u32;

        let mut total_findings = 0u32;
        let mut total_cost = 0.0f64;
        let mut max_score: Option<u32> = None;

        for span in self.spans.values().chain(self.finished_spans.iter()) {
            total_findings += span.security_findings.len() as u32;
            if let Some(cost) = span.estimated_cost_usd {
                total_cost += cost;
            }
            if let Some(score) = span.security_score {
                let s = score as u32;
                max_score = Some(max_score.map_or(s, |prev| prev.max(s)));
            }
        }

        TracerSummary {
            total_spans: active + finished,
            active_spans: active,
            finished_spans: finished,
            total_findings,
            total_cost_usd: total_cost,
            max_security_score: max_score,
        }
    }

    /// Get the tenant ID for this tracer.
    #[napi(getter)]
    pub fn tenant_id(&self) -> String {
        self.tenant_id.clone()
    }

    /// Export all finished spans as JSON.
    #[napi]
    pub fn export_spans(&self) -> napi::Result<String> {
        serde_json::to_string_pretty(&self.finished_spans)
            .map_err(|e| napi::Error::from_reason(e.to_string()))
    }

    /// Get all findings across all spans (active + finished).
    #[napi]
    pub fn get_all_findings(&self) -> Vec<Finding> {
        self.spans
            .values()
            .chain(self.finished_spans.iter())
            .flat_map(|span| span.security_findings.iter().cloned().map(Finding::from))
            .collect()
    }
}

impl LlmSecTracer {
    fn analyze_prompt_internal(
        &self,
        prompt: &str,
    ) -> napi::Result<Vec<llmtrace_core::SecurityFinding>> {
        use llmtrace_core::SecurityAnalyzer as _;
        let ctx = make_analysis_context();
        block_on(self.analyzer.analyze_request(prompt, &ctx))
            .map_err(|e| napi::Error::from_reason(e.to_string()))
    }

    fn analyze_response_internal(
        &self,
        response: &str,
    ) -> napi::Result<Vec<llmtrace_core::SecurityFinding>> {
        use llmtrace_core::SecurityAnalyzer as _;
        let ctx = make_analysis_context();
        block_on(self.analyzer.analyze_response(response, &ctx))
            .map_err(|e| napi::Error::from_reason(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Module-level convenience functions
// ---------------------------------------------------------------------------

/// Quick-check a prompt for security issues.
///
/// Creates a temporary analyzer for one-shot use.
/// Returns an array of findings.
#[napi]
pub fn check_prompt(prompt: String) -> napi::Result<Vec<Finding>> {
    let analyzer = SecurityAnalyzer::new()?;
    analyzer.analyze_prompt(prompt)
}

/// Quick-check a response for security issues.
#[napi]
pub fn check_response(response: String) -> napi::Result<Vec<Finding>> {
    let analyzer = SecurityAnalyzer::new()?;
    analyzer.analyze_response(response)
}

/// Quick estimate cost for a model request.
///
/// Returns the cost in USD, or `null` if the model is unknown.
#[napi]
pub fn estimate_cost(model: String, prompt_tokens: u32, completion_tokens: u32) -> Option<f64> {
    let estimator = CostEstimator::new();
    estimator.estimate(model, prompt_tokens, completion_tokens)
}

/// Instrument a simulated LLM call: analyze prompt, response, estimate cost.
///
/// Returns an object with findings and cost. This is a convenience function
/// for simple use cases that don't need full span tracking.
#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstrumentResult {
    /// Security findings from prompt and response analysis.
    pub findings: Vec<Finding>,
    /// Estimated cost in USD (null if model is unknown).
    pub estimated_cost_usd: Option<f64>,
    /// Highest severity found (null if no findings).
    pub max_severity: Option<String>,
    /// Overall security score (0–100, null if no findings).
    pub security_score: Option<u32>,
}

/// Instrument an LLM call by analyzing the prompt and response for security
/// issues and estimating cost.
#[napi]
pub fn instrument(
    prompt: String,
    response: String,
    model: String,
    prompt_tokens: Option<u32>,
    completion_tokens: Option<u32>,
) -> napi::Result<InstrumentResult> {
    let analyzer = SecurityAnalyzer::new()?;
    let mut findings = analyzer.analyze_prompt(prompt)?;
    findings.extend(analyzer.analyze_response(response)?);

    let estimated_cost_usd = match (prompt_tokens, completion_tokens) {
        (Some(pt), Some(ct)) => {
            let estimator = CostEstimator::new();
            estimator.estimate(model, pt, ct)
        }
        _ => None,
    };

    let max_severity = findings
        .iter()
        .map(|f| severity_rank(&f.severity))
        .max()
        .map(|rank| rank_to_severity(rank).to_string());

    let security_score = if findings.is_empty() {
        None
    } else {
        findings
            .iter()
            .map(|f| match f.severity.as_str() {
                "Critical" => 95u32,
                "High" => 80,
                "Medium" => 60,
                "Low" => 30,
                "Info" => 10,
                _ => 0,
            })
            .max()
    };

    Ok(InstrumentResult {
        findings,
        estimated_cost_usd,
        max_severity,
        security_score,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn severity_rank(s: &str) -> u8 {
    match s {
        "Critical" => 4,
        "High" => 3,
        "Medium" => 2,
        "Low" => 1,
        "Info" => 0,
        _ => 0,
    }
}

fn rank_to_severity(rank: u8) -> &'static str {
    match rank {
        4 => "Critical",
        3 => "High",
        2 => "Medium",
        1 => "Low",
        _ => "Info",
    }
}

fn parse_provider(s: &str) -> llmtrace_core::LLMProvider {
    match s.to_lowercase().as_str() {
        "openai" => llmtrace_core::LLMProvider::OpenAI,
        "anthropic" => llmtrace_core::LLMProvider::Anthropic,
        "vllm" => llmtrace_core::LLMProvider::VLLm,
        "sglang" => llmtrace_core::LLMProvider::SGLang,
        "tgi" => llmtrace_core::LLMProvider::TGI,
        "ollama" => llmtrace_core::LLMProvider::Ollama,
        "azureopenai" | "azure_openai" | "azure" => llmtrace_core::LLMProvider::AzureOpenAI,
        "bedrock" => llmtrace_core::LLMProvider::Bedrock,
        other => llmtrace_core::LLMProvider::Custom(other.to_string()),
    }
}

fn make_analysis_context() -> llmtrace_core::AnalysisContext {
    llmtrace_core::AnalysisContext {
        tenant_id: llmtrace_core::TenantId(uuid::Uuid::nil()),
        trace_id: uuid::Uuid::nil(),
        span_id: uuid::Uuid::nil(),
        provider: llmtrace_core::LLMProvider::Custom("node".to_string()),
        model_name: String::new(),
        parameters: HashMap::new(),
    }
}

/// Drive a future to completion on the current thread.
///
/// The futures produced by `RegexSecurityAnalyzer` are purely CPU-bound
/// (no I/O, no timers), so they complete in a single `poll` call.
fn block_on<F: std::future::Future<Output = T>, T>(fut: F) -> T {
    fn noop_clone(_: *const ()) -> RawWaker {
        noop_raw_waker()
    }
    fn noop(_: *const ()) {}
    fn noop_raw_waker() -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(noop_clone, noop, noop, noop);

    let waker = unsafe { Waker::from_raw(noop_raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = pin!(fut);

    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(val) => val,
        Poll::Pending => panic!("block_on: future was not ready (unexpected async I/O)"),
    }
}
