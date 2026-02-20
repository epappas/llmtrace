//! Core types, traits, and errors for LLMTrace
//!
//! This crate contains foundational types and traits shared across all LLMTrace components.
//! It provides the core data structures for representing traces, security findings, and
//! storage/analysis interfaces.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use utoipa::ToSchema;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Identity types
// ---------------------------------------------------------------------------

/// Unique identifier for a tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[schema(value_type = String, format = "uuid")]
pub struct TenantId(pub Uuid);

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TenantId {
    /// Create a new random tenant ID.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for TenantId {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RBAC & Auth types
// ---------------------------------------------------------------------------

/// Role for API key-based access control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ApiKeyRole {
    /// Full access: manage tenants, keys, read/write traces.
    Admin,
    /// Read + write traces, report actions; no tenant/key management.
    Operator,
    /// Read-only access to traces, spans, stats.
    Viewer,
}

impl ApiKeyRole {
    /// Check whether this role is at least as privileged as `required`.
    #[must_use]
    pub fn has_permission(self, required: ApiKeyRole) -> bool {
        self.privilege_level() >= required.privilege_level()
    }

    /// Numeric privilege level (higher = more privileged).
    fn privilege_level(self) -> u8 {
        match self {
            Self::Admin => 2,
            Self::Operator => 1,
            Self::Viewer => 0,
        }
    }
}

impl std::fmt::Display for ApiKeyRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Admin => write!(f, "admin"),
            Self::Operator => write!(f, "operator"),
            Self::Viewer => write!(f, "viewer"),
        }
    }
}

impl std::str::FromStr for ApiKeyRole {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "admin" => Ok(Self::Admin),
            "operator" => Ok(Self::Operator),
            "viewer" => Ok(Self::Viewer),
            _ => Err(format!("unknown role: {s}")),
        }
    }
}

/// A stored API key record (the plaintext key is never persisted).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApiKeyRecord {
    /// Unique identifier for this key.
    #[schema(value_type = String, format = "uuid")]
    pub id: Uuid,
    /// Tenant this key belongs to.
    pub tenant_id: TenantId,
    /// Human-readable name / label for the key.
    pub name: String,
    /// SHA-256 hex digest of the plaintext key.
    #[serde(skip_serializing)]
    pub key_hash: String,
    /// Key prefix for identification (e.g. `llmt_ab12...`).
    pub key_prefix: String,
    /// Role granted by this key.
    pub role: ApiKeyRole,
    /// When the key was created.
    #[schema(value_type = String, format = "date-time")]
    pub created_at: DateTime<Utc>,
    /// When the key was revoked (`None` if still active).
    #[schema(value_type = String, format = "date-time")]
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Authenticated context injected by the auth middleware.
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// Tenant the caller is authenticated as.
    pub tenant_id: TenantId,
    /// Role granted by the API key (or admin bootstrap key).
    pub role: ApiKeyRole,
    /// ID of the API key used (`None` for bootstrap admin key).
    pub key_id: Option<Uuid>,
}

// ---------------------------------------------------------------------------
// Security types
// ---------------------------------------------------------------------------

/// Metadata key for ensemble voting result ("majority" or "single_detector").
pub const VOTING_RESULT_KEY: &str = "voting_result";
/// Value indicating a finding was confirmed by multiple detectors.
pub const VOTING_MAJORITY: &str = "majority";
/// Value indicating a finding came from a single detector only.
pub const VOTING_SINGLE_DETECTOR: &str = "single_detector";

/// Returns `true` if a finding type is auxiliary (informational, not a direct
/// injection/attack indicator). Auxiliary findings should not drive the
/// security score above the flagging threshold on their own.
#[must_use]
pub fn is_auxiliary_finding_type(finding_type: &str) -> bool {
    matches!(
        finding_type,
        "is_hypothetical"
            | "is_incentive"
            | "is_urgent"
            | "is_systemic"
            | "is_covert"
            | "is_immoral"
            | "is_repeated_token"
            | "context_flooding"
    )
}

/// Pre-defined operating points that balance precision against recall.
///
/// Used in [`SecurityAnalysisConfig`] and mapped to per-category thresholds
/// by the ensemble analyzer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatingPoint {
    /// High recall, more false positives -- catch everything.
    HighRecall,
    /// Balanced precision and recall -- recommended default.
    #[default]
    Balanced,
    /// High precision, fewer false positives -- production-safe.
    HighPrecision,
}

/// Severity level for security findings.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
pub enum SecuritySeverity {
    /// Informational — no immediate action needed.
    Info,
    /// Low severity — minor issue.
    Low,
    /// Medium severity — should be addressed.
    Medium,
    /// High severity — prompt attention needed.
    High,
    /// Most severe — immediate attention required.
    Critical,
}

impl std::fmt::Display for SecuritySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "Info"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

impl std::str::FromStr for SecuritySeverity {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "Info" | "info" | "INFO" => Ok(Self::Info),
            "Low" | "low" | "LOW" => Ok(Self::Low),
            "Medium" | "medium" | "MEDIUM" => Ok(Self::Medium),
            "High" | "high" | "HIGH" => Ok(Self::High),
            "Critical" | "critical" | "CRITICAL" => Ok(Self::Critical),
            _ => Err(format!("unknown severity: {s}")),
        }
    }
}

/// A security finding detected during analysis.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SecurityFinding {
    /// Unique identifier for this finding.
    #[schema(value_type = String, format = "uuid")]
    pub id: Uuid,
    /// Severity level of the finding.
    pub severity: SecuritySeverity,
    /// Type of security issue (e.g., "prompt_injection", "pii_leak", "cost_anomaly").
    pub finding_type: String,
    /// Human-readable description of the finding.
    pub description: String,
    /// When the finding was detected.
    #[schema(value_type = String, format = "date-time")]
    pub detected_at: DateTime<Utc>,
    /// Confidence score (0.0 to 1.0).
    pub confidence_score: f64,
    /// Location where the issue was found (e.g., "request.messages[0]", "response.content").
    pub location: Option<String>,
    /// Additional metadata about the finding.
    #[schema(value_type = Object)]
    pub metadata: HashMap<String, String>,
    /// Whether this finding requires immediate alerting.
    pub requires_alert: bool,
}

impl SecurityFinding {
    /// Create a new security finding.
    pub fn new(
        severity: SecuritySeverity,
        finding_type: String,
        description: String,
        confidence_score: f64,
    ) -> Self {
        let requires_alert = matches!(
            severity,
            SecuritySeverity::Critical | SecuritySeverity::High
        );
        Self {
            id: Uuid::new_v4(),
            severity,
            finding_type,
            description,
            detected_at: Utc::now(),
            confidence_score,
            location: None,
            metadata: HashMap::new(),
            requires_alert,
        }
    }

    /// Set the location where this finding was detected.
    pub fn with_location(mut self, location: String) -> Self {
        self.location = Some(location);
        self
    }

    /// Add metadata to the finding.
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Set whether this finding requires immediate alerting.
    pub fn with_alert_required(mut self, requires_alert: bool) -> Self {
        self.requires_alert = requires_alert;
        self
    }
}

// ---------------------------------------------------------------------------
// LLM provider types
// ---------------------------------------------------------------------------

/// Supported LLM providers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum LLMProvider {
    OpenAI,
    Anthropic,
    VLLm,
    SGLang,
    TGI,
    Ollama,
    AzureOpenAI,
    Bedrock,
    Custom(String),
}

// ---------------------------------------------------------------------------
// Trace & Span types
// ---------------------------------------------------------------------------

/// A single span within a trace representing a portion of an LLM interaction.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TraceSpan {
    /// Unique identifier for the trace this span belongs to.
    #[schema(value_type = String, format = "uuid")]
    pub trace_id: Uuid,
    /// Unique identifier for this span.
    #[schema(value_type = String, format = "uuid")]
    pub span_id: Uuid,
    /// Parent span ID if this is a child span.
    #[schema(value_type = String, format = "uuid")]
    pub parent_span_id: Option<Uuid>,
    /// Tenant this span belongs to.
    pub tenant_id: TenantId,
    /// Name of the operation (e.g., "chat_completion", "embedding", "prompt_analysis").
    pub operation_name: String,
    /// When the span started.
    #[schema(value_type = String, format = "date-time")]
    pub start_time: DateTime<Utc>,
    /// When the span ended (None if still in progress).
    #[schema(value_type = String, format = "date-time")]
    pub end_time: Option<DateTime<Utc>>,
    /// LLM provider used for this span.
    pub provider: LLMProvider,
    /// Model name/identifier.
    pub model_name: String,
    /// The input prompt or messages.
    pub prompt: String,
    /// The response from the LLM (None if not yet completed).
    pub response: Option<String>,
    /// Number of tokens in the prompt.
    pub prompt_tokens: Option<u32>,
    /// Number of tokens in the completion/response.
    pub completion_tokens: Option<u32>,
    /// Total token count (prompt + completion).
    pub total_tokens: Option<u32>,
    /// Time to first token (TTFT) in milliseconds.
    pub time_to_first_token_ms: Option<u64>,
    /// Processing duration in milliseconds.
    pub duration_ms: Option<u64>,
    /// HTTP status code of the response.
    pub status_code: Option<u16>,
    /// Error message if the request failed.
    pub error_message: Option<String>,
    /// Estimated cost of this request in USD.
    pub estimated_cost_usd: Option<f64>,
    /// Overall security score (0-100, higher = more suspicious).
    pub security_score: Option<u8>,
    /// Security findings detected for this span.
    pub security_findings: Vec<SecurityFinding>,
    /// Custom tags and metadata.
    pub tags: HashMap<String, String>,
    /// Events that occurred during this span (e.g., streaming chunks, analysis results).
    pub events: Vec<SpanEvent>,
    /// Agent actions captured during this span (tool calls, commands, web access, etc.).
    #[serde(default)]
    pub agent_actions: Vec<AgentAction>,
}

impl TraceSpan {
    /// Create a new trace span.
    pub fn new(
        trace_id: Uuid,
        tenant_id: TenantId,
        operation_name: String,
        provider: LLMProvider,
        model_name: String,
        prompt: String,
    ) -> Self {
        Self {
            trace_id,
            span_id: Uuid::new_v4(),
            parent_span_id: None,
            tenant_id,
            operation_name,
            start_time: Utc::now(),
            end_time: None,
            provider,
            model_name,
            prompt,
            response: None,
            prompt_tokens: None,
            completion_tokens: None,
            total_tokens: None,
            time_to_first_token_ms: None,
            duration_ms: None,
            status_code: None,
            error_message: None,
            estimated_cost_usd: None,
            security_score: None,
            security_findings: Vec::new(),
            tags: HashMap::new(),
            events: Vec::new(),
            agent_actions: Vec::new(),
        }
    }

    /// Finish the span with a response.
    pub fn finish_with_response(mut self, response: String) -> Self {
        self.response = Some(response);
        let end_time = Utc::now();
        self.end_time = Some(end_time);
        self.duration_ms =
            Some((end_time.signed_duration_since(self.start_time)).num_milliseconds() as u64);
        self
    }

    /// Mark the span as failed with an error.
    pub fn finish_with_error(mut self, error: String, status_code: Option<u16>) -> Self {
        self.error_message = Some(error);
        self.status_code = status_code;
        let end_time = Utc::now();
        self.end_time = Some(end_time);
        self.duration_ms =
            Some((end_time.signed_duration_since(self.start_time)).num_milliseconds() as u64);
        self
    }

    /// Add a security finding to this span.
    pub fn add_security_finding(&mut self, finding: SecurityFinding) {
        self.security_findings.push(finding);
        let max_score = self
            .security_findings
            .iter()
            .map(|f| {
                let base = match f.severity {
                    SecuritySeverity::Critical => 95,
                    SecuritySeverity::High => 80,
                    SecuritySeverity::Medium => 60,
                    SecuritySeverity::Low => 30,
                    SecuritySeverity::Info => 10,
                };
                // Auxiliary (non-injection) findings: cap at 30 so they
                // don't cross the flagging threshold (50) on their own
                if is_auxiliary_finding_type(&f.finding_type) {
                    return base.min(30);
                }
                // Discount single-detector findings: cap at Medium (60)
                if f.metadata
                    .get(VOTING_RESULT_KEY)
                    .is_some_and(|v| v == VOTING_SINGLE_DETECTOR)
                {
                    base.min(60)
                } else {
                    base
                }
            })
            .max()
            .unwrap_or(0);
        self.security_score = Some(max_score as u8);
    }

    /// Add an event to this span.
    pub fn add_event(&mut self, event: SpanEvent) {
        self.events.push(event);
    }

    /// Add an agent action to this span.
    pub fn add_agent_action(&mut self, action: AgentAction) {
        self.agent_actions.push(action);
    }

    /// Return all tool call actions in this span.
    #[must_use]
    pub fn tool_calls(&self) -> Vec<&AgentAction> {
        self.agent_actions
            .iter()
            .filter(|a| a.action_type == AgentActionType::ToolCall)
            .collect()
    }

    /// Return all web access actions in this span.
    #[must_use]
    pub fn web_accesses(&self) -> Vec<&AgentAction> {
        self.agent_actions
            .iter()
            .filter(|a| a.action_type == AgentActionType::WebAccess)
            .collect()
    }

    /// Return all command execution actions in this span.
    #[must_use]
    pub fn commands(&self) -> Vec<&AgentAction> {
        self.agent_actions
            .iter()
            .filter(|a| a.action_type == AgentActionType::CommandExecution)
            .collect()
    }

    /// Check if this span has any tool call actions.
    #[must_use]
    pub fn has_tool_calls(&self) -> bool {
        self.agent_actions
            .iter()
            .any(|a| a.action_type == AgentActionType::ToolCall)
    }

    /// Check if this span has any web access actions.
    #[must_use]
    pub fn has_web_access(&self) -> bool {
        self.agent_actions
            .iter()
            .any(|a| a.action_type == AgentActionType::WebAccess)
    }

    /// Check if this span has any command execution actions.
    #[must_use]
    pub fn has_commands(&self) -> bool {
        self.agent_actions
            .iter()
            .any(|a| a.action_type == AgentActionType::CommandExecution)
    }

    /// Get the duration of this span.
    pub fn duration(&self) -> Option<Duration> {
        self.end_time.map(|end_time| {
            Duration::from_millis(
                end_time
                    .signed_duration_since(self.start_time)
                    .num_milliseconds() as u64,
            )
        })
    }

    /// Check if the span is complete.
    pub fn is_complete(&self) -> bool {
        self.end_time.is_some()
    }

    /// Check if the span failed.
    pub fn is_failed(&self) -> bool {
        self.error_message.is_some()
    }
}

// ---------------------------------------------------------------------------
// Agent action types
// ---------------------------------------------------------------------------

/// Maximum size in bytes for captured action results (stdout, response bodies, etc.).
pub const AGENT_ACTION_RESULT_MAX_BYTES: usize = 4096;

/// Type of agent action observed during an LLM interaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentActionType {
    /// LLM tool/function call (e.g. OpenAI `tool_calls`, Anthropic `tool_use`).
    ToolCall,
    /// Agent skill or plugin invocation.
    SkillInvocation,
    /// Shell command or subprocess execution.
    CommandExecution,
    /// HTTP request, curl, fetch, or browser action.
    WebAccess,
    /// File read, write, or delete operation.
    FileAccess,
}

impl std::fmt::Display for AgentActionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ToolCall => write!(f, "tool_call"),
            Self::SkillInvocation => write!(f, "skill_invocation"),
            Self::CommandExecution => write!(f, "command_execution"),
            Self::WebAccess => write!(f, "web_access"),
            Self::FileAccess => write!(f, "file_access"),
        }
    }
}

/// A single agent action captured during or after an LLM interaction.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AgentAction {
    /// Unique identifier for this action.
    #[schema(value_type = String, format = "uuid")]
    pub id: Uuid,
    /// Type of action.
    pub action_type: AgentActionType,
    /// Name of the tool, skill, command, URL, or file path.
    pub name: String,
    /// Arguments or parameters (JSON-encoded for tool calls, raw string otherwise).
    #[serde(default)]
    pub arguments: Option<String>,
    /// Result or output of the action (truncated to [`AGENT_ACTION_RESULT_MAX_BYTES`]).
    #[serde(default)]
    pub result: Option<String>,
    /// Duration of the action in milliseconds.
    #[serde(default)]
    pub duration_ms: Option<u64>,
    /// Whether the action succeeded.
    #[serde(default = "default_true")]
    pub success: bool,
    /// Exit code (for command executions).
    #[serde(default)]
    pub exit_code: Option<i32>,
    /// HTTP method (for web access).
    #[serde(default)]
    pub http_method: Option<String>,
    /// HTTP status code (for web access).
    #[serde(default)]
    pub http_status: Option<u16>,
    /// File operation type: "read", "write", "delete" (for file access).
    #[serde(default)]
    pub file_operation: Option<String>,
    /// When the action occurred.
    #[schema(value_type = String, format = "date-time")]
    pub timestamp: DateTime<Utc>,
    /// Additional metadata.
    #[schema(value_type = Object)]
    pub metadata: HashMap<String, String>,
}

fn default_true() -> bool {
    true
}

impl AgentAction {
    /// Create a new agent action.
    pub fn new(action_type: AgentActionType, name: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            action_type,
            name,
            arguments: None,
            result: None,
            duration_ms: None,
            success: true,
            exit_code: None,
            http_method: None,
            http_status: None,
            file_operation: None,
            timestamp: Utc::now(),
            metadata: HashMap::new(),
        }
    }

    /// Set the arguments for this action.
    pub fn with_arguments(mut self, arguments: String) -> Self {
        self.arguments = Some(arguments);
        self
    }

    /// Set the result, truncating to [`AGENT_ACTION_RESULT_MAX_BYTES`].
    pub fn with_result(mut self, result: String) -> Self {
        if result.len() > AGENT_ACTION_RESULT_MAX_BYTES {
            self.result = Some(result[..AGENT_ACTION_RESULT_MAX_BYTES].to_string());
        } else {
            self.result = Some(result);
        }
        self
    }

    /// Set the duration in milliseconds.
    pub fn with_duration_ms(mut self, ms: u64) -> Self {
        self.duration_ms = Some(ms);
        self
    }

    /// Mark the action as failed.
    pub fn with_failure(mut self) -> Self {
        self.success = false;
        self
    }

    /// Set the exit code (for command executions).
    pub fn with_exit_code(mut self, code: i32) -> Self {
        self.exit_code = Some(code);
        self
    }

    /// Set HTTP method and status (for web access).
    pub fn with_http(mut self, method: String, status: u16) -> Self {
        self.http_method = Some(method);
        self.http_status = Some(status);
        self
    }

    /// Set the file operation type (for file access).
    pub fn with_file_operation(mut self, op: String) -> Self {
        self.file_operation = Some(op);
        self
    }

    /// Add metadata to this action.
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
}

/// An event that occurred during a span.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SpanEvent {
    /// Unique identifier for the event.
    #[schema(value_type = String, format = "uuid")]
    pub id: Uuid,
    /// When the event occurred.
    #[schema(value_type = String, format = "date-time")]
    pub timestamp: DateTime<Utc>,
    /// Type of event (e.g., "token_received", "security_scan_completed", "error_occurred").
    pub event_type: String,
    /// Human-readable description.
    pub description: String,
    /// Event-specific data.
    #[schema(value_type = Object)]
    pub data: HashMap<String, String>,
}

impl SpanEvent {
    /// Create a new span event.
    pub fn new(event_type: String, description: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type,
            description,
            data: HashMap::new(),
        }
    }

    /// Add data to the event.
    pub fn with_data(mut self, key: String, value: String) -> Self {
        self.data.insert(key, value);
        self
    }
}

/// A complete trace event representing an LLM interaction.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TraceEvent {
    /// Unique trace identifier.
    #[schema(value_type = String, format = "uuid")]
    pub trace_id: Uuid,
    /// Tenant that owns this trace.
    pub tenant_id: TenantId,
    /// Spans within this trace.
    pub spans: Vec<TraceSpan>,
    /// When the trace was created.
    #[schema(value_type = String, format = "date-time")]
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Metadata types (tenants, configs, audit)
// ---------------------------------------------------------------------------

/// A tenant in the system.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Tenant {
    /// Unique tenant identifier.
    pub id: TenantId,
    /// Human-readable tenant name.
    pub name: String,
    /// Unique API token for proxy traffic.
    pub api_token: String,
    /// Subscription plan (e.g., "free", "pro", "enterprise").
    pub plan: String,
    /// When the tenant was created.
    #[schema(value_type = String, format = "date-time")]
    pub created_at: DateTime<Utc>,
    /// Arbitrary tenant-level configuration.
    #[schema(value_type = Object)]
    pub config: serde_json::Value,
}

/// Per-tenant configuration for security thresholds and feature flags.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TenantConfig {
    /// Tenant this configuration belongs to.
    pub tenant_id: TenantId,
    /// Security severity thresholds (e.g., "alert_min_score" → 80.0).
    #[schema(value_type = Object)]
    pub security_thresholds: HashMap<String, f64>,
    /// Feature flags (e.g., "enable_pii_detection" → true).
    #[schema(value_type = Object)]
    pub feature_flags: HashMap<String, bool>,
    /// Monitoring scope for this tenant.
    pub monitoring_scope: MonitoringScope,
    /// Rate limit in requests per minute (optional).
    pub rate_limit_rpm: Option<u32>,
    /// Monthly budget in USD (optional).
    pub monthly_budget: Option<f64>,
}

/// Controls which parts of an LLM interaction are stored/queried for a tenant.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MonitoringScope {
    /// Store both prompt and response (default).
    #[default]
    Hybrid,
    /// Store prompt only (do not store response).
    InputOnly,
    /// Store response only (do not store prompt).
    OutputOnly,
}

impl std::fmt::Display for MonitoringScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Hybrid => "hybrid",
            Self::InputOnly => "input_only",
            Self::OutputOnly => "output_only",
        };
        f.write_str(s)
    }
}

impl std::str::FromStr for MonitoringScope {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "hybrid" => Ok(Self::Hybrid),
            "input_only" => Ok(Self::InputOnly),
            "output_only" => Ok(Self::OutputOnly),
            other => Err(format!("Unknown monitoring scope: {other}")),
        }
    }
}

/// An audit log entry recording a tenant-scoped action.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuditEvent {
    /// Unique event identifier.
    #[schema(value_type = String, format = "uuid")]
    pub id: Uuid,
    /// Tenant this event belongs to.
    pub tenant_id: TenantId,
    /// Type of event (e.g., "config_changed", "tenant_created").
    pub event_type: String,
    /// Who performed the action.
    pub actor: String,
    /// What resource was affected.
    pub resource: String,
    /// Arbitrary event data.
    #[schema(value_type = Object)]
    pub data: serde_json::Value,
    /// When the event occurred.
    #[schema(value_type = String, format = "date-time")]
    pub timestamp: DateTime<Utc>,
}

/// A stored compliance report record for persistence.
///
/// Contains all data needed to persist and retrieve a compliance report
/// from the metadata repository.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ComplianceReportRecord {
    /// Unique report identifier.
    #[schema(value_type = String, format = "uuid")]
    pub id: Uuid,
    /// Tenant that requested the report.
    pub tenant_id: TenantId,
    /// Type of compliance report (e.g. "soc2", "gdpr", "hipaa").
    pub report_type: String,
    /// Current status: "pending", "completed", or "failed".
    pub status: String,
    /// Start of the reporting period.
    #[schema(value_type = String, format = "date-time")]
    pub period_start: DateTime<Utc>,
    /// End of the reporting period.
    #[schema(value_type = String, format = "date-time")]
    pub period_end: DateTime<Utc>,
    /// When the report was requested.
    #[schema(value_type = String, format = "date-time")]
    pub created_at: DateTime<Utc>,
    /// When the report generation completed (if finished).
    #[schema(value_type = String, format = "date-time")]
    pub completed_at: Option<DateTime<Utc>>,
    /// Report content as JSON (populated when status is "completed").
    #[schema(value_type = Object)]
    pub content: Option<serde_json::Value>,
    /// Error message (populated when status is "failed").
    pub error: Option<String>,
}

/// Query parameters for listing compliance reports.
#[derive(Debug, Clone, ToSchema)]
pub struct ReportQuery {
    /// Tenant to query reports for.
    pub tenant_id: TenantId,
    /// Maximum number of results.
    pub limit: Option<u32>,
    /// Number of results to skip (for pagination).
    pub offset: Option<u32>,
}

impl ReportQuery {
    /// Create a new report query for a tenant.
    pub fn new(tenant_id: TenantId) -> Self {
        Self {
            tenant_id,
            limit: None,
            offset: None,
        }
    }

    /// Set the result limit.
    pub fn with_limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set the offset for pagination.
    pub fn with_offset(mut self, offset: u32) -> Self {
        self.offset = Some(offset);
        self
    }
}

/// Query parameters for filtering audit events.
#[derive(Debug, Clone, ToSchema)]
pub struct AuditQuery {
    /// Tenant to query audit events for.
    pub tenant_id: TenantId,
    /// Filter by event type.
    pub event_type: Option<String>,
    /// Start time for the query range.
    #[schema(value_type = String, format = "date-time")]
    pub start_time: Option<DateTime<Utc>>,
    /// End time for the query range.
    #[schema(value_type = String, format = "date-time")]
    pub end_time: Option<DateTime<Utc>>,
    /// Maximum number of results.
    pub limit: Option<u32>,
    /// Number of results to skip (for pagination).
    pub offset: Option<u32>,
}

impl AuditQuery {
    /// Create a new audit query for a tenant.
    pub fn new(tenant_id: TenantId) -> Self {
        Self {
            tenant_id,
            event_type: None,
            start_time: None,
            end_time: None,
            limit: None,
            offset: None,
        }
    }

    /// Filter by event type.
    pub fn with_event_type(mut self, event_type: String) -> Self {
        self.event_type = Some(event_type);
        self
    }

    /// Set a time range filter.
    pub fn with_time_range(mut self, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        self.start_time = Some(start);
        self.end_time = Some(end);
        self
    }

    /// Set the result limit.
    pub fn with_limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }
}

// ---------------------------------------------------------------------------
// Configuration types
// ---------------------------------------------------------------------------

/// Configuration for the transparent proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Address and port to bind the proxy server to.
    pub listen_addr: String,
    /// Upstream URL for the LLM provider.
    pub upstream_url: String,
    /// Storage configuration section.
    #[serde(default)]
    pub storage: StorageConfig,
    /// Request timeout in milliseconds.
    pub timeout_ms: u64,
    /// Connection timeout in milliseconds.
    pub connection_timeout_ms: u64,
    /// Maximum number of concurrent connections.
    pub max_connections: u32,
    /// Enable TLS for the proxy server.
    pub enable_tls: bool,
    /// TLS certificate file path.
    pub tls_cert_file: Option<String>,
    /// TLS private key file path.
    pub tls_key_file: Option<String>,
    /// Enable security analysis of requests/responses.
    pub enable_security_analysis: bool,
    /// Enable trace storage.
    pub enable_trace_storage: bool,
    /// Enable streaming support.
    pub enable_streaming: bool,
    /// Maximum request body size in bytes.
    pub max_request_size_bytes: u64,
    /// Security analysis timeout in milliseconds.
    pub security_analysis_timeout_ms: u64,
    /// Trace storage timeout in milliseconds.
    pub trace_storage_timeout_ms: u64,
    /// Rate limiting configuration.
    pub rate_limiting: RateLimitConfig,
    /// Circuit breaker configuration.
    pub circuit_breaker: CircuitBreakerConfig,
    /// Health check configuration.
    pub health_check: HealthCheckConfig,
    /// Logging configuration.
    #[serde(default)]
    pub logging: LoggingConfig,
    /// Cost estimation configuration.
    #[serde(default)]
    pub cost_estimation: CostEstimationConfig,
    /// Alert engine configuration for webhook notifications.
    #[serde(default)]
    pub alerts: AlertConfig,
    /// Cost cap configuration for budget and token enforcement.
    #[serde(default)]
    pub cost_caps: CostCapConfig,
    /// Security analysis configuration (ML-based detection, thresholds).
    #[serde(default)]
    pub security_analysis: SecurityAnalysisConfig,
    /// Security enforcement configuration (pre-request blocking/flagging).
    #[serde(default)]
    pub enforcement: EnforcementConfig,
    /// OpenTelemetry OTLP ingestion configuration.
    #[serde(default)]
    pub otel_ingest: OtelIngestConfig,
    /// Authentication and RBAC configuration.
    #[serde(default)]
    pub auth: AuthConfig,
    /// gRPC ingestion gateway configuration.
    #[serde(default)]
    pub grpc: GrpcConfig,
    /// Anomaly detection configuration.
    #[serde(default)]
    pub anomaly_detection: AnomalyDetectionConfig,
    /// Streaming security analysis configuration.
    #[serde(default)]
    pub streaming_analysis: StreamingAnalysisConfig,
    /// PII detection and redaction configuration.
    #[serde(default)]
    pub pii: PiiConfig,
    /// Output safety configuration (toxicity detection, output analysis).
    #[serde(default)]
    pub output_safety: OutputSafetyConfig,
    /// Graceful shutdown configuration.
    #[serde(default)]
    pub shutdown: ShutdownConfig,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8080".to_string(),
            upstream_url: "https://api.openai.com".to_string(),
            storage: StorageConfig::default(),
            timeout_ms: 30000,
            connection_timeout_ms: 5000,
            max_connections: 1000,
            enable_tls: false,
            tls_cert_file: None,
            tls_key_file: None,
            enable_security_analysis: true,
            enable_trace_storage: true,
            enable_streaming: true,
            max_request_size_bytes: 50 * 1024 * 1024, // 50MB
            security_analysis_timeout_ms: 5000,
            trace_storage_timeout_ms: 10000,
            rate_limiting: RateLimitConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            health_check: HealthCheckConfig::default(),
            logging: LoggingConfig::default(),
            cost_estimation: CostEstimationConfig::default(),
            alerts: AlertConfig::default(),
            cost_caps: CostCapConfig::default(),
            security_analysis: SecurityAnalysisConfig::default(),
            enforcement: EnforcementConfig::default(),
            otel_ingest: OtelIngestConfig::default(),
            auth: AuthConfig::default(),
            grpc: GrpcConfig::default(),
            anomaly_detection: AnomalyDetectionConfig::default(),
            streaming_analysis: StreamingAnalysisConfig::default(),
            pii: PiiConfig::default(),
            output_safety: OutputSafetyConfig::default(),
            shutdown: ShutdownConfig::default(),
        }
    }
}

/// Storage configuration section within [`ProxyConfig`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Storage profile: `"lite"` (SQLite), `"memory"` (in-memory), or `"production"` (ClickHouse + PostgreSQL + Redis).
    #[serde(default = "default_storage_profile")]
    pub profile: String,
    /// Database file path (used by the `"lite"` profile).
    #[serde(default = "default_database_path")]
    pub database_path: String,
    /// ClickHouse HTTP URL (used by the `"production"` profile).
    #[serde(default)]
    pub clickhouse_url: Option<String>,
    /// ClickHouse database name (used by the `"production"` profile).
    #[serde(default)]
    pub clickhouse_database: Option<String>,
    /// PostgreSQL connection URL (used by the `"production"` profile).
    #[serde(default)]
    pub postgres_url: Option<String>,
    /// Redis connection URL (used by the `"production"` profile).
    #[serde(default)]
    pub redis_url: Option<String>,
    /// Automatically run pending database migrations on startup.
    ///
    /// Defaults to `true` for development (lite/memory profiles). Set to
    /// `false` in production to require explicit `llmtrace-proxy migrate`.
    #[serde(default = "default_auto_migrate")]
    pub auto_migrate: bool,
}

fn default_storage_profile() -> String {
    "lite".to_string()
}

fn default_database_path() -> String {
    "llmtrace.db".to_string()
}

fn default_auto_migrate() -> bool {
    true
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            profile: default_storage_profile(),
            database_path: default_database_path(),
            clickhouse_url: None,
            clickhouse_database: None,
            postgres_url: None,
            redis_url: None,
            auto_migrate: default_auto_migrate(),
        }
    }
}

/// Per-tenant rate limit override.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantRateLimitOverride {
    /// Requests per second for this tenant.
    pub requests_per_second: u32,
    /// Burst size for this tenant.
    pub burst_size: u32,
}

/// Rate limiting configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Enable rate limiting.
    pub enabled: bool,
    /// Default requests per second limit.
    pub requests_per_second: u32,
    /// Default burst size.
    pub burst_size: u32,
    /// Rate limiting window in seconds.
    pub window_seconds: u32,
    /// Per-tenant overrides keyed by tenant UUID string.
    #[serde(default)]
    pub tenant_overrides: HashMap<String, TenantRateLimitOverride>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_second: 100,
            burst_size: 200,
            window_seconds: 60,
            tenant_overrides: HashMap::new(),
        }
    }
}

/// Circuit breaker configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Enable circuit breaker.
    pub enabled: bool,
    /// Failure threshold before opening circuit.
    pub failure_threshold: u32,
    /// Recovery timeout in milliseconds.
    pub recovery_timeout_ms: u64,
    /// Half-open state max calls.
    pub half_open_max_calls: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            failure_threshold: 10,
            recovery_timeout_ms: 30000,
            half_open_max_calls: 3,
        }
    }
}

/// Health check configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// Enable health checks.
    pub enabled: bool,
    /// Health check endpoint path.
    pub path: String,
    /// Health check interval in seconds.
    pub interval_seconds: u32,
    /// Health check timeout in milliseconds.
    pub timeout_ms: u64,
    /// Number of retries before marking unhealthy.
    pub retries: u32,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: "/health".to_string(),
            interval_seconds: 10,
            timeout_ms: 5000,
            retries: 3,
        }
    }
}

/// Cost estimation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostEstimationConfig {
    /// Enable cost estimation on traced requests.
    #[serde(default = "default_cost_estimation_enabled")]
    pub enabled: bool,
    /// Optional path to an external pricing YAML/JSON file.
    ///
    /// When set, the proxy loads model pricing from this file at startup
    /// (and reloads on SIGHUP). If the file is missing, built-in defaults
    /// are used as a fallback.
    #[serde(default)]
    pub pricing_file: Option<String>,
    /// Custom model pricing overrides (model name → pricing).
    #[serde(default)]
    pub custom_models: HashMap<String, ModelPricingConfig>,
}

fn default_cost_estimation_enabled() -> bool {
    true
}

impl Default for CostEstimationConfig {
    fn default() -> Self {
        Self {
            enabled: default_cost_estimation_enabled(),
            pricing_file: None,
            custom_models: HashMap::new(),
        }
    }
}

/// Pricing for a single model (per 1 million tokens).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPricingConfig {
    /// Cost per 1 million input/prompt tokens in USD.
    pub input_per_million: f64,
    /// Cost per 1 million output/completion tokens in USD.
    pub output_per_million: f64,
}

// ---------------------------------------------------------------------------
// Cost cap types
// ---------------------------------------------------------------------------

/// Time window for budget enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum BudgetWindow {
    /// Rolling one-hour window.
    Hourly,
    /// Rolling one-day (24 h) window.
    Daily,
    /// Rolling seven-day window.
    Weekly,
    /// Rolling thirty-day window.
    Monthly,
}

impl BudgetWindow {
    /// Duration of this window in seconds.
    #[must_use]
    pub fn duration_secs(&self) -> u64 {
        match self {
            Self::Hourly => 3_600,
            Self::Daily => 86_400,
            Self::Weekly => 604_800,
            Self::Monthly => 2_592_000, // 30 days
        }
    }

    /// TTL for cache keys — slightly longer than the window so late
    /// writes are not lost.
    #[must_use]
    pub fn cache_ttl(&self) -> Duration {
        Duration::from_secs(self.duration_secs() + 300)
    }
}

impl std::fmt::Display for BudgetWindow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hourly => write!(f, "hourly"),
            Self::Daily => write!(f, "daily"),
            Self::Weekly => write!(f, "weekly"),
            Self::Monthly => write!(f, "monthly"),
        }
    }
}

/// A USD budget cap for a given time window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetCap {
    /// Which time window this cap applies to.
    pub window: BudgetWindow,
    /// Hard cap in USD — requests are rejected (429) when exceeded.
    pub hard_limit_usd: f64,
    /// Optional soft cap in USD — triggers an alert but allows the request.
    #[serde(default)]
    pub soft_limit_usd: Option<f64>,
}

/// Per-request token caps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenCap {
    /// Maximum prompt (input) tokens per request. `None` = unlimited.
    #[serde(default)]
    pub max_prompt_tokens: Option<u32>,
    /// Maximum completion (output) tokens per request. `None` = unlimited.
    #[serde(default)]
    pub max_completion_tokens: Option<u32>,
    /// Maximum total tokens per request. `None` = unlimited.
    #[serde(default)]
    pub max_total_tokens: Option<u32>,
}

/// Per-agent cost cap override.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCostCap {
    /// Agent identifier (matched against `X-LLMTrace-Agent-ID` header).
    pub agent_id: String,
    /// Budget caps that override the defaults for this agent.
    #[serde(default)]
    pub budget_caps: Vec<BudgetCap>,
    /// Token caps that override the defaults for this agent.
    #[serde(default)]
    pub token_cap: Option<TokenCap>,
}

/// Top-level cost cap configuration section within [`ProxyConfig`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CostCapConfig {
    /// Enable cost cap enforcement.
    #[serde(default)]
    pub enabled: bool,
    /// Default budget caps applied to all tenants/agents unless overridden.
    #[serde(default)]
    pub default_budget_caps: Vec<BudgetCap>,
    /// Default per-request token caps.
    #[serde(default)]
    pub default_token_cap: Option<TokenCap>,
    /// Per-agent overrides.
    #[serde(default)]
    pub agents: Vec<AgentCostCap>,
}

// ---------------------------------------------------------------------------
// Anomaly detection types
// ---------------------------------------------------------------------------

/// Type of anomaly detected.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyType {
    /// Abnormally high cost for a single request.
    CostSpike,
    /// Abnormally high token usage for a single request.
    TokenSpike,
    /// Abnormally high request velocity (requests per minute).
    VelocitySpike,
    /// Abnormally high response latency.
    LatencySpike,
}

impl std::fmt::Display for AnomalyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CostSpike => write!(f, "cost_spike"),
            Self::TokenSpike => write!(f, "token_spike"),
            Self::VelocitySpike => write!(f, "velocity_spike"),
            Self::LatencySpike => write!(f, "latency_spike"),
        }
    }
}

/// Anomaly detection configuration.
///
/// When enabled, the proxy tracks per-tenant moving averages and detects
/// statistical anomalies using a sliding window and sigma thresholds.
///
/// # Example (YAML)
///
/// ```yaml
/// anomaly_detection:
///   enabled: true
///   window_size: 100
///   sigma_threshold: 3.0
///   check_cost: true
///   check_tokens: true
///   check_velocity: true
///   check_latency: true
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyDetectionConfig {
    /// Enable anomaly detection.
    #[serde(default)]
    pub enabled: bool,
    /// Number of recent observations in the sliding window.
    #[serde(default = "default_anomaly_window_size")]
    pub window_size: usize,
    /// Sigma multiplier for anomaly threshold (default: 3.0).
    #[serde(default = "default_anomaly_sigma_threshold")]
    pub sigma_threshold: f64,
    /// Check for cost anomalies.
    #[serde(default = "default_true_flag")]
    pub check_cost: bool,
    /// Check for token usage anomalies.
    #[serde(default = "default_true_flag")]
    pub check_tokens: bool,
    /// Check for request velocity anomalies.
    #[serde(default = "default_true_flag")]
    pub check_velocity: bool,
    /// Check for latency anomalies.
    #[serde(default = "default_true_flag")]
    pub check_latency: bool,
}

fn default_anomaly_window_size() -> usize {
    100
}

fn default_anomaly_sigma_threshold() -> f64 {
    3.0
}

fn default_true_flag() -> bool {
    true
}

impl Default for AnomalyDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            window_size: default_anomaly_window_size(),
            sigma_threshold: default_anomaly_sigma_threshold(),
            check_cost: true,
            check_tokens: true,
            check_velocity: true,
            check_latency: true,
        }
    }
}

/// Configuration for real-time streaming security analysis.
///
/// When enabled, the proxy runs lightweight regex-based security pattern checks
/// incrementally during SSE streaming — every N tokens — producing interim
/// `SecurityFinding`s before the stream completes. This provides an early
/// warning layer; the full security analysis still runs after stream completion.
///
/// # Example (YAML)
///
/// ```yaml
/// streaming_analysis:
///   enabled: true
///   token_interval: 50
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamingAnalysisConfig {
    /// Enable incremental security analysis during SSE streaming.
    #[serde(default)]
    pub enabled: bool,
    /// Number of tokens between each incremental analysis check.
    #[serde(default = "default_streaming_token_interval")]
    pub token_interval: u32,
    /// Enable output-side analysis during SSE streaming (PII, secrets, toxicity on response content).
    #[serde(default)]
    pub output_enabled: bool,
    /// If a critical finding is detected mid-stream, inject a warning and stop.
    #[serde(default)]
    pub early_stop_on_critical: bool,
}

fn default_streaming_token_interval() -> u32 {
    50
}

impl Default for StreamingAnalysisConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            token_interval: default_streaming_token_interval(),
            output_enabled: false,
            early_stop_on_critical: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Output safety configuration
// ---------------------------------------------------------------------------

/// Output safety configuration for response content analysis.
///
/// When enabled, the proxy analyses LLM response content for toxicity,
/// PII leakage, secret exposure, and hallucination detection. This is a
/// post-processing step that runs after the upstream response is received.
///
/// # Example (YAML)
///
/// ```yaml
/// output_safety:
///   enabled: true
///   toxicity_enabled: true
///   toxicity_threshold: 0.7
///   block_on_critical: false
///   hallucination_enabled: false
///   hallucination_model: "vectara/hallucination_evaluation_model"
///   hallucination_threshold: 0.5
///   hallucination_min_response_length: 50
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputSafetyConfig {
    /// Enable output safety analysis on LLM responses.
    #[serde(default)]
    pub enabled: bool,
    /// Enable toxicity detection on response content.
    #[serde(default)]
    pub toxicity_enabled: bool,
    /// Confidence threshold for toxicity detection (0.0–1.0).
    #[serde(default = "default_toxicity_threshold")]
    pub toxicity_threshold: f32,
    /// Block (replace) the response if critical toxicity is detected.
    #[serde(default)]
    pub block_on_critical: bool,
    /// Enable hallucination detection on response content.
    ///
    /// When enabled, response sentences are scored against the user's prompt
    /// for factual consistency using a cross-encoder model.
    #[serde(default)]
    pub hallucination_enabled: bool,
    /// HuggingFace model ID for hallucination detection.
    #[serde(default = "default_hallucination_model")]
    pub hallucination_model: String,
    /// Threshold below which a sentence is considered potentially hallucinated
    /// (0.0–1.0). Sentences scoring below this are flagged.
    #[serde(default = "default_hallucination_threshold")]
    pub hallucination_threshold: f32,
    /// Minimum response length (in characters) to run hallucination detection.
    /// Responses shorter than this are skipped to save compute.
    #[serde(default = "default_hallucination_min_response_length")]
    pub hallucination_min_response_length: usize,
}

fn default_toxicity_threshold() -> f32 {
    0.7
}

fn default_hallucination_model() -> String {
    "vectara/hallucination_evaluation_model".to_string()
}

fn default_hallucination_threshold() -> f32 {
    0.5
}

fn default_hallucination_min_response_length() -> usize {
    50
}

impl Default for OutputSafetyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            toxicity_enabled: false,
            toxicity_threshold: default_toxicity_threshold(),
            block_on_critical: false,
            hallucination_enabled: false,
            hallucination_model: default_hallucination_model(),
            hallucination_threshold: default_hallucination_threshold(),
            hallucination_min_response_length: default_hallucination_min_response_length(),
        }
    }
}

// ---------------------------------------------------------------------------
// PII detection & redaction types
// ---------------------------------------------------------------------------

/// Action to take when PII is detected in request or response content.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PiiAction {
    /// Generate security findings but do not modify text (default).
    #[default]
    AlertOnly,
    /// Generate security findings *and* replace PII with `[PII:TYPE]` tags.
    AlertAndRedact,
    /// Replace PII silently without generating security findings.
    RedactSilent,
}

impl std::fmt::Display for PiiAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlertOnly => write!(f, "alert_only"),
            Self::AlertAndRedact => write!(f, "alert_and_redact"),
            Self::RedactSilent => write!(f, "redact_silent"),
        }
    }
}

/// PII detection and redaction configuration.
///
/// Controls how the security analyzer handles detected PII patterns.
///
/// # Example (YAML)
///
/// ```yaml
/// pii:
///   action: "alert_only"   # "alert_only" | "alert_and_redact" | "redact_silent"
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PiiConfig {
    /// Action to take when PII is detected.
    #[serde(default)]
    pub action: PiiAction,
}

/// Graceful shutdown configuration.
///
/// Controls how the proxy handles SIGTERM/SIGINT signals during Kubernetes
/// pod termination. The proxy drains in-flight connections, waits for
/// background tasks (trace capture, security analysis) to complete, and
/// then exits cleanly.
///
/// # Example (YAML)
///
/// ```yaml
/// shutdown:
///   timeout_seconds: 30
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownConfig {
    /// Maximum seconds to wait for in-flight tasks to complete after a
    /// shutdown signal is received. After this timeout the process exits
    /// regardless of pending work.
    #[serde(default = "default_shutdown_timeout_seconds")]
    pub timeout_seconds: u64,
}

fn default_shutdown_timeout_seconds() -> u64 {
    30
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: default_shutdown_timeout_seconds(),
        }
    }
}

/// Security analysis configuration for ML-based prompt injection detection.
///
/// Controls whether ML-based detection is enabled alongside regex-based analysis,
/// which HuggingFace model to use, the confidence threshold, and the local
/// model cache directory.
///
/// # Memory requirements
///
/// Each DeBERTa model requires ~400-600 MB of RAM. When `ml_enabled`,
/// `injecguard_enabled`, and `piguard_enabled` are all `true`, expect
/// ~1.2-1.8 GB total for three model instances. Plan host memory accordingly.
///
/// # Example (YAML)
///
/// ```yaml
/// security_analysis:
///   ml_enabled: true
///   ml_model: "protectai/deberta-v3-base-prompt-injection-v2"
///   ml_threshold: 0.8
///   ml_cache_dir: "~/.cache/llmtrace/models"
///   ml_preload: true
///   ml_download_timeout_seconds: 300
///   ner_enabled: true
///   ner_model: "dslim/bert-base-NER"
///   jailbreak_enabled: true
///   jailbreak_threshold: 0.7
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAnalysisConfig {
    /// Enable ML-based security analysis (requires `ml` feature in `llmtrace-security`).
    /// Enabled by default -- the Ensemble analyzer (regex + ML fusion) is the recommended path.
    #[serde(default = "default_ml_enabled")]
    pub ml_enabled: bool,
    /// HuggingFace model ID for ML-based prompt injection detection.
    #[serde(default = "default_ml_model")]
    pub ml_model: String,
    /// Confidence threshold for ML detection (0.0–1.0).
    #[serde(default = "default_ml_threshold")]
    pub ml_threshold: f64,
    /// Local cache directory for downloaded ML models.
    #[serde(default = "default_ml_cache_dir")]
    pub ml_cache_dir: String,
    /// Pre-load ML models at proxy startup rather than on first request.
    #[serde(default = "default_ml_preload")]
    pub ml_preload: bool,
    /// Timeout in seconds for downloading ML models at startup.
    #[serde(default = "default_ml_download_timeout_seconds")]
    pub ml_download_timeout_seconds: u64,
    /// Enable ML-based NER for PII detection (person names, orgs, locations).
    #[serde(default)]
    pub ner_enabled: bool,
    /// HuggingFace model ID for NER-based PII detection.
    #[serde(default = "default_ner_model")]
    pub ner_model: String,
    /// Enable feature-level fusion classifier (ADR-013).
    ///
    /// When `true`, the ensemble concatenates DeBERTa embeddings with heuristic
    /// feature vectors and feeds them through a learned fusion classifier instead
    /// of combining scores after independent classification.
    #[serde(default)]
    pub fusion_enabled: bool,
    /// Optional file path for trained fusion classifier weights.
    ///
    /// When `None`, the fusion classifier is initialised with random weights
    /// (suitable for architecture validation; not for production inference).
    #[serde(default)]
    pub fusion_model_path: Option<String>,
    /// Enable dedicated jailbreak detection (runs alongside prompt injection).
    ///
    /// When `true` (the default when security analysis is enabled), a separate
    /// jailbreak detector with heuristic patterns and encoding evasion checks
    /// is run on every request.
    #[serde(default = "default_jailbreak_enabled")]
    pub jailbreak_enabled: bool,
    /// Confidence threshold for jailbreak detection (0.0–1.0).
    #[serde(default = "default_jailbreak_threshold")]
    pub jailbreak_threshold: f32,
    /// Enable InjecGuard as a third injection detector in the Ensemble.
    ///
    /// When `true`, the ensemble uses majority voting (regex + ML + InjecGuard)
    /// to suppress false positives from individual detectors.
    /// Adds ~400-600 MB memory for the InjecGuard DeBERTa-v3 model.
    #[serde(default)]
    pub injecguard_enabled: bool,
    /// HuggingFace model ID for the InjecGuard model.
    #[serde(default = "default_injecguard_model")]
    pub injecguard_model: String,
    /// Confidence threshold for InjecGuard detection (0.0-1.0).
    #[serde(default = "default_injecguard_threshold")]
    pub injecguard_threshold: f64,
    /// Enable PIGuard as an additional injection detector in the Ensemble.
    ///
    /// PIGuard uses DeBERTa + MOF (Mitigating Over-defense for Free) training
    /// to reduce trigger-word false positives. Adds ~400-600 MB memory.
    #[serde(default)]
    pub piguard_enabled: bool,
    /// HuggingFace model ID for the PIGuard model.
    #[serde(default = "default_piguard_model")]
    pub piguard_model: String,
    /// Confidence threshold for PIGuard detection (0.0-1.0).
    #[serde(default = "default_piguard_threshold")]
    pub piguard_threshold: f64,
    /// Operating point for ensemble thresholds.
    #[serde(default)]
    pub operating_point: OperatingPoint,
    /// Enable over-defence suppression to reduce false positives on benign content.
    #[serde(default)]
    pub over_defence: bool,
}

fn default_ml_enabled() -> bool {
    true
}

fn default_ml_model() -> String {
    "protectai/deberta-v3-base-prompt-injection-v2".to_string()
}

fn default_ml_threshold() -> f64 {
    0.8
}

fn default_ml_cache_dir() -> String {
    "~/.cache/llmtrace/models".to_string()
}

fn default_ml_preload() -> bool {
    true
}

fn default_ml_download_timeout_seconds() -> u64 {
    300
}

fn default_ner_model() -> String {
    "dslim/bert-base-NER".to_string()
}

fn default_jailbreak_enabled() -> bool {
    true
}

fn default_jailbreak_threshold() -> f32 {
    0.7
}

fn default_injecguard_model() -> String {
    "leolee99/InjecGuard".to_string()
}

fn default_injecguard_threshold() -> f64 {
    0.85
}

fn default_piguard_model() -> String {
    "leolee99/PIGuard".to_string()
}

fn default_piguard_threshold() -> f64 {
    0.85
}

impl Default for SecurityAnalysisConfig {
    fn default() -> Self {
        Self {
            ml_enabled: default_ml_enabled(),
            ml_model: default_ml_model(),
            ml_threshold: default_ml_threshold(),
            ml_cache_dir: default_ml_cache_dir(),
            ml_preload: default_ml_preload(),
            ml_download_timeout_seconds: default_ml_download_timeout_seconds(),
            ner_enabled: false,
            ner_model: default_ner_model(),
            fusion_enabled: false,
            fusion_model_path: None,
            jailbreak_enabled: default_jailbreak_enabled(),
            jailbreak_threshold: default_jailbreak_threshold(),
            injecguard_enabled: false,
            injecguard_model: default_injecguard_model(),
            injecguard_threshold: default_injecguard_threshold(),
            piguard_enabled: false,
            piguard_model: default_piguard_model(),
            piguard_threshold: default_piguard_threshold(),
            operating_point: OperatingPoint::default(),
            over_defence: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Enforcement configuration
// ---------------------------------------------------------------------------

/// Enforcement mode for the proxy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    /// Log findings only (current behavior). Default for backward compat.
    #[default]
    Log,
    /// Block requests that trigger enforcement. Return 403.
    Block,
    /// Forward to upstream but attach finding metadata as response headers.
    Flag,
}

/// Analysis depth for enforcement.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisDepth {
    /// Regex-only analysis. Near-zero added latency.
    #[default]
    Fast,
    /// Full ensemble analysis (regex + ML). Adds ML inference latency.
    Full,
}

/// Per-category enforcement override.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryEnforcement {
    /// The finding type to match (e.g. "prompt_injection", "jailbreak").
    pub finding_type: String,
    /// Enforcement action for this category.
    pub action: EnforcementMode,
}

fn default_enforcement_min_severity() -> SecuritySeverity {
    SecuritySeverity::High
}

fn default_enforcement_min_confidence() -> f64 {
    0.8
}

fn default_enforcement_timeout_ms() -> u64 {
    2000
}

/// Security enforcement configuration.
///
/// Controls whether the proxy acts on security findings before forwarding
/// requests upstream. Default is `log` mode (current behavior unchanged).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementConfig {
    /// Default enforcement mode.
    #[serde(default)]
    pub mode: EnforcementMode,
    /// Analysis depth: "fast" (regex only) or "full" (regex + ML ensemble).
    #[serde(default)]
    pub analysis_depth: AnalysisDepth,
    /// Minimum severity level to enforce on.
    #[serde(default = "default_enforcement_min_severity")]
    pub min_severity: SecuritySeverity,
    /// Minimum confidence score to enforce on (0.0-1.0).
    #[serde(default = "default_enforcement_min_confidence")]
    pub min_confidence: f64,
    /// Timeout for enforcement analysis in milliseconds. Fail-open on timeout.
    #[serde(default = "default_enforcement_timeout_ms")]
    pub timeout_ms: u64,
    /// Per-category enforcement overrides.
    #[serde(default)]
    pub categories: Vec<CategoryEnforcement>,
}

impl Default for EnforcementConfig {
    fn default() -> Self {
        Self {
            mode: EnforcementMode::Log,
            analysis_depth: AnalysisDepth::Fast,
            min_severity: default_enforcement_min_severity(),
            min_confidence: default_enforcement_min_confidence(),
            timeout_ms: default_enforcement_timeout_ms(),
            categories: Vec::new(),
        }
    }
}

/// OpenTelemetry OTLP ingestion configuration.
///
/// When enabled, the proxy exposes `POST /v1/traces` to accept traces in
/// the standard OTLP/HTTP format (JSON and protobuf).
///
/// # Example (YAML)
///
/// ```yaml
/// otel_ingest:
///   enabled: true
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OtelIngestConfig {
    /// Enable the OTLP/HTTP ingestion endpoint.
    #[serde(default)]
    pub enabled: bool,
}

/// Authentication and RBAC configuration.
///
/// When `enabled` is `true`, every request (except `/health`) must carry
/// a valid API key in the `Authorization: Bearer <key>` header. The
/// `admin_key` serves as a bootstrap key for initial setup.
///
/// # Example (YAML)
///
/// ```yaml
/// auth:
///   enabled: true
///   admin_key: "llmt_bootstrap_secret"
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Enable API-key authentication and RBAC enforcement.
    #[serde(default)]
    pub enabled: bool,
    /// Bootstrap admin key — grants full admin access when auth is enabled.
    /// This key is not stored hashed; it's compared directly from config.
    #[serde(default)]
    pub admin_key: Option<String>,
}

/// gRPC ingestion gateway configuration.
///
/// When enabled, the proxy starts a `tonic` gRPC server on a separate
/// listen address that accepts traces in the LLMTrace-native protobuf
/// format. Supports both unary and client-streaming ingestion RPCs.
///
/// # Example (YAML)
///
/// ```yaml
/// grpc:
///   enabled: true
///   listen_addr: "0.0.0.0:50051"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcConfig {
    /// Enable the gRPC ingestion endpoint.
    #[serde(default)]
    pub enabled: bool,
    /// Address and port to bind the gRPC server to.
    #[serde(default = "default_grpc_listen_addr")]
    pub listen_addr: String,
}

fn default_grpc_listen_addr() -> String {
    "0.0.0.0:50051".to_string()
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: default_grpc_listen_addr(),
        }
    }
}

/// Alert engine configuration for webhook notifications.
///
/// Supports both a legacy single-webhook mode (via `webhook_url`) and a
/// multi-channel mode (via `channels`). When `channels` is non-empty it
/// takes precedence; otherwise the legacy `webhook_url` is wrapped in a
/// single `WebhookChannelConfig` for backward compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    /// Enable the alert engine.
    #[serde(default)]
    pub enabled: bool,
    /// **Legacy** — Webhook URL to POST alert payloads to.
    /// Ignored when `channels` is non-empty.
    #[serde(default)]
    pub webhook_url: String,
    /// **Legacy** — Minimum severity level (e.g. `"High"`).
    /// Used as the global default when `channels` is empty.
    #[serde(default = "default_alert_min_severity")]
    pub min_severity: String,
    /// **Legacy** — Minimum confidence-based score (0–100).
    #[serde(default = "default_alert_min_security_score")]
    pub min_security_score: u8,
    /// Cooldown in seconds between repeated alerts for the same finding type.
    #[serde(default = "default_alert_cooldown_seconds")]
    pub cooldown_seconds: u64,
    /// Multi-channel alert destinations.
    /// When non-empty, each channel has its own type, URL, and min_severity.
    #[serde(default)]
    pub channels: Vec<AlertChannelConfig>,
    /// Optional escalation configuration.
    #[serde(default)]
    pub escalation: Option<AlertEscalationConfig>,
}

/// Configuration for a single alert channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertChannelConfig {
    /// Channel type: `"webhook"`, `"slack"`, `"pagerduty"`, or `"email"`.
    #[serde(rename = "type")]
    pub channel_type: String,
    /// Webhook / Slack incoming-webhook URL.
    #[serde(default)]
    pub url: Option<String>,
    /// Alias accepted for `url` (convenience for webhook channels).
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// PagerDuty Events API v2 routing key.
    #[serde(default)]
    pub routing_key: Option<String>,
    /// Minimum severity to send to this channel (default: `"High"`).
    #[serde(default = "default_alert_min_severity")]
    pub min_severity: String,
    /// Minimum confidence-based score (0–100) to send to this channel.
    #[serde(default = "default_alert_min_security_score")]
    pub min_security_score: u8,
}

impl AlertChannelConfig {
    /// Resolve the effective URL (prefers `url`, falls back to `webhook_url`).
    pub fn effective_url(&self) -> Option<&str> {
        self.url
            .as_deref()
            .or(self.webhook_url.as_deref())
            .filter(|s| !s.is_empty())
    }
}

/// Optional alert escalation configuration.
///
/// If no acknowledgement is received within `escalate_after_seconds`, the
/// alert is re-sent at the next higher severity channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEscalationConfig {
    /// Enable escalation.
    #[serde(default)]
    pub enabled: bool,
    /// Seconds to wait before escalating an unacknowledged alert.
    #[serde(default = "default_escalation_seconds")]
    pub escalate_after_seconds: u64,
}

fn default_escalation_seconds() -> u64 {
    600
}

fn default_alert_min_severity() -> String {
    "High".to_string()
}

fn default_alert_min_security_score() -> u8 {
    70
}

fn default_alert_cooldown_seconds() -> u64 {
    300
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            webhook_url: String::new(),
            min_severity: default_alert_min_severity(),
            min_security_score: default_alert_min_security_score(),
            cooldown_seconds: default_alert_cooldown_seconds(),
            channels: Vec::new(),
            escalation: None,
        }
    }
}

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level: `trace`, `debug`, `info`, `warn`, or `error`.
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Output format: `text` (human-readable) or `json` (structured).
    #[serde(default = "default_log_format")]
    pub format: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "text".to_string()
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Core error types.
#[derive(thiserror::Error, Debug)]
pub enum LLMTraceError {
    /// Storage layer error.
    #[error("Storage error: {0}")]
    Storage(String),

    /// Security analysis error.
    #[error("Security analysis error: {0}")]
    Security(String),

    /// Serialization / deserialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Invalid tenant identifier.
    #[error("Invalid tenant: {tenant_id}")]
    InvalidTenant {
        /// The invalid tenant ID.
        tenant_id: TenantId,
    },

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),
}

/// Convenience alias for `std::result::Result<T, LLMTraceError>`.
pub type Result<T> = std::result::Result<T, LLMTraceError>;

// ---------------------------------------------------------------------------
// Query types
// ---------------------------------------------------------------------------

/// Query parameters for filtering traces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceQuery {
    /// Tenant to query traces for.
    pub tenant_id: TenantId,
    /// Start time for the query range.
    pub start_time: Option<DateTime<Utc>>,
    /// End time for the query range.
    pub end_time: Option<DateTime<Utc>>,
    /// Filter by provider.
    pub provider: Option<LLMProvider>,
    /// Filter by model name.
    pub model_name: Option<String>,
    /// Filter by operation name.
    pub operation_name: Option<String>,
    /// Minimum security score to include.
    pub min_security_score: Option<u8>,
    /// Maximum security score to include.
    pub max_security_score: Option<u8>,
    /// Filter by trace ID.
    pub trace_id: Option<Uuid>,
    /// Filter by tags.
    pub tags: HashMap<String, String>,
    /// Maximum number of results to return.
    pub limit: Option<u32>,
    /// Number of results to skip (for pagination).
    pub offset: Option<u32>,
}

impl TraceQuery {
    /// Create a new trace query for a tenant.
    pub fn new(tenant_id: TenantId) -> Self {
        Self {
            tenant_id,
            start_time: None,
            end_time: None,
            provider: None,
            model_name: None,
            operation_name: None,
            min_security_score: None,
            max_security_score: None,
            trace_id: None,
            tags: HashMap::new(),
            limit: None,
            offset: None,
        }
    }

    /// Add a time range filter.
    pub fn with_time_range(mut self, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        self.start_time = Some(start);
        self.end_time = Some(end);
        self
    }

    /// Add a provider filter.
    pub fn with_provider(mut self, provider: LLMProvider) -> Self {
        self.provider = Some(provider);
        self
    }

    /// Add a security score range filter.
    pub fn with_security_score_range(mut self, min: u8, max: u8) -> Self {
        self.min_security_score = Some(min);
        self.max_security_score = Some(max);
        self
    }

    /// Set the limit.
    pub fn with_limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }
}

// ---------------------------------------------------------------------------
// Storage statistics
// ---------------------------------------------------------------------------

/// Storage statistics for a tenant.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct StorageStats {
    /// Total number of traces stored.
    pub total_traces: u64,
    /// Total number of spans stored.
    pub total_spans: u64,
    /// Storage size in bytes.
    pub storage_size_bytes: u64,
    /// Oldest trace timestamp.
    #[schema(value_type = String, format = "date-time")]
    pub oldest_trace: Option<DateTime<Utc>>,
    /// Newest trace timestamp.
    #[schema(value_type = String, format = "date-time")]
    pub newest_trace: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// Repository traits (storage layer abstraction)
// ---------------------------------------------------------------------------

/// Repository for trace and span storage (analytical, high-volume data).
///
/// Dev/Lite: SQLite. Production: ClickHouse.
#[async_trait::async_trait]
pub trait TraceRepository: Send + Sync {
    /// Store a trace event with all its spans.
    async fn store_trace(&self, trace: &TraceEvent) -> Result<()>;

    /// Store a single trace span.
    async fn store_span(&self, span: &TraceSpan) -> Result<()>;

    /// Query traces with filters.
    async fn query_traces(&self, query: &TraceQuery) -> Result<Vec<TraceEvent>>;

    /// Query spans with filters.
    async fn query_spans(&self, query: &TraceQuery) -> Result<Vec<TraceSpan>>;

    /// Get a specific trace by ID.
    async fn get_trace(&self, tenant_id: TenantId, trace_id: Uuid) -> Result<Option<TraceEvent>>;

    /// Get a specific span by ID.
    async fn get_span(&self, tenant_id: TenantId, span_id: Uuid) -> Result<Option<TraceSpan>>;

    /// Delete traces older than the specified time.
    async fn delete_traces_before(&self, tenant_id: TenantId, before: DateTime<Utc>)
        -> Result<u64>;

    /// Get storage statistics for a tenant.
    async fn get_stats(&self, tenant_id: TenantId) -> Result<StorageStats>;

    /// Get aggregate statistics across all tenants (cluster-wide).
    async fn get_global_stats(&self) -> Result<StorageStats>;

    /// Health check for the trace repository.
    async fn health_check(&self) -> Result<()>;
}

/// Repository for metadata (tenants, configs, audit events).
///
/// Dev/Lite: SQLite. Production: PostgreSQL.
#[async_trait::async_trait]
pub trait MetadataRepository: Send + Sync {
    /// Create a new tenant.
    async fn create_tenant(&self, tenant: &Tenant) -> Result<()>;

    /// Get a tenant by ID.
    async fn get_tenant(&self, id: TenantId) -> Result<Option<Tenant>>;

    /// Get a tenant by its API token.
    async fn get_tenant_by_token(&self, token: &str) -> Result<Option<Tenant>>;

    /// Update an existing tenant.
    async fn update_tenant(&self, tenant: &Tenant) -> Result<()>;

    /// List all tenants.
    async fn list_tenants(&self) -> Result<Vec<Tenant>>;

    /// Delete a tenant by ID.
    async fn delete_tenant(&self, id: TenantId) -> Result<()>;

    /// Get the configuration for a tenant.
    async fn get_tenant_config(&self, tenant_id: TenantId) -> Result<Option<TenantConfig>>;

    /// Create or update tenant configuration.
    async fn upsert_tenant_config(&self, config: &TenantConfig) -> Result<()>;

    /// Record an audit event.
    async fn record_audit_event(&self, event: &AuditEvent) -> Result<()>;

    /// Query audit events.
    async fn query_audit_events(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>>;

    // -- API key management --------------------------------------------------

    /// Store a new API key record (the plaintext key is NOT stored — only its hash).
    async fn create_api_key(&self, key: &ApiKeyRecord) -> Result<()>;

    /// Look up an active (non-revoked) API key by its SHA-256 hash.
    async fn get_api_key_by_hash(&self, key_hash: &str) -> Result<Option<ApiKeyRecord>>;

    /// List all API keys for a tenant (includes revoked keys).
    async fn list_api_keys(&self, tenant_id: TenantId) -> Result<Vec<ApiKeyRecord>>;

    /// Revoke an API key by setting its `revoked_at` timestamp.
    async fn revoke_api_key(&self, key_id: Uuid) -> Result<bool>;

    // -- Compliance report persistence ---------------------------------------

    /// Store a compliance report (insert or update).
    async fn store_report(&self, report: &ComplianceReportRecord) -> Result<()>;

    /// Get a compliance report by ID.
    async fn get_report(&self, report_id: Uuid) -> Result<Option<ComplianceReportRecord>>;

    /// List compliance reports for a tenant with pagination.
    async fn list_reports(&self, query: &ReportQuery) -> Result<Vec<ComplianceReportRecord>>;

    /// Health check for the metadata repository.
    async fn health_check(&self) -> Result<()>;
}

/// Cache layer for hot queries and sessions.
///
/// Dev/Lite: In-memory `DashMap`. Production: Redis.
#[async_trait::async_trait]
pub trait CacheLayer: Send + Sync {
    /// Get a cached value by key.
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;

    /// Set a cached value with a TTL.
    async fn set(&self, key: &str, value: &[u8], ttl: Duration) -> Result<()>;

    /// Invalidate (remove) a cached entry.
    async fn invalidate(&self, key: &str) -> Result<()>;

    /// Health check for the cache layer.
    async fn health_check(&self) -> Result<()>;
}

// ---------------------------------------------------------------------------
// Composite Storage struct
// ---------------------------------------------------------------------------

/// Composite storage that wires together the three repository concerns.
///
/// Consumers receive a single `Storage` value instead of managing three
/// separate `Arc<dyn …>` handles.
pub struct Storage {
    /// Trace & span repository (analytical, high-volume).
    pub traces: Arc<dyn TraceRepository>,
    /// Metadata repository (tenants, configs, audit).
    pub metadata: Arc<dyn MetadataRepository>,
    /// Cache layer (hot queries, sessions).
    pub cache: Arc<dyn CacheLayer>,
}

// ---------------------------------------------------------------------------
// Analysis context & SecurityAnalyzer trait
// ---------------------------------------------------------------------------

/// Analysis context for security analyzers.
#[derive(Debug, Clone)]
pub struct AnalysisContext {
    /// Tenant ID for context.
    pub tenant_id: TenantId,
    /// Trace ID for context.
    pub trace_id: Uuid,
    /// Span ID for context.
    pub span_id: Uuid,
    /// LLM provider being used.
    pub provider: LLMProvider,
    /// Model name.
    pub model_name: String,
    /// Custom analysis parameters.
    pub parameters: HashMap<String, String>,
}

/// Trait for security analyzers.
#[async_trait::async_trait]
pub trait SecurityAnalyzer: Send + Sync {
    /// Analyze a request for security issues.
    async fn analyze_request(
        &self,
        prompt: &str,
        context: &AnalysisContext,
    ) -> Result<Vec<SecurityFinding>>;

    /// Analyze a response for security issues.
    async fn analyze_response(
        &self,
        response: &str,
        context: &AnalysisContext,
    ) -> Result<Vec<SecurityFinding>>;

    /// Analyze a complete request/response pair.
    async fn analyze_interaction(
        &self,
        prompt: &str,
        response: &str,
        context: &AnalysisContext,
    ) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();
        findings.extend(self.analyze_request(prompt, context).await?);
        findings.extend(self.analyze_response(response, context).await?);
        Ok(findings)
    }

    /// Get the analyzer name.
    fn name(&self) -> &'static str;

    /// Get the analyzer version.
    fn version(&self) -> &'static str;

    /// Get supported security finding types.
    fn supported_finding_types(&self) -> Vec<String>;

    /// Check if the analyzer is healthy.
    async fn health_check(&self) -> Result<()>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_id_creation() {
        let tenant1 = TenantId::new();
        let tenant2 = TenantId::new();
        assert_ne!(tenant1, tenant2);
    }

    #[test]
    fn test_tenant_id_display() {
        let tenant_id = TenantId::new();
        let display_str = format!("{}", tenant_id);
        let uuid_str = format!("{}", tenant_id.0);
        assert_eq!(display_str, uuid_str);
    }

    #[test]
    fn test_security_finding_creation() {
        let finding = SecurityFinding::new(
            SecuritySeverity::High,
            "prompt_injection".to_string(),
            "Detected system prompt override attempt".to_string(),
            0.95,
        );

        assert_eq!(finding.severity, SecuritySeverity::High);
        assert_eq!(finding.finding_type, "prompt_injection");
        assert!(finding.requires_alert);
        assert_eq!(finding.confidence_score, 0.95);
        assert!(finding.metadata.is_empty());
    }

    #[test]
    fn test_security_finding_with_metadata() {
        let finding = SecurityFinding::new(
            SecuritySeverity::Medium,
            "pii_detection".to_string(),
            "Found potential PII".to_string(),
            0.8,
        )
        .with_location("request.messages[0].content".to_string())
        .with_metadata("pii_type".to_string(), "email".to_string())
        .with_alert_required(true);

        assert_eq!(
            finding.location,
            Some("request.messages[0].content".to_string())
        );
        assert_eq!(finding.metadata.get("pii_type"), Some(&"email".to_string()));
        assert!(finding.requires_alert);
    }

    #[test]
    fn test_trace_span_creation() {
        let tenant_id = TenantId::new();
        let trace_id = Uuid::new_v4();

        let span = TraceSpan::new(
            trace_id,
            tenant_id,
            "chat_completion".to_string(),
            LLMProvider::OpenAI,
            "gpt-4".to_string(),
            "Hello, how are you?".to_string(),
        );

        assert_eq!(span.trace_id, trace_id);
        assert_eq!(span.tenant_id, tenant_id);
        assert_eq!(span.operation_name, "chat_completion");
        assert_eq!(span.provider, LLMProvider::OpenAI);
        assert!(span.response.is_none());
        assert!(!span.is_complete());
        assert!(!span.is_failed());
    }

    #[test]
    fn test_trace_span_completion() {
        let span = TraceSpan::new(
            Uuid::new_v4(),
            TenantId::new(),
            "test_op".to_string(),
            LLMProvider::OpenAI,
            "gpt-3.5-turbo".to_string(),
            "test prompt".to_string(),
        );

        let completed_span = span.finish_with_response("test response".to_string());

        assert_eq!(completed_span.response, Some("test response".to_string()));
        assert!(completed_span.is_complete());
        assert!(!completed_span.is_failed());
        assert!(completed_span.end_time.is_some());
        assert!(completed_span.duration_ms.is_some());
    }

    #[test]
    fn test_trace_span_error() {
        let span = TraceSpan::new(
            Uuid::new_v4(),
            TenantId::new(),
            "test_op".to_string(),
            LLMProvider::OpenAI,
            "gpt-4".to_string(),
            "test prompt".to_string(),
        );

        let failed_span = span.finish_with_error("API timeout".to_string(), Some(504));

        assert!(failed_span.is_failed());
        assert!(failed_span.is_complete());
        assert_eq!(failed_span.error_message, Some("API timeout".to_string()));
        assert_eq!(failed_span.status_code, Some(504));
    }

    #[test]
    fn test_trace_span_security_findings() {
        let mut span = TraceSpan::new(
            Uuid::new_v4(),
            TenantId::new(),
            "test_op".to_string(),
            LLMProvider::OpenAI,
            "gpt-4".to_string(),
            "test prompt".to_string(),
        );

        let finding = SecurityFinding::new(
            SecuritySeverity::Critical,
            "prompt_injection".to_string(),
            "Malicious prompt detected".to_string(),
            0.98,
        );

        span.add_security_finding(finding);

        assert_eq!(span.security_findings.len(), 1);
        assert_eq!(span.security_score, Some(95));
    }

    #[test]
    fn test_span_event_creation() {
        let event = SpanEvent::new(
            "token_received".to_string(),
            "First token received from LLM".to_string(),
        )
        .with_data("token".to_string(), "Hello".to_string())
        .with_data("position".to_string(), "0".to_string());

        assert_eq!(event.event_type, "token_received");
        assert_eq!(event.data.get("token"), Some(&"Hello".to_string()));
        assert_eq!(event.data.get("position"), Some(&"0".to_string()));
    }

    #[test]
    fn test_trace_query_creation() {
        let tenant_id = TenantId::new();
        let provider = LLMProvider::Anthropic;
        let start_time = Utc::now() - chrono::Duration::hours(24);
        let end_time = Utc::now();

        let query = TraceQuery::new(tenant_id)
            .with_time_range(start_time, end_time)
            .with_provider(provider.clone())
            .with_security_score_range(80, 100)
            .with_limit(50);

        assert_eq!(query.tenant_id, tenant_id);
        assert_eq!(query.start_time, Some(start_time));
        assert_eq!(query.end_time, Some(end_time));
        assert_eq!(query.provider, Some(provider));
        assert_eq!(query.min_security_score, Some(80));
        assert_eq!(query.max_security_score, Some(100));
        assert_eq!(query.limit, Some(50));
    }

    #[test]
    fn test_proxy_config_default() {
        let config = ProxyConfig::default();

        assert_eq!(config.listen_addr, "0.0.0.0:8080");
        assert!(config.enable_security_analysis);
        assert!(config.enable_trace_storage);
        assert!(config.enable_streaming);
        assert_eq!(config.timeout_ms, 30000);
        assert_eq!(config.max_connections, 1000);
        assert!(!config.enable_tls);
        assert_eq!(config.logging.level, "info");
        assert_eq!(config.logging.format, "text");
        assert!(config.cost_estimation.enabled);
        assert!(config.cost_estimation.custom_models.is_empty());
    }

    #[test]
    fn test_storage_config_default() {
        let config = StorageConfig::default();
        assert_eq!(config.profile, "lite");
        assert_eq!(config.database_path, "llmtrace.db");
        assert!(config.clickhouse_url.is_none());
        assert!(config.clickhouse_database.is_none());
        assert!(config.postgres_url.is_none());
        assert!(config.redis_url.is_none());
    }

    #[test]
    fn test_logging_config_default() {
        let config = LoggingConfig::default();
        assert_eq!(config.level, "info");
        assert_eq!(config.format, "text");
    }

    #[test]
    fn test_logging_config_serialization() {
        let config = LoggingConfig {
            level: "debug".to_string(),
            format: "json".to_string(),
        };
        let serialized = serde_json::to_string(&config).unwrap();
        let deserialized: LoggingConfig = serde_json::from_str(&serialized).unwrap();
        assert_eq!(config.level, deserialized.level);
        assert_eq!(config.format, deserialized.format);
    }

    #[test]
    fn test_rate_limit_config_default() {
        let config = RateLimitConfig::default();

        assert!(config.enabled);
        assert_eq!(config.requests_per_second, 100);
        assert_eq!(config.burst_size, 200);
        assert_eq!(config.window_seconds, 60);
    }

    #[test]
    fn test_circuit_breaker_config_default() {
        let config = CircuitBreakerConfig::default();

        assert!(config.enabled);
        assert_eq!(config.failure_threshold, 10);
        assert_eq!(config.recovery_timeout_ms, 30000);
        assert_eq!(config.half_open_max_calls, 3);
    }

    #[test]
    fn test_health_check_config_default() {
        let config = HealthCheckConfig::default();

        assert!(config.enabled);
        assert_eq!(config.path, "/health");
        assert_eq!(config.interval_seconds, 10);
        assert_eq!(config.timeout_ms, 5000);
        assert_eq!(config.retries, 3);
    }

    #[test]
    fn test_llm_provider_serialization() {
        let providers = vec![
            LLMProvider::OpenAI,
            LLMProvider::Anthropic,
            LLMProvider::VLLm,
            LLMProvider::SGLang,
            LLMProvider::TGI,
            LLMProvider::Ollama,
            LLMProvider::AzureOpenAI,
            LLMProvider::Bedrock,
            LLMProvider::Custom("CustomProvider".to_string()),
        ];

        for provider in providers {
            let serialized = serde_json::to_string(&provider).unwrap();
            let deserialized: LLMProvider = serde_json::from_str(&serialized).unwrap();
            assert_eq!(provider, deserialized);
        }
    }

    #[test]
    fn test_security_severity_ordering() {
        assert!(SecuritySeverity::Critical > SecuritySeverity::High);
        assert!(SecuritySeverity::High > SecuritySeverity::Medium);
        assert!(SecuritySeverity::Medium > SecuritySeverity::Low);
        assert!(SecuritySeverity::Low > SecuritySeverity::Info);
    }

    #[test]
    fn test_trace_serialization() {
        let tenant_id = TenantId::new();
        let trace_id = Uuid::new_v4();

        let span = TraceSpan::new(
            trace_id,
            tenant_id,
            "chat_completion".to_string(),
            LLMProvider::OpenAI,
            "gpt-4".to_string(),
            "Hello, world!".to_string(),
        );

        let trace = TraceEvent {
            trace_id,
            tenant_id,
            spans: vec![span],
            created_at: Utc::now(),
        };

        let serialized = serde_json::to_string(&trace).unwrap();
        let deserialized: TraceEvent = serde_json::from_str(&serialized).unwrap();

        assert_eq!(trace.trace_id, deserialized.trace_id);
        assert_eq!(trace.tenant_id, deserialized.tenant_id);
        assert_eq!(trace.spans.len(), deserialized.spans.len());
    }

    #[test]
    fn test_security_finding_serialization() {
        let finding = SecurityFinding::new(
            SecuritySeverity::High,
            "prompt_injection".to_string(),
            "Detected system prompt override attempt".to_string(),
            0.95,
        )
        .with_location("request.messages[0]".to_string())
        .with_metadata("pattern".to_string(), "ignore_previous".to_string());

        let serialized = serde_json::to_string(&finding).unwrap();
        let deserialized: SecurityFinding = serde_json::from_str(&serialized).unwrap();

        assert_eq!(finding.severity, deserialized.severity);
        assert_eq!(finding.finding_type, deserialized.finding_type);
        assert_eq!(finding.confidence_score, deserialized.confidence_score);
        assert_eq!(finding.location, deserialized.location);
        assert_eq!(finding.metadata, deserialized.metadata);
    }

    #[test]
    fn test_trace_span_serialization() {
        let mut span = TraceSpan::new(
            Uuid::new_v4(),
            TenantId::new(),
            "embedding".to_string(),
            LLMProvider::OpenAI,
            "text-embedding-ada-002".to_string(),
            "Test embedding text".to_string(),
        );

        let event = SpanEvent::new(
            "embedding_complete".to_string(),
            "Embedding calculation completed".to_string(),
        );
        span.add_event(event);

        let finding = SecurityFinding::new(
            SecuritySeverity::Low,
            "pii_detection".to_string(),
            "Potential email address detected".to_string(),
            0.7,
        );
        span.add_security_finding(finding);

        let serialized = serde_json::to_string(&span).unwrap();
        let deserialized: TraceSpan = serde_json::from_str(&serialized).unwrap();

        assert_eq!(span.trace_id, deserialized.trace_id);
        assert_eq!(span.operation_name, deserialized.operation_name);
        assert_eq!(span.provider, deserialized.provider);
        assert_eq!(span.events.len(), deserialized.events.len());
        assert_eq!(
            span.security_findings.len(),
            deserialized.security_findings.len()
        );
    }

    #[test]
    fn test_proxy_config_serialization() {
        let mut custom_models = HashMap::new();
        custom_models.insert(
            "my-custom-model".to_string(),
            ModelPricingConfig {
                input_per_million: 1.0,
                output_per_million: 2.0,
            },
        );

        let config = ProxyConfig {
            listen_addr: "127.0.0.1:9090".to_string(),
            upstream_url: "https://api.anthropic.com".to_string(),
            storage: StorageConfig {
                profile: "lite".to_string(),
                database_path: "test.db".to_string(),
                clickhouse_url: None,
                clickhouse_database: None,
                postgres_url: None,
                redis_url: None,
                auto_migrate: true,
            },
            timeout_ms: 60000,
            connection_timeout_ms: 10000,
            max_connections: 2000,
            enable_tls: true,
            tls_cert_file: Some("/etc/ssl/cert.pem".to_string()),
            tls_key_file: Some("/etc/ssl/key.pem".to_string()),
            enable_security_analysis: true,
            enable_trace_storage: true,
            enable_streaming: true,
            max_request_size_bytes: 100 * 1024 * 1024,
            security_analysis_timeout_ms: 3000,
            trace_storage_timeout_ms: 5000,
            rate_limiting: RateLimitConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            health_check: HealthCheckConfig::default(),
            logging: LoggingConfig {
                level: "debug".to_string(),
                format: "json".to_string(),
            },
            cost_estimation: CostEstimationConfig {
                enabled: true,
                pricing_file: None,
                custom_models,
            },
            alerts: AlertConfig::default(),
            cost_caps: CostCapConfig::default(),
            security_analysis: SecurityAnalysisConfig {
                ml_enabled: true,
                ml_model: "custom/model".to_string(),
                ml_threshold: 0.9,
                ml_cache_dir: "/tmp/models".to_string(),
                ml_preload: true,
                ml_download_timeout_seconds: 300,
                ner_enabled: false,
                ner_model: default_ner_model(),
                fusion_enabled: false,
                fusion_model_path: None,
                jailbreak_enabled: true,
                jailbreak_threshold: 0.7,
                injecguard_enabled: false,
                injecguard_model: default_injecguard_model(),
                injecguard_threshold: default_injecguard_threshold(),
                piguard_enabled: false,
                piguard_model: default_piguard_model(),
                piguard_threshold: default_piguard_threshold(),
                operating_point: OperatingPoint::default(),
                over_defence: false,
            },
            otel_ingest: OtelIngestConfig::default(),
            auth: AuthConfig::default(),
            grpc: GrpcConfig::default(),
            anomaly_detection: AnomalyDetectionConfig::default(),
            streaming_analysis: StreamingAnalysisConfig::default(),
            pii: PiiConfig {
                action: PiiAction::AlertAndRedact,
            },
            output_safety: OutputSafetyConfig::default(),
            shutdown: ShutdownConfig::default(),
            enforcement: EnforcementConfig::default(),
        };

        let serialized = serde_json::to_string(&config).unwrap();
        let deserialized: ProxyConfig = serde_json::from_str(&serialized).unwrap();

        assert_eq!(config.listen_addr, deserialized.listen_addr);
        assert_eq!(config.upstream_url, deserialized.upstream_url);
        assert_eq!(config.enable_tls, deserialized.enable_tls);
        assert_eq!(config.tls_cert_file, deserialized.tls_cert_file);
        assert_eq!(config.storage.profile, deserialized.storage.profile);
        assert_eq!(
            config.storage.database_path,
            deserialized.storage.database_path
        );
        assert_eq!(config.logging.level, deserialized.logging.level);
        assert_eq!(config.logging.format, deserialized.logging.format);
        assert_eq!(deserialized.pii.action, PiiAction::AlertAndRedact);
        assert!(deserialized.cost_estimation.enabled);
        let custom = deserialized
            .cost_estimation
            .custom_models
            .get("my-custom-model")
            .unwrap();
        assert!((custom.input_per_million - 1.0).abs() < f64::EPSILON);
        assert!((custom.output_per_million - 2.0).abs() < f64::EPSILON);
        assert!(deserialized.security_analysis.ml_enabled);
        assert_eq!(deserialized.security_analysis.ml_model, "custom/model");
        assert!(!deserialized.grpc.enabled);
        assert_eq!(deserialized.grpc.listen_addr, "0.0.0.0:50051");
    }

    #[test]
    fn test_trace_query_serialization() {
        let query = TraceQuery::new(TenantId::new())
            .with_time_range(Utc::now() - chrono::Duration::hours(1), Utc::now())
            .with_provider(LLMProvider::Anthropic)
            .with_limit(100);

        let serialized = serde_json::to_string(&query).unwrap();
        let deserialized: TraceQuery = serde_json::from_str(&serialized).unwrap();

        assert_eq!(query.tenant_id, deserialized.tenant_id);
        assert_eq!(query.provider, deserialized.provider);
        assert_eq!(query.limit, deserialized.limit);
    }

    #[test]
    fn test_storage_stats_serialization() {
        let stats = StorageStats {
            total_traces: 12345,
            total_spans: 67890,
            storage_size_bytes: 1024 * 1024 * 1024, // 1GB
            oldest_trace: Some(Utc::now() - chrono::Duration::days(30)),
            newest_trace: Some(Utc::now()),
        };

        let serialized = serde_json::to_string(&stats).unwrap();
        let deserialized: StorageStats = serde_json::from_str(&serialized).unwrap();

        assert_eq!(stats.total_traces, deserialized.total_traces);
        assert_eq!(stats.total_spans, deserialized.total_spans);
        assert_eq!(stats.storage_size_bytes, deserialized.storage_size_bytes);
    }

    #[test]
    fn test_tenant_creation() {
        let tenant = Tenant {
            id: TenantId::new(),
            name: "Acme Corp".to_string(),
            api_token: "test-token".to_string(),
            plan: "pro".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({"max_traces_per_day": 10000}),
        };

        let serialized = serde_json::to_string(&tenant).unwrap();
        let deserialized: Tenant = serde_json::from_str(&serialized).unwrap();
        assert_eq!(tenant.id, deserialized.id);
        assert_eq!(tenant.name, deserialized.name);
        assert_eq!(tenant.plan, deserialized.plan);
    }

    #[test]
    fn test_tenant_config_creation() {
        let mut thresholds = HashMap::new();
        thresholds.insert("alert_min_score".to_string(), 80.0);

        let mut flags = HashMap::new();
        flags.insert("enable_pii_detection".to_string(), true);

        let config = TenantConfig {
            tenant_id: TenantId::new(),
            security_thresholds: thresholds,
            feature_flags: flags,
            monitoring_scope: MonitoringScope::Hybrid,
            rate_limit_rpm: None,
            monthly_budget: None,
        };

        let serialized = serde_json::to_string(&config).unwrap();
        let deserialized: TenantConfig = serde_json::from_str(&serialized).unwrap();
        assert_eq!(config.tenant_id, deserialized.tenant_id);
        assert_eq!(
            config.security_thresholds.get("alert_min_score"),
            deserialized.security_thresholds.get("alert_min_score")
        );
    }

    #[test]
    fn test_audit_event_creation() {
        let event = AuditEvent {
            id: Uuid::new_v4(),
            tenant_id: TenantId::new(),
            event_type: "config_changed".to_string(),
            actor: "admin@example.com".to_string(),
            resource: "tenant_config".to_string(),
            data: serde_json::json!({"field": "enable_pii_detection", "old": false, "new": true}),
            timestamp: Utc::now(),
        };

        let serialized = serde_json::to_string(&event).unwrap();
        let deserialized: AuditEvent = serde_json::from_str(&serialized).unwrap();
        assert_eq!(event.id, deserialized.id);
        assert_eq!(event.event_type, deserialized.event_type);
        assert_eq!(event.actor, deserialized.actor);
    }

    #[test]
    fn test_audit_query_builder() {
        let tenant = TenantId::new();
        let start = Utc::now() - chrono::Duration::hours(1);
        let end = Utc::now();

        let query = AuditQuery::new(tenant)
            .with_event_type("config_changed".to_string())
            .with_time_range(start, end)
            .with_limit(50);

        assert_eq!(query.tenant_id, tenant);
        assert_eq!(query.event_type, Some("config_changed".to_string()));
        assert_eq!(query.start_time, Some(start));
        assert_eq!(query.end_time, Some(end));
        assert_eq!(query.limit, Some(50));
    }

    #[test]
    fn test_alert_config_default() {
        let config = AlertConfig::default();
        assert!(!config.enabled);
        assert!(config.webhook_url.is_empty());
        assert_eq!(config.min_severity, "High");
        assert_eq!(config.min_security_score, 70);
        assert_eq!(config.cooldown_seconds, 300);
        assert!(config.channels.is_empty());
        assert!(config.escalation.is_none());
    }

    #[test]
    fn test_alert_config_serialization() {
        let config = AlertConfig {
            enabled: true,
            webhook_url: "https://hooks.slack.com/services/T00/B00/xxx".to_string(),
            min_severity: "Critical".to_string(),
            min_security_score: 90,
            cooldown_seconds: 600,
            channels: Vec::new(),
            escalation: None,
        };
        let serialized = serde_json::to_string(&config).unwrap();
        let deserialized: AlertConfig = serde_json::from_str(&serialized).unwrap();
        assert_eq!(config.enabled, deserialized.enabled);
        assert_eq!(config.webhook_url, deserialized.webhook_url);
        assert_eq!(config.min_severity, deserialized.min_severity);
        assert_eq!(config.min_security_score, deserialized.min_security_score);
        assert_eq!(config.cooldown_seconds, deserialized.cooldown_seconds);
    }

    #[test]
    fn test_alert_config_deserializes_with_defaults() {
        let json = r#"{"enabled": true, "webhook_url": "http://example.com"}"#;
        let config: AlertConfig = serde_json::from_str(json).unwrap();
        assert!(config.enabled);
        assert_eq!(config.webhook_url, "http://example.com");
        assert_eq!(config.min_severity, "High");
        assert_eq!(config.min_security_score, 70);
        assert_eq!(config.cooldown_seconds, 300);
        assert!(config.channels.is_empty());
    }

    #[test]
    fn test_alert_config_multi_channel() {
        let json = r#"{
            "enabled": true,
            "cooldown_seconds": 120,
            "channels": [
                {"type": "slack", "url": "https://hooks.slack.com/services/T/B/x", "min_severity": "Medium"},
                {"type": "pagerduty", "routing_key": "abc123", "min_severity": "Critical"},
                {"type": "webhook", "url": "https://example.com/hook", "min_severity": "High"}
            ]
        }"#;
        let config: AlertConfig = serde_json::from_str(json).unwrap();
        assert!(config.enabled);
        assert_eq!(config.channels.len(), 3);
        assert_eq!(config.channels[0].channel_type, "slack");
        assert_eq!(config.channels[0].min_severity, "Medium");
        assert_eq!(config.channels[1].channel_type, "pagerduty");
        assert_eq!(config.channels[1].routing_key.as_deref(), Some("abc123"));
        assert_eq!(config.channels[2].channel_type, "webhook");
    }

    #[test]
    fn test_alert_channel_config_effective_url() {
        // Prefers `url` over `webhook_url`
        let cfg = AlertChannelConfig {
            channel_type: "webhook".to_string(),
            url: Some("https://primary.com".to_string()),
            webhook_url: Some("https://fallback.com".to_string()),
            routing_key: None,
            min_severity: "High".to_string(),
            min_security_score: 70,
        };
        assert_eq!(cfg.effective_url(), Some("https://primary.com"));

        // Falls back to `webhook_url`
        let cfg2 = AlertChannelConfig {
            url: None,
            webhook_url: Some("https://fallback.com".to_string()),
            ..cfg.clone()
        };
        assert_eq!(cfg2.effective_url(), Some("https://fallback.com"));

        // Empty strings treated as None
        let cfg3 = AlertChannelConfig {
            url: Some(String::new()),
            webhook_url: None,
            ..cfg
        };
        assert!(cfg3.effective_url().is_none());
    }

    #[test]
    fn test_proxy_config_default_includes_alerts() {
        let config = ProxyConfig::default();
        assert!(!config.alerts.enabled);
        assert!(config.alerts.webhook_url.is_empty());
        assert_eq!(config.alerts.min_severity, "High");
        assert!(config.alerts.channels.is_empty());
    }

    #[test]
    fn test_security_severity_display() {
        assert_eq!(SecuritySeverity::Info.to_string(), "Info");
        assert_eq!(SecuritySeverity::Low.to_string(), "Low");
        assert_eq!(SecuritySeverity::Medium.to_string(), "Medium");
        assert_eq!(SecuritySeverity::High.to_string(), "High");
        assert_eq!(SecuritySeverity::Critical.to_string(), "Critical");
    }

    #[test]
    fn test_security_severity_from_str() {
        assert_eq!(
            "Info".parse::<SecuritySeverity>().unwrap(),
            SecuritySeverity::Info
        );
        assert_eq!(
            "low".parse::<SecuritySeverity>().unwrap(),
            SecuritySeverity::Low
        );
        assert_eq!(
            "MEDIUM".parse::<SecuritySeverity>().unwrap(),
            SecuritySeverity::Medium
        );
        assert_eq!(
            "High".parse::<SecuritySeverity>().unwrap(),
            SecuritySeverity::High
        );
        assert_eq!(
            "critical".parse::<SecuritySeverity>().unwrap(),
            SecuritySeverity::Critical
        );
        assert!("unknown".parse::<SecuritySeverity>().is_err());
    }

    // -- Cost cap types ---------------------------------------------------

    #[test]
    fn test_budget_window_duration_secs() {
        assert_eq!(BudgetWindow::Hourly.duration_secs(), 3_600);
        assert_eq!(BudgetWindow::Daily.duration_secs(), 86_400);
        assert_eq!(BudgetWindow::Weekly.duration_secs(), 604_800);
        assert_eq!(BudgetWindow::Monthly.duration_secs(), 2_592_000);
    }

    #[test]
    fn test_budget_window_cache_ttl_exceeds_window() {
        for window in [
            BudgetWindow::Hourly,
            BudgetWindow::Daily,
            BudgetWindow::Weekly,
            BudgetWindow::Monthly,
        ] {
            assert!(window.cache_ttl().as_secs() > window.duration_secs());
        }
    }

    #[test]
    fn test_budget_window_display() {
        assert_eq!(BudgetWindow::Hourly.to_string(), "hourly");
        assert_eq!(BudgetWindow::Daily.to_string(), "daily");
        assert_eq!(BudgetWindow::Weekly.to_string(), "weekly");
        assert_eq!(BudgetWindow::Monthly.to_string(), "monthly");
    }

    #[test]
    fn test_budget_window_serialization() {
        let window = BudgetWindow::Daily;
        let json = serde_json::to_string(&window).unwrap();
        assert_eq!(json, r#""daily""#);
        let deser: BudgetWindow = serde_json::from_str(&json).unwrap();
        assert_eq!(deser, window);
    }

    #[test]
    fn test_budget_cap_serialization() {
        let cap = BudgetCap {
            window: BudgetWindow::Hourly,
            hard_limit_usd: 10.0,
            soft_limit_usd: Some(8.0),
        };
        let json = serde_json::to_string(&cap).unwrap();
        let deser: BudgetCap = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.window, BudgetWindow::Hourly);
        assert!((deser.hard_limit_usd - 10.0).abs() < f64::EPSILON);
        assert!((deser.soft_limit_usd.unwrap() - 8.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_budget_cap_no_soft_limit() {
        let json = r#"{"window":"monthly","hard_limit_usd":100.0}"#;
        let cap: BudgetCap = serde_json::from_str(json).unwrap();
        assert_eq!(cap.window, BudgetWindow::Monthly);
        assert!(cap.soft_limit_usd.is_none());
    }

    #[test]
    fn test_token_cap_serialization() {
        let cap = TokenCap {
            max_prompt_tokens: Some(4096),
            max_completion_tokens: Some(2048),
            max_total_tokens: None,
        };
        let json = serde_json::to_string(&cap).unwrap();
        let deser: TokenCap = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.max_prompt_tokens, Some(4096));
        assert_eq!(deser.max_completion_tokens, Some(2048));
        assert!(deser.max_total_tokens.is_none());
    }

    #[test]
    fn test_agent_cost_cap_serialization() {
        let agent_cap = AgentCostCap {
            agent_id: "agent-007".to_string(),
            budget_caps: vec![BudgetCap {
                window: BudgetWindow::Daily,
                hard_limit_usd: 50.0,
                soft_limit_usd: Some(40.0),
            }],
            token_cap: Some(TokenCap {
                max_prompt_tokens: Some(8192),
                max_completion_tokens: None,
                max_total_tokens: Some(16384),
            }),
        };
        let json = serde_json::to_string(&agent_cap).unwrap();
        let deser: AgentCostCap = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.agent_id, "agent-007");
        assert_eq!(deser.budget_caps.len(), 1);
        assert!(deser.token_cap.is_some());
    }

    #[test]
    fn test_cost_cap_config_default() {
        let config = CostCapConfig::default();
        assert!(!config.enabled);
        assert!(config.default_budget_caps.is_empty());
        assert!(config.default_token_cap.is_none());
        assert!(config.agents.is_empty());
    }

    #[test]
    fn test_cost_cap_config_serialization() {
        let config = CostCapConfig {
            enabled: true,
            default_budget_caps: vec![BudgetCap {
                window: BudgetWindow::Daily,
                hard_limit_usd: 100.0,
                soft_limit_usd: Some(80.0),
            }],
            default_token_cap: Some(TokenCap {
                max_prompt_tokens: Some(4096),
                max_completion_tokens: Some(4096),
                max_total_tokens: None,
            }),
            agents: vec![AgentCostCap {
                agent_id: "heavy-agent".to_string(),
                budget_caps: vec![BudgetCap {
                    window: BudgetWindow::Daily,
                    hard_limit_usd: 200.0,
                    soft_limit_usd: None,
                }],
                token_cap: None,
            }],
        };
        let json = serde_json::to_string(&config).unwrap();
        let deser: CostCapConfig = serde_json::from_str(&json).unwrap();
        assert!(deser.enabled);
        assert_eq!(deser.default_budget_caps.len(), 1);
        assert!(deser.default_token_cap.is_some());
        assert_eq!(deser.agents.len(), 1);
        assert_eq!(deser.agents[0].agent_id, "heavy-agent");
    }

    #[test]
    fn test_proxy_config_default_includes_cost_caps() {
        let config = ProxyConfig::default();
        assert!(!config.cost_caps.enabled);
        assert!(config.cost_caps.default_budget_caps.is_empty());
    }

    #[test]
    fn test_proxy_config_default_includes_security_analysis() {
        let config = ProxyConfig::default();
        assert!(config.security_analysis.ml_enabled);
        assert_eq!(
            config.security_analysis.ml_model,
            "protectai/deberta-v3-base-prompt-injection-v2"
        );
        assert!((config.security_analysis.ml_threshold - 0.8).abs() < f64::EPSILON);
        assert_eq!(
            config.security_analysis.ml_cache_dir,
            "~/.cache/llmtrace/models"
        );
        assert!(config.security_analysis.ml_preload);
        assert_eq!(config.security_analysis.ml_download_timeout_seconds, 300);
        assert!(!config.security_analysis.ner_enabled);
        assert_eq!(config.security_analysis.ner_model, "dslim/bert-base-NER");
        assert!(!config.security_analysis.fusion_enabled);
        assert!(config.security_analysis.fusion_model_path.is_none());
        assert!(config.security_analysis.jailbreak_enabled);
        assert!((config.security_analysis.jailbreak_threshold - 0.7).abs() < f32::EPSILON);
    }

    #[test]
    fn test_security_analysis_config_default() {
        let config = SecurityAnalysisConfig::default();
        assert!(config.ml_enabled);
        assert_eq!(
            config.ml_model,
            "protectai/deberta-v3-base-prompt-injection-v2"
        );
        assert!((config.ml_threshold - 0.8).abs() < f64::EPSILON);
        assert_eq!(config.ml_cache_dir, "~/.cache/llmtrace/models");
        assert!(config.ml_preload);
        assert_eq!(config.ml_download_timeout_seconds, 300);
        assert!(!config.ner_enabled);
        assert_eq!(config.ner_model, "dslim/bert-base-NER");
        assert!(!config.fusion_enabled);
        assert!(config.fusion_model_path.is_none());
        assert!(config.jailbreak_enabled);
        assert!((config.jailbreak_threshold - 0.7).abs() < f32::EPSILON);
    }

    #[test]
    fn test_security_analysis_config_serialization() {
        let config = SecurityAnalysisConfig {
            ml_enabled: true,
            ml_model: "custom/model".to_string(),
            ml_threshold: 0.9,
            ml_cache_dir: "/tmp/models".to_string(),
            ml_preload: false,
            ml_download_timeout_seconds: 600,
            ner_enabled: true,
            ner_model: "dslim/bert-base-NER".to_string(),
            fusion_enabled: false,
            fusion_model_path: None,
            jailbreak_enabled: true,
            jailbreak_threshold: 0.7,
            injecguard_enabled: false,
            injecguard_model: default_injecguard_model(),
            injecguard_threshold: default_injecguard_threshold(),
            piguard_enabled: false,
            piguard_model: default_piguard_model(),
            piguard_threshold: default_piguard_threshold(),
            operating_point: OperatingPoint::default(),
            over_defence: false,
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: SecurityAnalysisConfig = serde_json::from_str(&json).unwrap();
        assert!(deserialized.ml_enabled);
        assert_eq!(deserialized.ml_model, "custom/model");
        assert!((deserialized.ml_threshold - 0.9).abs() < f64::EPSILON);
        assert_eq!(deserialized.ml_cache_dir, "/tmp/models");
        assert!(!deserialized.ml_preload);
        assert_eq!(deserialized.ml_download_timeout_seconds, 600);
        assert!(deserialized.ner_enabled);
        assert_eq!(deserialized.ner_model, "dslim/bert-base-NER");
    }

    // ---------------------------------------------------------------
    // Agent action types
    // ---------------------------------------------------------------

    #[test]
    fn test_agent_action_type_display() {
        assert_eq!(AgentActionType::ToolCall.to_string(), "tool_call");
        assert_eq!(
            AgentActionType::SkillInvocation.to_string(),
            "skill_invocation"
        );
        assert_eq!(
            AgentActionType::CommandExecution.to_string(),
            "command_execution"
        );
        assert_eq!(AgentActionType::WebAccess.to_string(), "web_access");
        assert_eq!(AgentActionType::FileAccess.to_string(), "file_access");
    }

    #[test]
    fn test_agent_action_type_serialization() {
        let types = vec![
            AgentActionType::ToolCall,
            AgentActionType::SkillInvocation,
            AgentActionType::CommandExecution,
            AgentActionType::WebAccess,
            AgentActionType::FileAccess,
        ];
        for action_type in types {
            let json = serde_json::to_string(&action_type).unwrap();
            let deser: AgentActionType = serde_json::from_str(&json).unwrap();
            assert_eq!(action_type, deser);
        }
    }

    #[test]
    fn test_agent_action_creation() {
        let action = AgentAction::new(AgentActionType::ToolCall, "get_weather".to_string());
        assert_eq!(action.action_type, AgentActionType::ToolCall);
        assert_eq!(action.name, "get_weather");
        assert!(action.success);
        assert!(action.arguments.is_none());
        assert!(action.result.is_none());
    }

    #[test]
    fn test_agent_action_builder() {
        let action = AgentAction::new(AgentActionType::CommandExecution, "ls -la".to_string())
            .with_arguments("-la /tmp".to_string())
            .with_result("file1\nfile2".to_string())
            .with_duration_ms(150)
            .with_exit_code(0)
            .with_metadata("cwd".to_string(), "/home".to_string());

        assert_eq!(action.action_type, AgentActionType::CommandExecution);
        assert_eq!(action.arguments, Some("-la /tmp".to_string()));
        assert_eq!(action.result, Some("file1\nfile2".to_string()));
        assert_eq!(action.duration_ms, Some(150));
        assert_eq!(action.exit_code, Some(0));
        assert!(action.success);
        assert_eq!(action.metadata.get("cwd"), Some(&"/home".to_string()));
    }

    #[test]
    fn test_agent_action_web_access() {
        let action = AgentAction::new(
            AgentActionType::WebAccess,
            "https://api.example.com".to_string(),
        )
        .with_http("GET".to_string(), 200)
        .with_duration_ms(500);

        assert_eq!(action.http_method, Some("GET".to_string()));
        assert_eq!(action.http_status, Some(200));
    }

    #[test]
    fn test_agent_action_file_access() {
        let action = AgentAction::new(AgentActionType::FileAccess, "/etc/passwd".to_string())
            .with_file_operation("read".to_string());

        assert_eq!(action.file_operation, Some("read".to_string()));
    }

    #[test]
    fn test_agent_action_failure() {
        let action = AgentAction::new(AgentActionType::CommandExecution, "rm -rf /".to_string())
            .with_failure()
            .with_exit_code(1);

        assert!(!action.success);
        assert_eq!(action.exit_code, Some(1));
    }

    #[test]
    fn test_agent_action_result_truncation() {
        let long_result = "x".repeat(AGENT_ACTION_RESULT_MAX_BYTES + 100);
        let action = AgentAction::new(AgentActionType::ToolCall, "big_output".to_string())
            .with_result(long_result);

        assert_eq!(
            action.result.as_ref().unwrap().len(),
            AGENT_ACTION_RESULT_MAX_BYTES
        );
    }

    #[test]
    fn test_agent_action_serialization() {
        let action = AgentAction::new(AgentActionType::ToolCall, "get_weather".to_string())
            .with_arguments(r#"{"location": "London"}"#.to_string())
            .with_result(r#"{"temp": 15}"#.to_string())
            .with_duration_ms(200);

        let json = serde_json::to_string(&action).unwrap();
        let deser: AgentAction = serde_json::from_str(&json).unwrap();

        assert_eq!(deser.action_type, AgentActionType::ToolCall);
        assert_eq!(deser.name, "get_weather");
        assert_eq!(deser.arguments, action.arguments);
        assert_eq!(deser.result, action.result);
        assert_eq!(deser.duration_ms, Some(200));
        assert!(deser.success);
    }

    #[test]
    fn test_trace_span_agent_actions() {
        let mut span = TraceSpan::new(
            Uuid::new_v4(),
            TenantId::new(),
            "chat_completion".to_string(),
            LLMProvider::OpenAI,
            "gpt-4".to_string(),
            "test".to_string(),
        );

        assert!(span.agent_actions.is_empty());
        assert!(!span.has_tool_calls());
        assert!(!span.has_web_access());
        assert!(!span.has_commands());

        span.add_agent_action(AgentAction::new(
            AgentActionType::ToolCall,
            "search".to_string(),
        ));
        span.add_agent_action(AgentAction::new(
            AgentActionType::WebAccess,
            "https://example.com".to_string(),
        ));
        span.add_agent_action(AgentAction::new(
            AgentActionType::CommandExecution,
            "ls".to_string(),
        ));
        span.add_agent_action(AgentAction::new(
            AgentActionType::FileAccess,
            "/tmp/file.txt".to_string(),
        ));

        assert_eq!(span.agent_actions.len(), 4);
        assert!(span.has_tool_calls());
        assert!(span.has_web_access());
        assert!(span.has_commands());
        assert_eq!(span.tool_calls().len(), 1);
        assert_eq!(span.web_accesses().len(), 1);
        assert_eq!(span.commands().len(), 1);
    }

    #[test]
    fn test_trace_span_with_agent_actions_serialization() {
        let mut span = TraceSpan::new(
            Uuid::new_v4(),
            TenantId::new(),
            "chat_completion".to_string(),
            LLMProvider::OpenAI,
            "gpt-4".to_string(),
            "test prompt".to_string(),
        );
        span.add_agent_action(
            AgentAction::new(AgentActionType::ToolCall, "calculate".to_string())
                .with_arguments(r#"{"expr": "2+2"}"#.to_string())
                .with_result("4".to_string()),
        );

        let json = serde_json::to_string(&span).unwrap();
        let deser: TraceSpan = serde_json::from_str(&json).unwrap();

        assert_eq!(deser.agent_actions.len(), 1);
        assert_eq!(deser.agent_actions[0].name, "calculate");
        assert_eq!(
            deser.agent_actions[0].action_type,
            AgentActionType::ToolCall
        );
    }

    #[test]
    fn test_trace_span_deserialize_without_agent_actions() {
        // Ensure backward compatibility: old spans without agent_actions field deserialize OK
        let json = r#"{
            "trace_id": "00000000-0000-0000-0000-000000000001",
            "span_id": "00000000-0000-0000-0000-000000000002",
            "parent_span_id": null,
            "tenant_id": "00000000-0000-0000-0000-000000000003",
            "operation_name": "test",
            "start_time": "2024-01-01T00:00:00Z",
            "end_time": null,
            "provider": "OpenAI",
            "model_name": "gpt-4",
            "prompt": "hello",
            "response": null,
            "prompt_tokens": null,
            "completion_tokens": null,
            "total_tokens": null,
            "time_to_first_token_ms": null,
            "duration_ms": null,
            "status_code": null,
            "error_message": null,
            "estimated_cost_usd": null,
            "security_score": null,
            "security_findings": [],
            "tags": {},
            "events": []
        }"#;
        let span: TraceSpan = serde_json::from_str(json).unwrap();
        assert!(span.agent_actions.is_empty());
    }

    // -----------------------------------------------------------------------
    // Auth & RBAC types
    // -----------------------------------------------------------------------

    #[test]
    fn test_api_key_role_has_permission() {
        // Admin can do everything
        assert!(ApiKeyRole::Admin.has_permission(ApiKeyRole::Admin));
        assert!(ApiKeyRole::Admin.has_permission(ApiKeyRole::Operator));
        assert!(ApiKeyRole::Admin.has_permission(ApiKeyRole::Viewer));

        // Operator can do operator + viewer things
        assert!(!ApiKeyRole::Operator.has_permission(ApiKeyRole::Admin));
        assert!(ApiKeyRole::Operator.has_permission(ApiKeyRole::Operator));
        assert!(ApiKeyRole::Operator.has_permission(ApiKeyRole::Viewer));

        // Viewer can only view
        assert!(!ApiKeyRole::Viewer.has_permission(ApiKeyRole::Admin));
        assert!(!ApiKeyRole::Viewer.has_permission(ApiKeyRole::Operator));
        assert!(ApiKeyRole::Viewer.has_permission(ApiKeyRole::Viewer));
    }

    #[test]
    fn test_api_key_role_roundtrip() {
        for role in &[ApiKeyRole::Admin, ApiKeyRole::Operator, ApiKeyRole::Viewer] {
            let s = role.to_string();
            let parsed: ApiKeyRole = s.parse().unwrap();
            assert_eq!(*role, parsed);
        }
    }

    #[test]
    fn test_api_key_role_serialization() {
        let role = ApiKeyRole::Operator;
        let json = serde_json::to_string(&role).unwrap();
        assert_eq!(json, r#""operator""#);
        let deserialized: ApiKeyRole = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, ApiKeyRole::Operator);
    }

    #[test]
    fn test_api_key_record_serialization_skips_hash() {
        let record = ApiKeyRecord {
            id: Uuid::new_v4(),
            tenant_id: TenantId::new(),
            name: "test-key".to_string(),
            key_hash: "abc123".to_string(),
            key_prefix: "llmt_ab…".to_string(),
            role: ApiKeyRole::Viewer,
            created_at: Utc::now(),
            revoked_at: None,
        };
        let json = serde_json::to_string(&record).unwrap();
        // key_hash is skip_serializing — should not appear in JSON output
        assert!(!json.contains("abc123"));
        assert!(json.contains("llmt_ab"));
    }

    #[test]
    fn test_auth_config_default() {
        let cfg = AuthConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.admin_key.is_none());
    }

    #[test]
    fn test_auth_config_serialization() {
        let cfg = AuthConfig {
            enabled: true,
            admin_key: Some("my-secret".to_string()),
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let deser: AuthConfig = serde_json::from_str(&json).unwrap();
        assert!(deser.enabled);
        assert_eq!(deser.admin_key.as_deref(), Some("my-secret"));
    }

    #[test]
    fn test_proxy_config_includes_auth() {
        let config = ProxyConfig::default();
        assert!(!config.auth.enabled);
        assert!(config.auth.admin_key.is_none());
    }

    // -----------------------------------------------------------------------
    // PII types
    // -----------------------------------------------------------------------

    #[test]
    fn test_pii_action_default() {
        assert_eq!(PiiAction::default(), PiiAction::AlertOnly);
    }

    #[test]
    fn test_pii_action_display() {
        assert_eq!(PiiAction::AlertOnly.to_string(), "alert_only");
        assert_eq!(PiiAction::AlertAndRedact.to_string(), "alert_and_redact");
        assert_eq!(PiiAction::RedactSilent.to_string(), "redact_silent");
    }

    #[test]
    fn test_pii_action_serialization() {
        let action = PiiAction::AlertAndRedact;
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(json, r#""alert_and_redact""#);
        let deser: PiiAction = serde_json::from_str(&json).unwrap();
        assert_eq!(deser, PiiAction::AlertAndRedact);
    }

    #[test]
    fn test_pii_config_default() {
        let config = PiiConfig::default();
        assert_eq!(config.action, PiiAction::AlertOnly);
    }

    #[test]
    fn test_pii_config_serialization() {
        let config = PiiConfig {
            action: PiiAction::RedactSilent,
        };
        let json = serde_json::to_string(&config).unwrap();
        let deser: PiiConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.action, PiiAction::RedactSilent);
    }

    #[test]
    fn test_pii_config_deserializes_with_defaults() {
        let json = r#"{}"#;
        let config: PiiConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.action, PiiAction::AlertOnly);
    }

    #[test]
    fn test_proxy_config_default_includes_pii() {
        let config = ProxyConfig::default();
        assert_eq!(config.pii.action, PiiAction::AlertOnly);
    }
}
