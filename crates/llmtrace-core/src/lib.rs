//! Core types, traits, and errors for LLMTrace
//!
//! This crate contains foundational types and traits shared across all LLMTrace components.
//! It provides the core data structures for representing traces, security findings, and
//! storage/analysis interfaces.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use uuid::Uuid;

/// Unique identifier for a tenant
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantId(pub Uuid);

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TenantId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for TenantId {
    fn default() -> Self {
        Self::new()
    }
}

/// Severity level for security findings
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SecuritySeverity {
    /// Informational - no immediate action needed
    Info,
    /// Low severity - minor issue
    Low,
    /// Medium severity - should be addressed
    Medium,
    /// High severity - prompt attention needed
    High,
    /// Most severe - immediate attention required
    Critical,
}

/// A security finding detected during analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    /// Unique identifier for this finding
    pub id: Uuid,
    /// Severity level of the finding
    pub severity: SecuritySeverity,
    /// Type of security issue (e.g., "prompt_injection", "pii_leak", "cost_anomaly")
    pub finding_type: String,
    /// Human-readable description of the finding
    pub description: String,
    /// When the finding was detected
    pub detected_at: DateTime<Utc>,
    /// Confidence score (0.0 to 1.0)
    pub confidence_score: f64,
    /// Location where the issue was found (e.g., "request.messages[0]", "response.content")
    pub location: Option<String>,
    /// Additional metadata about the finding
    pub metadata: HashMap<String, String>,
    /// Whether this finding requires immediate alerting
    pub requires_alert: bool,
}

impl SecurityFinding {
    /// Create a new security finding
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

    /// Set the location where this finding was detected
    pub fn with_location(mut self, location: String) -> Self {
        self.location = Some(location);
        self
    }

    /// Add metadata to the finding
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Set whether this finding requires immediate alerting
    pub fn with_alert_required(mut self, requires_alert: bool) -> Self {
        self.requires_alert = requires_alert;
        self
    }
}

/// Supported LLM providers
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// A single span within a trace representing a portion of an LLM interaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSpan {
    /// Unique identifier for the trace this span belongs to
    pub trace_id: Uuid,
    /// Unique identifier for this span
    pub span_id: Uuid,
    /// Parent span ID if this is a child span
    pub parent_span_id: Option<Uuid>,
    /// Tenant this span belongs to
    pub tenant_id: TenantId,
    /// Name of the operation (e.g., "chat_completion", "embedding", "prompt_analysis")
    pub operation_name: String,
    /// When the span started
    pub start_time: DateTime<Utc>,
    /// When the span ended (None if still in progress)
    pub end_time: Option<DateTime<Utc>>,
    /// LLM provider used for this span
    pub provider: LLMProvider,
    /// Model name/identifier
    pub model_name: String,
    /// The input prompt or messages
    pub prompt: String,
    /// The response from the LLM (None if not yet completed)
    pub response: Option<String>,
    /// Number of tokens in the prompt
    pub prompt_tokens: Option<u32>,
    /// Number of tokens in the completion/response
    pub completion_tokens: Option<u32>,
    /// Total token count (prompt + completion)
    pub total_tokens: Option<u32>,
    /// Time to first token (TTFT) in milliseconds
    pub time_to_first_token_ms: Option<u64>,
    /// Processing duration in milliseconds
    pub duration_ms: Option<u64>,
    /// HTTP status code of the response
    pub status_code: Option<u16>,
    /// Error message if the request failed
    pub error_message: Option<String>,
    /// Estimated cost of this request in USD
    pub estimated_cost_usd: Option<f64>,
    /// Overall security score (0-100, higher = more suspicious)
    pub security_score: Option<u8>,
    /// Security findings detected for this span
    pub security_findings: Vec<SecurityFinding>,
    /// Custom tags and metadata
    pub tags: HashMap<String, String>,
    /// Events that occurred during this span (e.g., streaming chunks, analysis results)
    pub events: Vec<SpanEvent>,
}

impl TraceSpan {
    /// Create a new trace span
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
        }
    }

    /// Finish the span with a response
    pub fn finish_with_response(mut self, response: String) -> Self {
        self.response = Some(response);
        let end_time = Utc::now();
        self.end_time = Some(end_time);
        self.duration_ms =
            Some((end_time.signed_duration_since(self.start_time)).num_milliseconds() as u64);
        self
    }

    /// Mark the span as failed with an error
    pub fn finish_with_error(mut self, error: String, status_code: Option<u16>) -> Self {
        self.error_message = Some(error);
        self.status_code = status_code;
        let end_time = Utc::now();
        self.end_time = Some(end_time);
        self.duration_ms =
            Some((end_time.signed_duration_since(self.start_time)).num_milliseconds() as u64);
        self
    }

    /// Add a security finding to this span
    pub fn add_security_finding(&mut self, finding: SecurityFinding) {
        self.security_findings.push(finding);
        // Update overall security score based on highest severity finding
        let max_score = self
            .security_findings
            .iter()
            .map(|f| match f.severity {
                SecuritySeverity::Critical => 95,
                SecuritySeverity::High => 80,
                SecuritySeverity::Medium => 60,
                SecuritySeverity::Low => 30,
                SecuritySeverity::Info => 10,
            })
            .max()
            .unwrap_or(0);
        self.security_score = Some(max_score as u8);
    }

    /// Add an event to this span
    pub fn add_event(&mut self, event: SpanEvent) {
        self.events.push(event);
    }

    /// Get the duration of this span
    pub fn duration(&self) -> Option<Duration> {
        self.end_time.map(|end_time| {
            Duration::from_millis(
                end_time
                    .signed_duration_since(self.start_time)
                    .num_milliseconds() as u64,
            )
        })
    }

    /// Check if the span is complete
    pub fn is_complete(&self) -> bool {
        self.end_time.is_some()
    }

    /// Check if the span failed
    pub fn is_failed(&self) -> bool {
        self.error_message.is_some()
    }
}

/// An event that occurred during a span
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanEvent {
    /// Unique identifier for the event
    pub id: Uuid,
    /// When the event occurred
    pub timestamp: DateTime<Utc>,
    /// Type of event (e.g., "token_received", "security_scan_completed", "error_occurred")
    pub event_type: String,
    /// Human-readable description
    pub description: String,
    /// Event-specific data
    pub data: HashMap<String, String>,
}

impl SpanEvent {
    /// Create a new span event
    pub fn new(event_type: String, description: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type,
            description,
            data: HashMap::new(),
        }
    }

    /// Add data to the event
    pub fn with_data(mut self, key: String, value: String) -> Self {
        self.data.insert(key, value);
        self
    }
}

/// A complete trace event representing an LLM interaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEvent {
    pub trace_id: Uuid,
    pub tenant_id: TenantId,
    pub spans: Vec<TraceSpan>,
    pub created_at: DateTime<Utc>,
}

/// Configuration for the transparent proxy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Address and port to bind the proxy server to
    pub listen_addr: String,
    /// Upstream URL for the LLM provider
    pub upstream_url: String,
    /// SQLite database URL for trace storage (e.g. "sqlite:///tmp/llmtrace.db" or "sqlite::memory:")
    #[serde(default = "default_database_url")]
    pub database_url: String,
    /// Request timeout in milliseconds
    pub timeout_ms: u64,
    /// Connection timeout in milliseconds
    pub connection_timeout_ms: u64,
    /// Maximum number of concurrent connections
    pub max_connections: u32,
    /// Enable TLS for the proxy server
    pub enable_tls: bool,
    /// TLS certificate file path
    pub tls_cert_file: Option<String>,
    /// TLS private key file path
    pub tls_key_file: Option<String>,
    /// Enable security analysis of requests/responses
    pub enable_security_analysis: bool,
    /// Enable trace storage
    pub enable_trace_storage: bool,
    /// Enable streaming support
    pub enable_streaming: bool,
    /// Maximum request body size in bytes
    pub max_request_size_bytes: u64,
    /// Security analysis timeout in milliseconds
    pub security_analysis_timeout_ms: u64,
    /// Trace storage timeout in milliseconds
    pub trace_storage_timeout_ms: u64,
    /// Rate limiting configuration
    pub rate_limiting: RateLimitConfig,
    /// Circuit breaker configuration
    pub circuit_breaker: CircuitBreakerConfig,
    /// Health check configuration
    pub health_check: HealthCheckConfig,
}

/// Default database URL used when none is specified in config.
fn default_database_url() -> String {
    "sqlite:llmtrace.db".to_string()
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8080".to_string(),
            upstream_url: "https://api.openai.com".to_string(),
            database_url: default_database_url(),
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
        }
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Enable rate limiting
    pub enabled: bool,
    /// Requests per second limit
    pub requests_per_second: u32,
    /// Burst size
    pub burst_size: u32,
    /// Rate limiting window in seconds
    pub window_seconds: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_second: 100,
            burst_size: 200,
            window_seconds: 60,
        }
    }
}

/// Circuit breaker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Enable circuit breaker
    pub enabled: bool,
    /// Failure threshold before opening circuit
    pub failure_threshold: u32,
    /// Recovery timeout in milliseconds
    pub recovery_timeout_ms: u64,
    /// Half-open state max calls
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

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// Enable health checks
    pub enabled: bool,
    /// Health check endpoint path
    pub path: String,
    /// Health check interval in seconds
    pub interval_seconds: u32,
    /// Health check timeout in milliseconds
    pub timeout_ms: u64,
    /// Number of retries before marking unhealthy
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

/// Core error types
#[derive(thiserror::Error, Debug)]
pub enum LLMTraceError {
    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Security analysis error: {0}")]
    Security(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Invalid tenant: {tenant_id}")]
    InvalidTenant { tenant_id: TenantId },

    #[error("Configuration error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, LLMTraceError>;

/// Query parameters for filtering traces
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceQuery {
    /// Tenant to query traces for
    pub tenant_id: TenantId,
    /// Start time for the query range
    pub start_time: Option<DateTime<Utc>>,
    /// End time for the query range
    pub end_time: Option<DateTime<Utc>>,
    /// Filter by provider
    pub provider: Option<LLMProvider>,
    /// Filter by model name
    pub model_name: Option<String>,
    /// Filter by operation name
    pub operation_name: Option<String>,
    /// Minimum security score to include
    pub min_security_score: Option<u8>,
    /// Maximum security score to include
    pub max_security_score: Option<u8>,
    /// Filter by trace ID
    pub trace_id: Option<Uuid>,
    /// Filter by tags
    pub tags: HashMap<String, String>,
    /// Maximum number of results to return
    pub limit: Option<u32>,
    /// Number of results to skip (for pagination)
    pub offset: Option<u32>,
}

impl TraceQuery {
    /// Create a new trace query for a tenant
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

    /// Add a time range filter
    pub fn with_time_range(mut self, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        self.start_time = Some(start);
        self.end_time = Some(end);
        self
    }

    /// Add a provider filter
    pub fn with_provider(mut self, provider: LLMProvider) -> Self {
        self.provider = Some(provider);
        self
    }

    /// Add a security score range filter
    pub fn with_security_score_range(mut self, min: u8, max: u8) -> Self {
        self.min_security_score = Some(min);
        self.max_security_score = Some(max);
        self
    }

    /// Set the limit
    pub fn with_limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }
}

/// Trait for storage backends
#[async_trait::async_trait]
pub trait StorageBackend: Send + Sync {
    /// Store a trace event
    async fn store_trace(&self, trace: &TraceEvent) -> Result<()>;

    /// Store a single trace span
    async fn store_span(&self, span: &TraceSpan) -> Result<()>;

    /// Query traces with filters
    async fn query_traces(&self, query: &TraceQuery) -> Result<Vec<TraceEvent>>;

    /// Query spans with filters
    async fn query_spans(&self, query: &TraceQuery) -> Result<Vec<TraceSpan>>;

    /// Get a specific trace by ID
    async fn get_trace(&self, tenant_id: TenantId, trace_id: Uuid) -> Result<Option<TraceEvent>>;

    /// Get a specific span by ID
    async fn get_span(&self, tenant_id: TenantId, span_id: Uuid) -> Result<Option<TraceSpan>>;

    /// Delete traces older than the specified time
    async fn delete_traces_before(&self, tenant_id: TenantId, before: DateTime<Utc>)
        -> Result<u64>;

    /// Get storage statistics
    async fn get_stats(&self, tenant_id: TenantId) -> Result<StorageStats>;

    /// Health check for the storage backend
    async fn health_check(&self) -> Result<()>;
}

/// Storage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    /// Total number of traces stored
    pub total_traces: u64,
    /// Total number of spans stored
    pub total_spans: u64,
    /// Storage size in bytes
    pub storage_size_bytes: u64,
    /// Oldest trace timestamp
    pub oldest_trace: Option<DateTime<Utc>>,
    /// Newest trace timestamp
    pub newest_trace: Option<DateTime<Utc>>,
}

/// Analysis context for security analyzers
#[derive(Debug, Clone)]
pub struct AnalysisContext {
    /// Tenant ID for context
    pub tenant_id: TenantId,
    /// Trace ID for context
    pub trace_id: Uuid,
    /// Span ID for context
    pub span_id: Uuid,
    /// LLM provider being used
    pub provider: LLMProvider,
    /// Model name
    pub model_name: String,
    /// Custom analysis parameters
    pub parameters: HashMap<String, String>,
}

/// Trait for security analyzers
#[async_trait::async_trait]
pub trait SecurityAnalyzer: Send + Sync {
    /// Analyze a request for security issues
    async fn analyze_request(
        &self,
        prompt: &str,
        context: &AnalysisContext,
    ) -> Result<Vec<SecurityFinding>>;

    /// Analyze a response for security issues
    async fn analyze_response(
        &self,
        response: &str,
        context: &AnalysisContext,
    ) -> Result<Vec<SecurityFinding>>;

    /// Analyze a complete request/response pair
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

    /// Get the analyzer name
    fn name(&self) -> &'static str;

    /// Get the analyzer version
    fn version(&self) -> &'static str;

    /// Get supported security finding types
    fn supported_finding_types(&self) -> Vec<String>;

    /// Check if the analyzer is healthy
    async fn health_check(&self) -> Result<()>;
}

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
        let config = ProxyConfig {
            listen_addr: "127.0.0.1:9090".to_string(),
            upstream_url: "https://api.anthropic.com".to_string(),
            database_url: "sqlite:test.db".to_string(),
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
        };

        let serialized = serde_json::to_string(&config).unwrap();
        let deserialized: ProxyConfig = serde_json::from_str(&serialized).unwrap();

        assert_eq!(config.listen_addr, deserialized.listen_addr);
        assert_eq!(config.upstream_url, deserialized.upstream_url);
        assert_eq!(config.enable_tls, deserialized.enable_tls);
        assert_eq!(config.tls_cert_file, deserialized.tls_cert_file);
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
}
