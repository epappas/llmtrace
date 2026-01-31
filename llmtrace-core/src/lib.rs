//! Core types, traits, and errors for LLMTrace
//!
//! This crate contains foundational types and traits shared across all LLMTrace components.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecuritySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// A security finding detected during analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub severity: SecuritySeverity,
    pub finding_type: String,
    pub description: String,
    pub detected_at: DateTime<Utc>,
    pub confidence_score: f64,
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

/// A single span within a trace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSpan {
    pub trace_id: Uuid,
    pub span_id: Uuid,
    pub parent_span_id: Option<Uuid>,
    pub tenant_id: TenantId,
    pub operation_name: String,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub provider: LLMProvider,
    pub model_name: String,
    pub prompt: String,
    pub response: Option<String>,
    pub prompt_tokens: Option<u32>,
    pub completion_tokens: Option<u32>,
    pub total_tokens: Option<u32>,
    pub security_score: Option<u8>,
    pub security_findings: Vec<SecurityFinding>,
    pub tags: HashMap<String, String>,
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
    pub listen_addr: String,
    pub upstream_url: String,
    pub timeout_ms: u64,
    pub enable_security_analysis: bool,
    pub enable_trace_storage: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8080".to_string(),
            upstream_url: "https://api.openai.com".to_string(),
            timeout_ms: 30000,
            enable_security_analysis: true,
            enable_trace_storage: true,
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

/// Trait for storage backends
#[async_trait::async_trait]
pub trait StorageBackend: Send + Sync {
    /// Store a trace event
    async fn store_trace(&self, trace: &TraceEvent) -> Result<()>;

    /// Query traces with filters
    async fn query_traces(
        &self,
        tenant_id: TenantId,
        limit: Option<u32>,
    ) -> Result<Vec<TraceEvent>>;

    /// Health check for the storage backend
    async fn health_check(&self) -> Result<()>;
}

/// Trait for security analyzers
#[async_trait::async_trait]
pub trait SecurityAnalyzer: Send + Sync {
    /// Analyze a request for security issues
    async fn analyze_request(&self, prompt: &str) -> Result<Vec<SecurityFinding>>;

    /// Analyze a response for security issues
    async fn analyze_response(&self, response: &str) -> Result<Vec<SecurityFinding>>;

    /// Get the analyzer name
    fn name(&self) -> &'static str;
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
    fn test_trace_serialization() {
        let trace = TraceEvent {
            trace_id: Uuid::new_v4(),
            tenant_id: TenantId::new(),
            spans: vec![],
            created_at: Utc::now(),
        };

        let serialized = serde_json::to_string(&trace).unwrap();
        let deserialized: TraceEvent = serde_json::from_str(&serialized).unwrap();

        assert_eq!(trace.trace_id, deserialized.trace_id);
        assert_eq!(trace.tenant_id, deserialized.tenant_id);
    }

    #[test]
    fn test_security_finding_serialization() {
        let finding = SecurityFinding {
            severity: SecuritySeverity::High,
            finding_type: "prompt_injection".to_string(),
            description: "Detected system prompt override attempt".to_string(),
            detected_at: Utc::now(),
            confidence_score: 0.95,
        };

        let serialized = serde_json::to_string(&finding).unwrap();
        let deserialized: SecurityFinding = serde_json::from_str(&serialized).unwrap();

        assert_eq!(finding.severity, deserialized.severity);
        assert_eq!(finding.finding_type, deserialized.finding_type);
    }
}
