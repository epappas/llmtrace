//! LLMTrace SDK for Rust Applications
//!
//! This SDK provides embeddable tracing capabilities for Rust applications using LLM APIs.

use llmtrace_core::{LLMProvider, Result, TenantId, TraceSpan};
use uuid::Uuid;

/// Configuration for the LLMTrace SDK
#[derive(Debug, Clone)]
pub struct SDKConfig {
    pub tenant_id: TenantId,
    pub endpoint: Option<String>,
    pub enable_async_upload: bool,
    pub buffer_size: usize,
}

impl Default for SDKConfig {
    fn default() -> Self {
        Self {
            tenant_id: TenantId::new(),
            endpoint: None,
            enable_async_upload: true,
            buffer_size: 1000,
        }
    }
}

/// Main SDK client for tracing LLM calls
pub struct LLMTracer {
    config: SDKConfig,
    // TODO: Add trace buffer and uploader
}

impl LLMTracer {
    /// Create a new LLM tracer with the given configuration
    pub fn new(config: SDKConfig) -> Self {
        Self { config }
    }

    /// Create a new LLM tracer with default configuration
    pub fn with_defaults() -> Self {
        Self::new(SDKConfig::default())
    }

    /// Start a new trace span
    pub async fn start_span(
        &self,
        operation_name: &str,
        provider: LLMProvider,
        model: &str,
    ) -> TraceSpan {
        TraceSpan::new(
            Uuid::new_v4(), // trace_id
            self.config.tenant_id,
            operation_name.to_string(),
            provider,
            model.to_string(),
            String::new(), // empty prompt initially
        )
    }

    /// Trace an LLM call with automatic instrumentation
    pub async fn trace_call<F, R>(&self, _operation: &str, call: F) -> Result<R>
    where
        F: FnOnce() -> Result<R>,
    {
        // TODO: Implement automatic tracing wrapper
        // For now, just execute the function
        call()
    }

    /// Upload buffered traces (placeholder for async implementation)
    pub async fn flush(&self) -> Result<()> {
        // TODO: Implement trace upload to backend
        Ok(())
    }
}

/// Helper macro for instrumenting LLM calls
#[macro_export]
macro_rules! trace_llm_call {
    ($tracer:expr, $operation:expr, $block:expr) => {{
        // TODO: Implement macro-based instrumentation
        $block
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sdk_config_default() {
        let config = SDKConfig::default();
        assert!(config.enable_async_upload);
        assert_eq!(config.buffer_size, 1000);
    }

    #[tokio::test]
    async fn test_tracer_creation() {
        let tracer = LLMTracer::with_defaults();
        assert_eq!(tracer.config.buffer_size, 1000);
    }

    #[tokio::test]
    async fn test_start_span() {
        let tracer = LLMTracer::with_defaults();
        let span = tracer
            .start_span("test_operation", LLMProvider::OpenAI, "gpt-4")
            .await;

        assert_eq!(span.operation_name, "test_operation");
        assert_eq!(span.provider, LLMProvider::OpenAI);
        assert_eq!(span.model_name, "gpt-4");
        assert_eq!(span.tenant_id, tracer.config.tenant_id);
    }
}
