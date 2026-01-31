//! LLMTrace Transparent Proxy Server
//!
//! A transparent HTTP proxy that intercepts LLM API calls for observability and security analysis.

use llmtrace_core::{ProxyConfig, Result};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    info!("Starting LLMTrace proxy server...");

    // Load configuration (stub for now)
    let config = ProxyConfig::default();

    info!(
        "Proxy configuration loaded: listen_addr={}, upstream_url={}",
        config.listen_addr, config.upstream_url
    );

    // TODO: Implement actual proxy server
    // For now, just print configuration and exit
    info!("Proxy server would start here with config: {:?}", config);

    Ok(())
}

/// Placeholder for future proxy server implementation
#[allow(dead_code)]
async fn start_proxy_server(_config: ProxyConfig) -> Result<()> {
    // This will be implemented in later loops
    // Will use axum + hyper for the HTTP proxy
    unimplemented!("Proxy server implementation will be added in Loop 4")
}
