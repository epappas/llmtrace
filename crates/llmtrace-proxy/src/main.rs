//! LLMTrace Transparent Proxy Server
//!
//! A transparent HTTP proxy that intercepts LLM API calls for observability
//! and security analysis. Supports OpenAI-compatible `/v1/chat/completions`
//! and `/v1/completions` endpoints, streaming SSE passthrough, async trace
//! capture, async security analysis, and circuit-breaker degradation.

mod circuit_breaker;
mod config;
mod proxy;

use crate::circuit_breaker::CircuitBreaker;
use crate::proxy::{health_handler, proxy_handler, AppState};
use axum::routing::{any, get};
use axum::Router;
use llmtrace_core::ProxyConfig;
use llmtrace_security::RegexSecurityAnalyzer;
use llmtrace_storage::InMemoryStorage;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize structured logging
    tracing_subscriber::fmt::init();

    // Load configuration: from CLI arg, env var, or default
    let config = load_proxy_config()?;

    info!(
        listen_addr = %config.listen_addr,
        upstream_url = %config.upstream_url,
        "Starting LLMTrace proxy server"
    );

    let listen_addr = config.listen_addr.clone();

    // Build shared application state
    let state = build_app_state(config)?;

    // Build the axum router
    let app = build_router(state);

    // Bind and serve
    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    info!(%listen_addr, "Proxy server listening");
    axum::serve(listener, app).await?;

    Ok(())
}

/// Load proxy configuration from a YAML file or fall back to defaults.
///
/// Checks (in order):
/// 1. First CLI argument as config path
/// 2. `LLMTRACE_CONFIG` environment variable
/// 3. Default configuration
fn load_proxy_config() -> anyhow::Result<ProxyConfig> {
    let config_path: Option<PathBuf> = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("LLMTRACE_CONFIG").ok())
        .map(PathBuf::from);

    match config_path {
        Some(path) => {
            info!(path = %path.display(), "Loading configuration from file");
            config::load_config(&path)
        }
        None => {
            info!("No config file specified, using defaults");
            Ok(ProxyConfig::default())
        }
    }
}

/// Build the shared [`AppState`] from the proxy configuration.
fn build_app_state(config: ProxyConfig) -> anyhow::Result<Arc<AppState>> {
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_millis(
            config.connection_timeout_ms,
        ))
        .timeout(std::time::Duration::from_millis(config.timeout_ms))
        .build()?;

    let storage = Arc::new(InMemoryStorage::new()) as Arc<dyn llmtrace_core::StorageBackend>;

    let security = Arc::new(
        RegexSecurityAnalyzer::new()
            .map_err(|e| anyhow::anyhow!("Failed to initialize security analyzer: {}", e))?,
    ) as Arc<dyn llmtrace_core::SecurityAnalyzer>;

    let storage_breaker = Arc::new(CircuitBreaker::from_config(&config.circuit_breaker));
    let security_breaker = Arc::new(CircuitBreaker::from_config(&config.circuit_breaker));

    Ok(Arc::new(AppState {
        config,
        client,
        storage,
        security,
        storage_breaker,
        security_breaker,
    }))
}

/// Build the axum [`Router`] with all routes.
fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .fallback(any(proxy_handler))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    /// Build a test router with default config.
    fn test_app() -> Router {
        let config = ProxyConfig::default();
        let state = build_app_state(config).unwrap();
        build_router(state)
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let app = test_app();
        let req = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "healthy");
        assert!(json["storage"]["healthy"].as_bool().unwrap());
        assert!(json["security"]["healthy"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_proxy_returns_bad_gateway_when_upstream_unreachable() {
        // Config pointing to an unreachable upstream
        let config = ProxyConfig {
            upstream_url: "http://127.0.0.1:1".to_string(), // nothing listening
            connection_timeout_ms: 100,
            timeout_ms: 500,
            ..ProxyConfig::default()
        };
        let state = build_app_state(config).unwrap();
        let app = build_router(state);

        let body = serde_json::json!({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "Hello"}]
        });

        let req = Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("content-type", "application/json")
            .header("authorization", "Bearer sk-test")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn test_build_app_state_succeeds() {
        let config = ProxyConfig::default();
        let state = build_app_state(config);
        assert!(state.is_ok());
    }
}
