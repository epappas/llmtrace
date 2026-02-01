//! LLMTrace Transparent Proxy Server
//!
//! A transparent HTTP proxy that intercepts LLM API calls for observability
//! and security analysis. Supports OpenAI-compatible `/v1/chat/completions`
//! and `/v1/completions` endpoints, streaming SSE passthrough, async trace
//! capture, async security analysis, and circuit-breaker degradation.

use axum::routing::{any, get, post};
use axum::Router;
use clap::{Parser, Subcommand};
use llmtrace_core::{ProxyConfig, SecurityAnalyzer};
use llmtrace_proxy::alerts::AlertEngine;
use llmtrace_proxy::circuit_breaker::CircuitBreaker;
use llmtrace_proxy::config;
use llmtrace_proxy::cost::CostEstimator;
use llmtrace_proxy::cost_caps::CostTracker;
use llmtrace_proxy::proxy::{health_handler, proxy_handler, AppState};
use llmtrace_security::RegexSecurityAnalyzer;
use llmtrace_storage::StorageProfile;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

/// LLMTrace transparent proxy server for LLM API observability and security.
#[derive(Parser)]
#[command(name = "llmtrace-proxy", version, about, long_about = None)]
struct Cli {
    /// Path to YAML configuration file.
    #[arg(short, long, global = true, env = "LLMTRACE_CONFIG")]
    config: Option<PathBuf>,

    /// Override log level (trace, debug, info, warn, error).
    #[arg(long, global = true, env = "LLMTRACE_LOG_LEVEL")]
    log_level: Option<String>,

    /// Override log output format (text, json).
    #[arg(long, global = true, env = "LLMTRACE_LOG_FORMAT")]
    log_format: Option<String>,

    /// Subcommand to run. If omitted, starts the proxy server.
    #[command(subcommand)]
    command: Option<Commands>,
}

/// CLI subcommands.
#[derive(Subcommand)]
enum Commands {
    /// Validate a configuration file and print resolved settings.
    Validate,
}

// ---------------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Load, merge, and validate configuration
    let config = load_and_merge_config(&cli)?;

    match cli.command {
        Some(Commands::Validate) => run_validate(&config),
        None => {
            init_logging(&config)?;
            config::validate_config(&config)?;
            run_proxy(config).await
        }
    }
}

// ---------------------------------------------------------------------------
// Configuration loading
// ---------------------------------------------------------------------------

/// Load configuration from file/defaults, then apply env var and CLI overrides.
///
/// Precedence (highest wins):
/// 1. CLI flags (`--log-level`, `--log-format`)
/// 2. Environment variables (`LLMTRACE_LISTEN_ADDR`, etc.)
/// 3. Config file values
/// 4. Built-in defaults
fn load_and_merge_config(cli: &Cli) -> anyhow::Result<ProxyConfig> {
    let mut config = match &cli.config {
        Some(path) => {
            // Logging isn't initialised yet — use eprintln for early diagnostics.
            eprintln!("Loading configuration from {}", path.display());
            config::load_config(path)?
        }
        None => {
            eprintln!("No config file specified, using defaults");
            ProxyConfig::default()
        }
    };

    // Apply environment variable overrides
    config::apply_env_overrides(&mut config);

    // Apply CLI flag overrides (highest precedence)
    if let Some(ref level) = cli.log_level {
        config.logging.level.clone_from(level);
    }
    if let Some(ref format) = cli.log_format {
        config.logging.format.clone_from(format);
    }

    Ok(config)
}

// ---------------------------------------------------------------------------
// Subcommand: validate
// ---------------------------------------------------------------------------

/// Validate configuration and print resolved settings.
fn run_validate(config: &ProxyConfig) -> anyhow::Result<()> {
    config::validate_config(config)?;
    println!("✓ Configuration is valid.\n");
    println!("Resolved configuration:");
    println!("{}", serde_yaml::to_string(config)?);
    Ok(())
}

// ---------------------------------------------------------------------------
// Subcommand: run proxy (default)
// ---------------------------------------------------------------------------

/// Start the proxy server.
async fn run_proxy(config: ProxyConfig) -> anyhow::Result<()> {
    info!(
        listen_addr = %config.listen_addr,
        upstream_url = %config.upstream_url,
        storage_profile = %config.storage.profile,
        "Starting LLMTrace proxy server"
    );

    let listen_addr = config.listen_addr.clone();

    // Build shared application state
    let state = build_app_state(config).await?;

    // Build the axum router
    let app = build_router(state);

    // Bind and serve
    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    info!(%listen_addr, "Proxy server listening");
    axum::serve(listener, app).await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Structured logging
// ---------------------------------------------------------------------------

/// Initialize structured logging based on configuration.
///
/// The `RUST_LOG` environment variable takes highest precedence for
/// filter directives. Otherwise the `logging.level` from the resolved
/// configuration is used.
fn init_logging(config: &ProxyConfig) -> anyhow::Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&config.logging.level));

    match config.logging.format.as_str() {
        "json" => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(filter)
                .with_target(true)
                .with_thread_ids(true)
                .init();
        }
        _ => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(true)
                .init();
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Application wiring
// ---------------------------------------------------------------------------

/// Build the shared [`AppState`] from the proxy configuration.
async fn build_app_state(config: ProxyConfig) -> anyhow::Result<Arc<AppState>> {
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_millis(
            config.connection_timeout_ms,
        ))
        .timeout(std::time::Duration::from_millis(config.timeout_ms))
        .build()?;

    let profile =
        match config.storage.profile.as_str() {
            "memory" => StorageProfile::Memory,
            "production" => StorageProfile::Production {
                clickhouse_url: config
                    .storage
                    .clickhouse_url
                    .clone()
                    .unwrap_or_else(|| "http://localhost:8123".to_string()),
                clickhouse_database: config
                    .storage
                    .clickhouse_database
                    .clone()
                    .unwrap_or_else(|| "llmtrace".to_string()),
                postgres_url: config.storage.postgres_url.clone().unwrap_or_else(|| {
                    "postgres://llmtrace:llmtrace@localhost/llmtrace".to_string()
                }),
                redis_url: config
                    .storage
                    .redis_url
                    .clone()
                    .unwrap_or_else(|| "redis://127.0.0.1:6379".to_string()),
            },
            _ => StorageProfile::Lite {
                database_path: config.storage.database_path.clone(),
            },
        };

    info!(
        profile = %config.storage.profile,
        database_path = %config.storage.database_path,
        "Initializing storage"
    );
    let storage = profile
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to initialize storage: {}", e))?;

    let security = Arc::new(
        RegexSecurityAnalyzer::new()
            .map_err(|e| anyhow::anyhow!("Failed to initialize security analyzer: {}", e))?,
    ) as Arc<dyn SecurityAnalyzer>;

    let storage_breaker = Arc::new(CircuitBreaker::from_config(&config.circuit_breaker));
    let security_breaker = Arc::new(CircuitBreaker::from_config(&config.circuit_breaker));
    let cost_estimator = CostEstimator::new(&config.cost_estimation);
    let alert_engine = AlertEngine::from_config(&config.alerts, client.clone());
    let cost_tracker = CostTracker::new(&config.cost_caps, Arc::clone(&storage.cache));

    if alert_engine.is_some() {
        info!(
            webhook_url = %config.alerts.webhook_url,
            min_severity = %config.alerts.min_severity,
            "Alert engine enabled"
        );
    }
    if cost_tracker.is_some() {
        info!("Cost cap enforcement enabled");
    }

    Ok(Arc::new(AppState {
        config,
        client,
        storage,
        security,
        storage_breaker,
        security_breaker,
        cost_estimator,
        alert_engine,
        cost_tracker,
    }))
}

/// Build the axum [`Router`] with all routes.
fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        // REST Query API
        .route("/api/v1/traces", get(llmtrace_proxy::api::list_traces))
        .route(
            "/api/v1/traces/:trace_id",
            get(llmtrace_proxy::api::get_trace),
        )
        .route("/api/v1/spans", get(llmtrace_proxy::api::list_spans))
        .route(
            "/api/v1/spans/:span_id",
            get(llmtrace_proxy::api::get_span),
        )
        .route("/api/v1/stats", get(llmtrace_proxy::api::get_stats))
        .route(
            "/api/v1/security/findings",
            get(llmtrace_proxy::api::list_security_findings),
        )
        .route(
            "/api/v1/costs/current",
            get(llmtrace_proxy::api::get_current_costs),
        )
        // Agent action reporting and summary
        .route(
            "/api/v1/traces/:trace_id/actions",
            post(llmtrace_proxy::api::report_action),
        )
        .route(
            "/api/v1/actions/summary",
            get(llmtrace_proxy::api::actions_summary),
        )
        // Tenant Management API
        .route(
            "/api/v1/tenants",
            post(llmtrace_proxy::tenant_api::create_tenant)
                .get(llmtrace_proxy::tenant_api::list_tenants),
        )
        .route(
            "/api/v1/tenants/:id",
            get(llmtrace_proxy::tenant_api::get_tenant)
                .put(llmtrace_proxy::tenant_api::update_tenant)
                .delete(llmtrace_proxy::tenant_api::delete_tenant),
        )
        // OpenTelemetry OTLP/HTTP trace ingestion
        .route(
            "/v1/traces",
            post(llmtrace_proxy::otel::ingest_traces),
        )
        // Fallback: proxy everything else to upstream
        .fallback(any(proxy_handler))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use llmtrace_core::StorageConfig;
    use tower::ServiceExt;

    /// Build a test config that uses the in-memory storage profile.
    fn memory_config() -> ProxyConfig {
        ProxyConfig {
            storage: StorageConfig {
                profile: "memory".to_string(),
                database_path: String::new(),
                ..StorageConfig::default()
            },
            ..ProxyConfig::default()
        }
    }

    /// Build a test router with default config (in-memory storage).
    async fn test_app() -> Router {
        let state = build_app_state(memory_config()).await.unwrap();
        build_router(state)
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let app = test_app().await;
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
        assert!(json["storage"]["traces"]["healthy"].as_bool().unwrap());
        assert!(json["security"]["healthy"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_proxy_returns_bad_gateway_when_upstream_unreachable() {
        // Config pointing to an unreachable upstream
        let config = ProxyConfig {
            upstream_url: "http://127.0.0.1:1".to_string(), // nothing listening
            connection_timeout_ms: 100,
            timeout_ms: 500,
            storage: StorageConfig {
                profile: "memory".to_string(),
                database_path: String::new(),
                ..StorageConfig::default()
            },
            ..ProxyConfig::default()
        };
        let state = build_app_state(config).await.unwrap();
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
        let state = build_app_state(memory_config()).await;
        assert!(state.is_ok());
    }

    #[test]
    fn test_load_and_merge_config_defaults() {
        let cli = Cli {
            config: None,
            log_level: None,
            log_format: None,
            command: None,
        };
        let config = load_and_merge_config(&cli).unwrap();
        assert_eq!(config.listen_addr, "0.0.0.0:8080");
        assert_eq!(config.logging.level, "info");
        assert_eq!(config.logging.format, "text");
    }

    #[test]
    fn test_load_and_merge_config_cli_overrides() {
        let cli = Cli {
            config: None,
            log_level: Some("debug".to_string()),
            log_format: Some("json".to_string()),
            command: None,
        };
        let config = load_and_merge_config(&cli).unwrap();
        assert_eq!(config.logging.level, "debug");
        assert_eq!(config.logging.format, "json");
    }

    #[test]
    fn test_load_and_merge_config_from_file() {
        use std::io::Write;
        let yaml = r#"
listen_addr: "127.0.0.1:9999"
upstream_url: "http://localhost:11434"
timeout_ms: 60000
connection_timeout_ms: 5000
max_connections: 500
enable_tls: false
enable_security_analysis: true
enable_trace_storage: true
enable_streaming: true
max_request_size_bytes: 52428800
security_analysis_timeout_ms: 5000
trace_storage_timeout_ms: 10000
rate_limiting:
  enabled: true
  requests_per_second: 100
  burst_size: 200
  window_seconds: 60
circuit_breaker:
  enabled: true
  failure_threshold: 10
  recovery_timeout_ms: 30000
  half_open_max_calls: 3
health_check:
  enabled: true
  path: "/health"
  interval_seconds: 10
  timeout_ms: 5000
  retries: 3
logging:
  level: "warn"
  format: "json"
"#;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(yaml.as_bytes()).unwrap();

        let cli = Cli {
            config: Some(f.path().to_path_buf()),
            log_level: None,
            log_format: None,
            command: None,
        };
        let config = load_and_merge_config(&cli).unwrap();
        assert_eq!(config.listen_addr, "127.0.0.1:9999");
        assert_eq!(config.logging.level, "warn");
        assert_eq!(config.logging.format, "json");
    }
}
