//! LLMTrace Transparent Proxy Server
//!
//! A transparent HTTP proxy that intercepts LLM API calls for observability
//! and security analysis. Supports OpenAI-compatible `/v1/chat/completions`
//! and `/v1/completions` endpoints, streaming SSE passthrough, async trace
//! capture, async security analysis, and circuit-breaker degradation.

use axum::middleware;
use axum::routing::{any, delete, get, post};
use axum::Router;
use clap::{Parser, Subcommand};
use llmtrace_core::{ProxyConfig, SecurityAnalyzer};
use llmtrace_proxy::alerts::AlertEngine;
use llmtrace_proxy::circuit_breaker::CircuitBreaker;
use llmtrace_proxy::config;
use llmtrace_proxy::cost::CostEstimator;
use llmtrace_proxy::cost_caps::CostTracker;
use llmtrace_proxy::proxy::{health_handler, proxy_handler, AppState, MlModelStatus};
use llmtrace_proxy::shutdown::{self, ShutdownCoordinator};
use llmtrace_security::RegexSecurityAnalyzer;
use llmtrace_storage::StorageProfile;
use std::path::PathBuf;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
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
    /// Run pending database migrations and exit.
    Migrate,
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
        Some(Commands::Migrate) => {
            init_logging(&config)?;
            run_migrate(&config).await
        }
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
// Subcommand: migrate
// ---------------------------------------------------------------------------

/// Run pending database migrations and exit.
async fn run_migrate(config: &ProxyConfig) -> anyhow::Result<()> {
    info!(
        profile = %config.storage.profile,
        "Running database migrations"
    );

    match config.storage.profile.as_str() {
        "lite" => {
            let url = format!("sqlite:{}", config.storage.database_path);
            let pool = llmtrace_storage::migration::open_sqlite_pool(&url).await?;
            llmtrace_storage::migration::run_sqlite_migrations(&pool).await?;
            info!("SQLite migrations complete");
        }
        "memory" => {
            info!("Memory profile uses no persistent storage — nothing to migrate");
        }
        "production" => {
            // Run PostgreSQL migrations for production metadata storage.
            if let Some(ref pg_url) = config.storage.postgres_url {
                let pool = llmtrace_storage::migration::open_pg_pool(pg_url).await?;
                llmtrace_storage::migration::run_pg_migrations(&pool).await?;
                info!("PostgreSQL migrations complete");
            } else {
                anyhow::bail!("storage.postgres_url is required for production profile migrations");
            }
        }
        other => {
            anyhow::bail!("Unknown storage profile: {other}");
        }
    }

    println!("✓ All migrations applied successfully.");
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
        shutdown_timeout_seconds = config.shutdown.timeout_seconds,
        "Starting LLMTrace proxy server"
    );

    let listen_addr = config.listen_addr.clone();

    // Build shared application state (includes the ShutdownCoordinator)
    let state = build_app_state(config).await?;
    let coordinator = state.shutdown.clone();

    // Optionally start the gRPC ingestion gateway in a background task.
    // The gRPC server shares the same cancellation token so it drains
    // gracefully when a shutdown signal arrives.
    if state.config.grpc.enabled {
        let grpc_state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = llmtrace_proxy::run_grpc_server(grpc_state).await {
                tracing::error!("gRPC server exited with error: {e}");
            }
        });
    }

    // Build the axum router
    let app = build_router(state);

    // Bind and serve with graceful shutdown
    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    info!(%listen_addr, "Proxy server listening");

    let shutdown_coord = coordinator.clone();
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown::shutdown_signal(shutdown_coord))
        .await?;

    // -------------------------------------------------------------------
    // Axum has stopped accepting new connections and is draining existing
    // ones. Now wait for in-flight background tasks (trace capture,
    // security analysis) to complete, up to the configured timeout.
    // -------------------------------------------------------------------
    let n = coordinator.in_flight_count();
    if n > 0 {
        info!(
            in_flight_tasks = n,
            "Waiting for in-flight background tasks to complete"
        );
    }
    coordinator.wait_for_tasks().await;
    info!("Shutdown complete");

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
///
/// Includes a [`ShutdownCoordinator`] initialised from the config's
/// `shutdown.timeout_seconds`.
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

    // Build the security analyzer — attempt ML warm-up if enabled and compiled
    let (security, ml_status) = build_security_analyzer(&config).await?;

    let storage_breaker = Arc::new(CircuitBreaker::from_config(&config.circuit_breaker));
    let security_breaker = Arc::new(CircuitBreaker::from_config(&config.circuit_breaker));
    let cost_estimator = CostEstimator::new(&config.cost_estimation);
    let alert_engine = AlertEngine::from_config(&config.alerts, client.clone());
    let cost_tracker = CostTracker::new(&config.cost_caps, Arc::clone(&storage.cache));
    let anomaly_detector = llmtrace_proxy::anomaly::AnomalyDetector::new(
        &config.anomaly_detection,
        Arc::clone(&storage.cache),
    );

    if let Some(ref engine) = alert_engine {
        info!(
            channels = engine.channel_count(),
            "Alert engine enabled with {} channel(s)",
            engine.channel_count(),
        );
    }
    if cost_tracker.is_some() {
        info!("Cost cap enforcement enabled");
    }
    if anomaly_detector.is_some() {
        info!("Anomaly detection enabled");
    }

    let report_store = llmtrace_proxy::compliance::new_report_store();
    let shutdown = ShutdownCoordinator::new(config.shutdown.timeout_seconds);
    let metrics = llmtrace_proxy::metrics::Metrics::new();
    let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Per-tenant rate limiter
    let rate_limiter = if config.rate_limiting.enabled {
        info!(
            rps = config.rate_limiting.requests_per_second,
            burst = config.rate_limiting.burst_size,
            overrides = config.rate_limiting.tenant_overrides.len(),
            "Per-tenant rate limiting enabled"
        );
        Some(llmtrace_proxy::RateLimiter::new(
            &config.rate_limiting,
            Arc::clone(&storage.cache),
        ))
    } else {
        None
    };

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
        anomaly_detector,
        report_store,
        rate_limiter,
        ml_status,
        shutdown,
        metrics,
        ready,
    }))
}

/// Build the security analyzer, pre-loading ML models at startup by default.
///
/// Since `ml_enabled` defaults to `true`, the default analyzer is the Ensemble
/// (regex + ML fusion), which preserves the regex baseline while adding ML.
/// When the `ml` feature is compiled in and `ml_preload: true` (also default),
/// this loads the prompt injection and NER models eagerly.
/// On failure, it falls back to the regex-only analyzer and logs a warning.
async fn build_security_analyzer(
    config: &ProxyConfig,
) -> anyhow::Result<(Arc<dyn SecurityAnalyzer>, MlModelStatus)> {
    // Optional runtime overrides (useful for local stacks and CI).
    // These do not modify the loaded config; they only affect analyzer wiring.
    let mut ml_enabled = config.security_analysis.ml_enabled;
    let mut ml_preload = config.security_analysis.ml_preload;
    if let Ok(v) = std::env::var("LLMTRACE_ML_ENABLED") {
        let v = v.to_lowercase();
        ml_enabled = !(v == "0" || v == "false" || v == "no");
        if !ml_enabled {
            tracing::info!("LLMTRACE_ML_ENABLED disabled ML security analysis");
        }
    }
    if let Ok(v) = std::env::var("LLMTRACE_ML_PRELOAD") {
        let v = v.to_lowercase();
        ml_preload = !(v == "0" || v == "false" || v == "no");
        if !ml_preload {
            tracing::info!("LLMTRACE_ML_PRELOAD disabled ML model preloading");
        }
    }

    #[cfg(feature = "ml")]
    {
        if ml_enabled && ml_preload {
            info!("Pre-loading ML models at startup (ml_preload=true)");
            let load_start = std::time::Instant::now();

            let ml_config = llmtrace_security::MLSecurityConfig {
                model_id: config.security_analysis.ml_model.clone(),
                threshold: config.security_analysis.ml_threshold,
                cache_dir: Some(config.security_analysis.ml_cache_dir.clone()),
            };

            let ner_config = if config.security_analysis.ner_enabled {
                Some(llmtrace_security::NerConfig {
                    model_id: config.security_analysis.ner_model.clone(),
                    cache_dir: Some(config.security_analysis.ml_cache_dir.clone()),
                })
            } else {
                None
            };

            // Apply download timeout
            let timeout = std::time::Duration::from_secs(
                config.security_analysis.ml_download_timeout_seconds,
            );

            match tokio::time::timeout(
                timeout,
                llmtrace_security::EnsembleSecurityAnalyzer::with_ner(
                    &ml_config,
                    ner_config.as_ref(),
                ),
            )
            .await
            {
                Ok(Ok(ensemble)) => {
                    let load_time_ms = load_start.elapsed().as_millis() as u64;
                    let pi_loaded = ensemble.is_ml_active();
                    let ner_loaded = ensemble.is_ner_active();
                    info!(
                        prompt_injection_loaded = pi_loaded,
                        ner_loaded = ner_loaded,
                        load_time_ms = load_time_ms,
                        "ML models pre-loaded at startup"
                    );
                    let status = MlModelStatus::Loaded {
                        prompt_injection: pi_loaded,
                        ner: ner_loaded,
                        load_time_ms,
                    };
                    Ok((Arc::new(ensemble) as Arc<dyn SecurityAnalyzer>, status))
                }
                Ok(Err(e)) => {
                    let err_msg = format!("{e}");
                    tracing::warn!(
                        error = %e,
                        "ML model loading failed at startup — falling back to regex analyzer"
                    );
                    let regex = RegexSecurityAnalyzer::new().map_err(|e| {
                        anyhow::anyhow!("Failed to initialize security analyzer: {}", e)
                    })?;
                    Ok((
                        Arc::new(regex) as Arc<dyn SecurityAnalyzer>,
                        MlModelStatus::Failed { error: err_msg },
                    ))
                }
                Err(_) => {
                    let err_msg = format!(
                        "ML model download timed out after {}s",
                        config.security_analysis.ml_download_timeout_seconds
                    );
                    tracing::warn!(
                        timeout_seconds = config.security_analysis.ml_download_timeout_seconds,
                        "ML model download timed out — falling back to regex analyzer"
                    );
                    let regex = RegexSecurityAnalyzer::new().map_err(|e| {
                        anyhow::anyhow!("Failed to initialize security analyzer: {}", e)
                    })?;
                    Ok((
                        Arc::new(regex) as Arc<dyn SecurityAnalyzer>,
                        MlModelStatus::Failed { error: err_msg },
                    ))
                }
            }
        } else if ml_enabled {
            // ML enabled but preload disabled — will load on first request
            info!("ML enabled but ml_preload=false — models will load on first request");
            let regex = RegexSecurityAnalyzer::new()
                .map_err(|e| anyhow::anyhow!("Failed to initialize security analyzer: {}", e))?;
            Ok((
                Arc::new(regex) as Arc<dyn SecurityAnalyzer>,
                MlModelStatus::Disabled,
            ))
        } else {
            let regex = RegexSecurityAnalyzer::new()
                .map_err(|e| anyhow::anyhow!("Failed to initialize security analyzer: {}", e))?;
            Ok((
                Arc::new(regex) as Arc<dyn SecurityAnalyzer>,
                MlModelStatus::Disabled,
            ))
        }
    }

    #[cfg(not(feature = "ml"))]
    {
        let _ = &config.security_analysis; // suppress unused warning
        let regex = RegexSecurityAnalyzer::new()
            .map_err(|e| anyhow::anyhow!("Failed to initialize security analyzer: {}", e))?;
        Ok((
            Arc::new(regex) as Arc<dyn SecurityAnalyzer>,
            MlModelStatus::Disabled,
        ))
    }
}

/// Build the axum [`Router`] with all routes.
fn build_router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/health", get(health_handler))
        .route("/metrics", get(llmtrace_proxy::metrics::metrics_handler))
        // Auth key management API
        .route(
            "/api/v1/auth/keys",
            post(llmtrace_proxy::auth::create_api_key)
                .get(llmtrace_proxy::auth::list_api_keys),
        )
        .route(
            "/api/v1/auth/keys/:id",
            delete(llmtrace_proxy::auth::revoke_api_key),
        )
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
        // Compliance reporting
        .route(
            "/api/v1/reports/generate",
            post(llmtrace_proxy::compliance::generate_report),
        )
        .route(
            "/api/v1/reports",
            get(llmtrace_proxy::compliance::list_reports),
        )
        .route(
            "/api/v1/reports/:id",
            get(llmtrace_proxy::compliance::get_report),
        )
        // OpenTelemetry OTLP/HTTP trace ingestion
        .route(
            "/v1/traces",
            post(llmtrace_proxy::otel::ingest_traces),
        )
        // Fallback: proxy everything else to upstream
        .fallback(any(proxy_handler))
        // Auth middleware — applied to all routes (skips /health internally)
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            llmtrace_proxy::auth::auth_middleware,
        ))
        .layer(cors)
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

    #[tokio::test]
    async fn test_metrics_endpoint_returns_prometheus_format() {
        let app = test_app().await;
        let req = Request::builder()
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let ct = response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            ct.contains("text/plain"),
            "Expected text/plain content type for Prometheus, got: {ct}"
        );

        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&body);

        // Should contain Prometheus HELP/TYPE declarations
        assert!(
            text.contains("# HELP llmtrace_active_connections"),
            "Missing active_connections metric"
        );
        assert!(
            text.contains("# TYPE llmtrace_active_connections gauge"),
            "Missing active_connections type"
        );
        assert!(
            text.contains("# HELP llmtrace_circuit_breaker_state"),
            "Missing circuit_breaker_state metric"
        );
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
