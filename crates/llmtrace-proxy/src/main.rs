//! LLMTrace Transparent Proxy Server
//!
//! A transparent HTTP proxy that intercepts LLM API calls for observability
//! and security analysis. Supports OpenAI-compatible `/v1/chat/completions`
//! and `/v1/completions` endpoints, streaming SSE passthrough, async trace
//! capture, async security analysis, and circuit-breaker degradation.

use axum::middleware;
use axum::routing::{any, delete, get, post, put};
use axum::Router;
use clap::{Parser, Subcommand};
use llmtrace_core::{ProxyConfig, SecurityAnalyzer};
use llmtrace_proxy::alerts::AlertEngine;
use llmtrace_proxy::circuit_breaker::CircuitBreaker;
use llmtrace_proxy::config;
use llmtrace_proxy::cost::CostEstimator;
use llmtrace_proxy::cost_caps::CostTracker;
use llmtrace_proxy::openapi::ApiDoc;
use llmtrace_proxy::proxy::{health_handler, proxy_handler, AppState, MlModelStatus};
use llmtrace_proxy::shutdown::{self, ShutdownCoordinator};
use llmtrace_security::RegexSecurityAnalyzer;
use llmtrace_storage::StorageProfile;
use std::path::PathBuf;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

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

    /// Path to the sidecar `config.runtime.yaml` overlay written by the
    /// feature-flag admin API (issue #42).
    ///
    /// Takes precedence over the `LLMTRACE_RUNTIME_CONFIG` env var and
    /// the auto-derived `config.runtime.yaml` next to `--config`. If
    /// none of the three resolve, runtime persistence is disabled and
    /// PUTs to `/api/v1/config/features` apply in memory only.
    #[arg(long, global = true, env = "LLMTRACE_RUNTIME_CONFIG")]
    runtime_config: Option<PathBuf>,

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

/// Resolve the sidecar runtime-overlay path with the documented
/// precedence: explicit CLI / env flag wins, otherwise derive from the
/// base `--config` parent directory, otherwise `None` (persistence
/// disabled).
fn resolve_runtime_overlay_path(cli: &Cli) -> Option<PathBuf> {
    if let Some(path) = &cli.runtime_config {
        return Some(path.clone());
    }
    cli.config
        .as_ref()
        .and_then(|p| p.parent().map(|dir| dir.join("config.runtime.yaml")))
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
    let runtime_overlay_path = resolve_runtime_overlay_path(&cli);

    match cli.command {
        Some(Commands::Validate) => run_validate(&config),
        Some(Commands::Migrate) => {
            init_logging(&config)?;
            run_migrate(&config).await
        }
        None => {
            init_logging(&config)?;
            config::validate_config(&config)?;
            run_proxy(config, runtime_overlay_path).await
        }
    }
}

// ---------------------------------------------------------------------------
// Configuration loading
// ---------------------------------------------------------------------------

/// Load configuration from file/defaults, then apply the runtime
/// sidecar overlay, then env var overrides, then CLI flag overrides.
///
/// Precedence (highest wins):
/// 1. CLI flags (`--log-level`, `--log-format`)
/// 2. Environment variables (`LLMTRACE_LISTEN_ADDR`, etc.)
/// 3. Sidecar runtime overlay (`config.runtime.yaml` written by the
///    `/api/v1/config/features` admin API — issue #42)
/// 4. Config file values (`--config`)
/// 5. Built-in defaults
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

    // Apply the sidecar feature-flag overlay, if present. This sits
    // between the base config file and env/CLI overrides so operator
    // environment still wins over any runtime toggles.
    if let Some(overlay_path) = resolve_runtime_overlay_path(cli) {
        match llmtrace_proxy::feature_flags::load_runtime_overlay(&overlay_path) {
            Ok(Some(flags)) => {
                eprintln!(
                    "Applying runtime feature-flag overlay from {}",
                    overlay_path.display()
                );
                if let Err(e) = flags.apply_to_config(&mut config) {
                    eprintln!(
                        "Runtime overlay {} contains an invalid flag combination ({e}); ignoring",
                        overlay_path.display()
                    );
                }
            }
            Ok(None) => {}
            Err(e) => {
                eprintln!(
                    "Failed to load runtime overlay {}: {e}; continuing with base config",
                    overlay_path.display()
                );
            }
        }
    }

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
async fn run_proxy(
    config: ProxyConfig,
    runtime_overlay_path: Option<PathBuf>,
) -> anyhow::Result<()> {
    info!(
        listen_addr = %config.listen_addr,
        upstream_url = %config.upstream_url,
        storage_profile = %config.storage.profile,
        shutdown_timeout_seconds = config.shutdown.timeout_seconds,
        runtime_overlay_path = ?runtime_overlay_path,
        "Starting LLMTrace proxy server"
    );

    let listen_addr = config.listen_addr.clone();

    // Build shared application state (includes the ShutdownCoordinator)
    let state = build_app_state(config, runtime_overlay_path).await?;
    let coordinator = state.shutdown.clone();

    // Optionally start the gRPC ingestion gateway in a background task.
    // The gRPC server shares the same cancellation token so it drains
    // gracefully when a shutdown signal arrives.
    if state.config_handle.load().grpc.enabled {
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
///
/// Also probes the runtime feature-flag overlay path for writability
/// and logs a loud WARN if persistence will silently fail (common
/// under read-only Kubernetes ConfigMap mounts). The probe uses
/// `tempfile::NamedTempFile` for a symlink-resistant test (the crate
/// opens with `O_EXCL | O_CREAT` and randomizes the suffix), writes
/// a small non-empty payload so per-file-quota / fs-full surfaces
/// immediately, and automatically cleans up via the tempfile `Drop`
/// impl.
///
/// On failure the tuple `(ReasonCode, String)` is returned — the code
/// is stored on `AppState` and surfaced on `/health`, the string goes
/// straight into the startup WARN log so operators still get the raw
/// diagnostic server-side.
fn probe_runtime_overlay_writable(
    path: &std::path::Path,
) -> Result<(), (llmtrace_proxy::proxy::RuntimeOverlayReasonCode, String)> {
    use llmtrace_proxy::proxy::RuntimeOverlayReasonCode;
    use std::io::Write;

    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => std::path::PathBuf::from("."),
    };
    if !parent.exists() {
        if let Err(e) = std::fs::create_dir_all(&parent) {
            let code = RuntimeOverlayReasonCode::from_io_error(&e);
            return Err((
                code,
                format!(
                    "runtime overlay parent {} is not creatable: {e}",
                    parent.display()
                ),
            ));
        }
    }

    // Create a randomised tempfile in the target parent, write a
    // small payload, flush, and let the `NamedTempFile` destructor
    // remove it. Symlinks planted at a deterministic path cannot
    // redirect this write.
    let mut tmp = match tempfile::NamedTempFile::new_in(&parent) {
        Ok(t) => t,
        Err(e) => {
            let code = RuntimeOverlayReasonCode::from_io_error(&e);
            return Err((
                code,
                format!(
                    "runtime overlay parent {} is not writable: {e}",
                    parent.display()
                ),
            ));
        }
    };
    if let Err(e) = tmp.write_all(b"llmtrace_probe\n") {
        let code = RuntimeOverlayReasonCode::from_io_error(&e);
        return Err((
            code,
            format!(
                "runtime overlay parent {} failed probe write: {e}",
                parent.display()
            ),
        ));
    }
    if let Err(e) = tmp.as_file().sync_all() {
        let code = RuntimeOverlayReasonCode::from_io_error(&e);
        return Err((
            code,
            format!(
                "runtime overlay parent {} failed probe fsync: {e}",
                parent.display()
            ),
        ));
    }
    // Tempfile is closed and removed when `tmp` drops at end of scope.
    drop(tmp);
    Ok(())
}

async fn build_app_state(
    config: ProxyConfig,
    runtime_overlay_path: Option<PathBuf>,
) -> anyhow::Result<Arc<AppState>> {
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
    let (security, ml_status, ensemble_runtime) = build_security_analyzer(&config).await?;

    // Regex-only analyzer for fast-path enforcement (near-zero latency).
    // Shares the jailbreak toggle with the ensemble's inner regex analyzer
    // via the runtime handle so runtime flag flips affect both (#42).
    let fast_analyzer: Arc<dyn llmtrace_core::SecurityAnalyzer> = Arc::new(
        llmtrace_security::RegexSecurityAnalyzer::new_with_jailbreak_flag(
            ensemble_runtime.jailbreak_flag(),
        )
        .map_err(|e| anyhow::anyhow!("Failed to build fast analyzer: {e}"))?,
    );

    let storage_breaker = Arc::new(CircuitBreaker::from_config(&config.circuit_breaker));
    let security_breaker = Arc::new(CircuitBreaker::from_config(&config.circuit_breaker));
    let cost_estimator = CostEstimator::new(&config.cost_estimation);
    let alert_engine = AlertEngine::from_config(&config.alerts, client.clone());
    // Always construct the cost tracker so the runtime feature-flag API
    // can toggle cost caps on and off without restart (#42). Hot-path
    // call sites gate usage on the live `cfg.cost_caps.enabled`.
    let cost_tracker = CostTracker::new(&config.cost_caps, Arc::clone(&storage.cache));
    let anomaly_detector = llmtrace_proxy::anomaly::AnomalyDetector::new(
        &config.anomaly_detection,
        Arc::clone(&storage.cache),
    );
    #[cfg_attr(not(feature = "judge"), allow(unused_mut))]
    let mut action_router = llmtrace_proxy::action_router::ActionRouter::new(
        &config.action_router,
        config.judge.promotion.clone(),
        config.judge.worker.max_analysis_text_bytes,
        Some(Arc::clone(&storage.cache)),
        client.clone(),
    );

    // Claim the judge channel receiver before the router is moved into
    // AppState so the judge worker can consume it. Returns None when the
    // action router is disabled (the JudgeRouteAction is not registered
    // in that case and the channel is never used).
    #[cfg(feature = "judge")]
    let judge_rx = action_router.take_judge_receiver();

    if let Some(ref engine) = alert_engine {
        info!(
            channels = engine.channel_count(),
            "Alert engine enabled with {} channel(s)",
            engine.channel_count(),
        );
    }
    if cost_tracker.is_enabled() {
        info!("Cost cap enforcement enabled");
    }
    if anomaly_detector.is_some() {
        info!("Anomaly detection enabled");
    }

    let report_store = llmtrace_proxy::compliance::new_report_store();
    let shutdown = ShutdownCoordinator::new(config.shutdown.timeout_seconds);
    let metrics = llmtrace_proxy::metrics::Metrics::new();
    let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Boundary defense startup state
    if config.boundary_defense.enabled {
        info!(
            shadow_mode = config.boundary_defense.shadow_mode,
            delimiter = %config.boundary_defense.delimiter,
            wrap_roles = ?config.boundary_defense.wrap_roles,
            randomize_nonce = config.boundary_defense.randomize_nonce,
            "Boundary defense enabled"
        );
        if config.boundary_defense.shadow_mode {
            metrics.boundary_defense_shadow_mode.set(1);
        }
    }

    // Always construct the per-tenant rate limiter so the runtime
    // feature-flag API can toggle rate limiting on and off without
    // restart (#42). Hot-path call sites gate usage on the live
    // `cfg.rate_limiting.enabled`.
    if config.rate_limiting.enabled {
        info!(
            rps = config.rate_limiting.requests_per_second,
            burst = config.rate_limiting.burst_size,
            overrides = config.rate_limiting.tenant_overrides.len(),
            "Per-tenant rate limiting enabled"
        );
    }
    let rate_limiter =
        llmtrace_proxy::RateLimiter::new(&config.rate_limiting, Arc::clone(&storage.cache));

    // Warn loudly if the runtime overlay path is configured but the
    // filesystem refuses writes. Operators running under a read-only
    // ConfigMap mount will otherwise see silent failures at the first
    // admin PUT. The probe result is also cached on AppState and
    // surfaced via /health so Kubernetes readiness probes can fail
    // fast on the silent-revert trap (see docs/runbooks/feature-flags.md).
    let runtime_overlay_status = match runtime_overlay_path.as_ref() {
        None => llmtrace_proxy::proxy::RuntimeOverlayStatus::Disabled,
        Some(path) => match probe_runtime_overlay_writable(path) {
            Ok(()) => {
                info!(
                    runtime_overlay = %path.display(),
                    "Runtime feature-flag overlay path is writable"
                );
                llmtrace_proxy::proxy::RuntimeOverlayStatus::Writable
            }
            Err((reason_code, reason_log)) => {
                // The raw `reason_log` (with path + errno) is logged
                // server-side only. /health exposes only the stable
                // `reason_code.as_str()` to avoid leaking the
                // filesystem layout to unauthenticated callers
                // (issue #42 C1).
                tracing::warn!(
                    runtime_overlay = %path.display(),
                    reason_code = %reason_code.as_str(),
                    reason = %reason_log,
                    "Runtime feature-flag overlay path is not writable. \
                     Admin PUTs to /api/v1/config/features will still apply \
                     in memory but the sidecar will NOT persist across \
                     restarts. See docs/runbooks/feature-flags.md for the \
                     'runtime overlay didn't persist' entry. Mount an \
                     emptyDir or writable volume at the runtime overlay \
                     parent directory to enable persistence."
                );
                llmtrace_proxy::proxy::RuntimeOverlayStatus::NotWritable { reason_code }
            }
        },
    };

    let config_handle =
        llmtrace_proxy::config_handle::ConfigHandle::new(config, None, runtime_overlay_path);

    // Spawn the LLM-as-a-Judge worker before AppState is finalized so
    // any subsequent request handlers can dispatch `JudgeRouteAction`
    // without racing the worker startup. `judge.enabled=false` at
    // startup skips the spawn entirely -- see `build_judge_backend`.
    #[cfg(feature = "judge")]
    let judge_worker_spawned: bool = {
        if let Some(rx) = judge_rx {
            let judge_cfg = config_handle.snapshot().judge.clone();
            match llmtrace_proxy::judge::build_judge_backend(&judge_cfg, client.clone()).await {
                Ok(Some(backend)) => {
                    let store = Arc::clone(&storage.judge_verdicts);
                    let cfg_source: Arc<dyn llmtrace_proxy::judge::ConfigSnapshotSource> =
                        Arc::new(config_handle.clone());
                    let worker = llmtrace_proxy::judge::JudgeWorker::new(
                        rx,
                        backend,
                        store,
                        cfg_source,
                        metrics.clone(),
                        judge_cfg.worker.max_concurrency,
                        shutdown.clone(),
                    );
                    info!(
                        backend = ?judge_cfg.backend,
                        max_concurrency = judge_cfg.worker.max_concurrency,
                        min_score_threshold = judge_cfg.min_score_threshold,
                        persist_verdicts = judge_cfg.persist_verdicts,
                        "LLM-as-a-Judge worker started"
                    );
                    tokio::spawn(worker.run());
                    true
                }
                Ok(None) => {
                    info!(
                        "LLM-as-a-Judge disabled at startup; worker not spawned. \
                         Flip the llm_judge_enabled flag and restart to activate."
                    );
                    false
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "Failed to construct judge backend; worker not spawned. \
                         Requests routed to JudgeRouteAction will fail-open."
                    );
                    false
                }
            }
        } else {
            false
        }
    };
    #[cfg(not(feature = "judge"))]
    let judge_worker_spawned: bool = false;

    let state = Arc::new(AppState {
        config_handle,
        client,
        storage,
        security,
        ensemble_runtime,
        fast_analyzer,
        storage_breaker,
        security_breaker,
        cost_estimator,
        alert_engine,
        cost_tracker,
        anomaly_detector,
        action_router,
        report_store,
        rate_limiter,
        ml_status,
        judge_worker_spawned,
        runtime_overlay_status,
        shutdown,
        metrics,
        ready,
    });

    // Seed the per-flag state metric so dashboards reflect the
    // startup configuration immediately, without waiting for the first
    // admin PUT.
    llmtrace_proxy::feature_flags_api::init_state_metrics(
        &state,
        &llmtrace_proxy::feature_flags::FeatureFlags::from_config(&state.config_handle.snapshot()),
    );

    Ok(state)
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
) -> anyhow::Result<(
    Arc<dyn SecurityAnalyzer>,
    MlModelStatus,
    Arc<llmtrace_security::EnsembleRuntimeHandle>,
)> {
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
    let ml_cache_dir = std::env::var("LLMTRACE_ML_CACHE_DIR")
        .unwrap_or_else(|_| config.security_analysis.ml_cache_dir.clone());

    #[cfg(feature = "ml")]
    {
        if ml_enabled && ml_preload {
            info!("Pre-loading ML models at startup (ml_preload=true)");
            let load_start = std::time::Instant::now();

            let ml_config = llmtrace_security::MLSecurityConfig {
                model_id: config.security_analysis.ml_model.clone(),
                threshold: config.security_analysis.ml_threshold,
                cache_dir: Some(ml_cache_dir.clone()),
            };

            let ner_config = if config.security_analysis.ner_enabled {
                Some(llmtrace_security::NerConfig {
                    model_id: config.security_analysis.ner_model.clone(),
                    cache_dir: Some(ml_cache_dir.clone()),
                })
            } else {
                None
            };

            let ig_config = if config.security_analysis.injecguard_enabled {
                Some(llmtrace_security::InjecGuardConfig {
                    model_id: config.security_analysis.injecguard_model.clone(),
                    threshold: config.security_analysis.injecguard_threshold,
                    cache_dir: Some(ml_cache_dir.clone()),
                })
            } else {
                None
            };

            let pg_config = if config.security_analysis.piguard_enabled {
                Some(llmtrace_security::PIGuardConfig {
                    model_id: config.security_analysis.piguard_model.clone(),
                    threshold: config.security_analysis.piguard_threshold,
                    cache_dir: Some(ml_cache_dir.clone()),
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
                llmtrace_security::EnsembleSecurityAnalyzer::with_piguard(
                    &ml_config,
                    ner_config.as_ref(),
                    ig_config.as_ref(),
                    pg_config.as_ref(),
                ),
            )
            .await
            {
                Ok(Ok(ensemble)) => {
                    let load_time_ms = load_start.elapsed().as_millis() as u64;
                    let pi_loaded = ensemble.is_ml_active();
                    let ner_loaded = ensemble.is_ner_active();
                    let ig_loaded = ensemble.is_injecguard_active();
                    let pg_loaded = ensemble.is_piguard_active();
                    // DeBERTa models ~500 MB each, NER (BERT-base) ~400 MB
                    let deberta_count = [pi_loaded, ig_loaded, pg_loaded]
                        .iter()
                        .filter(|&&v| v)
                        .count();
                    let ner_mb = if ner_loaded { 400 } else { 0 };
                    let estimated_mb = deberta_count * 500 + ner_mb;
                    let total_models = deberta_count + (ner_loaded as usize);
                    info!(
                        prompt_injection_loaded = pi_loaded,
                        ner_loaded = ner_loaded,
                        injecguard_loaded = ig_loaded,
                        piguard_loaded = pg_loaded,
                        load_time_ms = load_time_ms,
                        estimated_memory_mb = estimated_mb,
                        "ML models pre-loaded at startup (~{estimated_mb} MB for {total_models} model(s))"
                    );
                    let status = MlModelStatus::Loaded {
                        prompt_injection: pi_loaded,
                        ner: ner_loaded,
                        injecguard: ig_loaded,
                        piguard: pg_loaded,
                        load_time_ms,
                    };
                    let op = match config.security_analysis.operating_point {
                        llmtrace_core::OperatingPoint::HighRecall => {
                            llmtrace_security::OperatingPoint::HighRecall
                        }
                        llmtrace_core::OperatingPoint::HighPrecision => {
                            llmtrace_security::OperatingPoint::HighPrecision
                        }
                        llmtrace_core::OperatingPoint::Balanced => {
                            llmtrace_security::OperatingPoint::Balanced
                        }
                    };
                    let ensemble = ensemble
                        .with_operating_point(op)
                        .with_over_defence(config.security_analysis.over_defence);
                    // Initialise the runtime handle from config so the
                    // starting state matches what the operator asked for.
                    let handle = ensemble.runtime_handle();
                    handle.set_ml(config.security_analysis.ml_enabled);
                    handle.set_injecguard(config.security_analysis.injecguard_enabled);
                    handle.set_piguard(config.security_analysis.piguard_enabled);
                    handle.set_jailbreak(config.security_analysis.jailbreak_enabled);
                    Ok((
                        Arc::new(ensemble) as Arc<dyn SecurityAnalyzer>,
                        status,
                        Arc::new(handle),
                    ))
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
                        Arc::new(llmtrace_security::EnsembleRuntimeHandle::inert()),
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
                        Arc::new(llmtrace_security::EnsembleRuntimeHandle::inert()),
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
                Arc::new(llmtrace_security::EnsembleRuntimeHandle::inert()),
            ))
        } else {
            let regex = RegexSecurityAnalyzer::new()
                .map_err(|e| anyhow::anyhow!("Failed to initialize security analyzer: {}", e))?;
            Ok((
                Arc::new(regex) as Arc<dyn SecurityAnalyzer>,
                MlModelStatus::Disabled,
                Arc::new(llmtrace_security::EnsembleRuntimeHandle::inert()),
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
            Arc::new(llmtrace_security::EnsembleRuntimeHandle::inert()),
        ))
    }
}

/// Build the axum [`Router`] with all routes.
fn build_router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let router = Router::new()
        // OpenAPI / Swagger UI (served by the proxy itself, not forwarded upstream).
        .merge(SwaggerUi::new("/swagger-ui").url("/api-doc/openapi.json", ApiDoc::openapi()))
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
        .route(
            "/api/v1/config/live",
            get(llmtrace_proxy::api::get_live_config),
        )
        // Runtime feature flag admin API (issue #42)
        .route(
            "/api/v1/config/features",
            get(llmtrace_proxy::feature_flags_api::get_features)
                .put(llmtrace_proxy::feature_flags_api::bulk_update_features),
        )
        .route(
            "/api/v1/config/features/:feature",
            put(llmtrace_proxy::feature_flags_api::update_feature),
        )
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
            "/api/v1/stats/global",
            get(llmtrace_proxy::api::get_global_stats),
        )
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
                            "/api/v1/tenants/current/token",
                            get(llmtrace_proxy::tenant_api::get_current_tenant_token),
                        )
                        .route(
                            "/api/v1/tenants/:id/token",
                            get(llmtrace_proxy::tenant_api::get_tenant_token),
                        )
        .route(
            "/api/v1/tenants/:id",
            get(llmtrace_proxy::tenant_api::get_tenant)
                .put(llmtrace_proxy::tenant_api::update_tenant)
                .delete(llmtrace_proxy::tenant_api::delete_tenant),
        )
        .route(
            "/api/v1/tenants/:id/token/reset",
            post(llmtrace_proxy::tenant_api::reset_tenant_token),
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
        );

    // Debug routes — registered only when `server.debug_endpoints: true`.
    // Used by the e2e adversarial test framework (#91 / #95) to read
    // judge verdicts back by trace_id. Default is OFF; production
    // proxies must never enable this because verdicts are returned
    // un-auth-gated by trace_id.
    let router = if state.config_handle.snapshot().server.debug_endpoints {
        tracing::warn!(
            "Debug endpoints enabled (server.debug_endpoints=true). \
             Do not run with this flag in production."
        );
        router.route(
            "/debug/judge/verdicts",
            get(llmtrace_proxy::debug::verdict_by_trace_id_handler),
        )
    } else {
        router
    };

    router
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
        let state = build_app_state(memory_config(), None).await.unwrap();
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
        let state = build_app_state(config, None).await.unwrap();
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
        let state = build_app_state(memory_config(), None).await;
        assert!(state.is_ok());
    }

    // ---- /debug/judge/verdicts (Loop E2E-L5 of #91) -----------------

    fn debug_endpoints_config(enabled: bool) -> ProxyConfig {
        let mut cfg = memory_config();
        cfg.server.debug_endpoints = enabled;
        cfg
    }

    async fn insert_test_verdict(
        state: &Arc<llmtrace_proxy::AppState>,
        trace_id: uuid::Uuid,
    ) -> llmtrace_core::JudgeVerdict {
        use chrono::Utc;
        let verdict = llmtrace_core::JudgeVerdict {
            id: uuid::Uuid::new_v4(),
            trace_id,
            tenant_id: llmtrace_core::TenantId(uuid::Uuid::new_v4()),
            is_threat: true,
            category: "prompt_injection".to_string(),
            confidence: 0.92,
            security_score: 80,
            recommended_action: "flag".to_string(),
            reasoning: "test verdict".to_string(),
            mode: llmtrace_core::JudgeMode::Async,
            model_used: "test-model".to_string(),
            latency_ms: 12,
            prompt_tokens: None,
            completion_tokens: None,
            created_at: Utc::now(),
        };
        state
            .storage
            .judge_verdicts
            .insert_verdict(&verdict)
            .await
            .expect("verdict insert");
        verdict
    }

    #[tokio::test]
    async fn test_debug_verdicts_returns_404_when_flag_off() {
        let state = build_app_state(debug_endpoints_config(false), None)
            .await
            .unwrap();
        let _ = insert_test_verdict(&state, uuid::Uuid::new_v4()).await;
        let app = build_router(state);
        let req = Request::builder()
            .uri(format!(
                "/debug/judge/verdicts?trace_id={}",
                uuid::Uuid::new_v4()
            ))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "debug route must NOT be mounted when server.debug_endpoints=false"
        );
    }

    #[tokio::test]
    async fn test_debug_verdicts_returns_404_when_no_verdict_for_trace() {
        let state = build_app_state(debug_endpoints_config(true), None)
            .await
            .unwrap();
        let app = build_router(state);
        let req = Request::builder()
            .uri(format!(
                "/debug/judge/verdicts?trace_id={}",
                uuid::Uuid::new_v4()
            ))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_debug_verdicts_returns_verdict_when_present() {
        let trace_id = uuid::Uuid::new_v4();
        let state = build_app_state(debug_endpoints_config(true), None)
            .await
            .unwrap();
        let inserted = insert_test_verdict(&state, trace_id).await;
        let app = build_router(state);
        let req = Request::builder()
            .uri(format!("/debug/judge/verdicts?trace_id={trace_id}"))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let payload: llmtrace_core::JudgeVerdict =
            serde_json::from_slice(&body).expect("response is a JudgeVerdict");
        assert_eq!(payload.id, inserted.id);
        assert_eq!(payload.trace_id, trace_id);
        assert_eq!(payload.category, "prompt_injection");
        assert!(payload.is_threat);
    }

    #[tokio::test]
    async fn test_debug_verdicts_rejects_non_uuid_trace_id() {
        let state = build_app_state(debug_endpoints_config(true), None)
            .await
            .unwrap();
        let app = build_router(state);
        let req = Request::builder()
            .uri("/debug/judge/verdicts?trace_id=not-a-uuid")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_load_and_merge_config_defaults() {
        let cli = Cli {
            runtime_config: None,
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
            runtime_config: None,
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
            runtime_config: None,
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
