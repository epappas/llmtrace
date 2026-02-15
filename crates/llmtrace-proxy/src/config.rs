//! YAML configuration loading, environment variable overrides, and validation.
//!
//! Loads [`ProxyConfig`] from a YAML file on disk, applies environment variable
//! overrides, and validates the resulting configuration.

use llmtrace_core::ProxyConfig;
use std::path::Path;

/// Load a [`ProxyConfig`] from a YAML file at `path`.
///
/// # Errors
///
/// Returns an error if the file cannot be read or the YAML is invalid.
pub fn load_config(path: &Path) -> anyhow::Result<ProxyConfig> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Failed to read config file {}: {}", path.display(), e))?;
    let config: ProxyConfig = serde_yaml::from_str(&contents)
        .map_err(|e| anyhow::anyhow!("Failed to parse config YAML: {}", e))?;
    Ok(config)
}

/// Apply environment variable overrides to a [`ProxyConfig`].
///
/// Supported variables:
/// - `LLMTRACE_LISTEN_ADDR` → `listen_addr`
/// - `LLMTRACE_UPSTREAM_URL` → `upstream_url`
/// - `LLMTRACE_STORAGE_PROFILE` → `storage.profile`
/// - `LLMTRACE_STORAGE_DATABASE_PATH` → `storage.database_path`
/// - `LLMTRACE_CLICKHOUSE_URL` → `storage.clickhouse_url`
/// - `LLMTRACE_CLICKHOUSE_DATABASE` → `storage.clickhouse_database`
/// - `LLMTRACE_POSTGRES_URL` → `storage.postgres_url`
/// - `LLMTRACE_REDIS_URL` → `storage.redis_url`
pub fn apply_env_overrides(config: &mut ProxyConfig) {
    if let Ok(val) = std::env::var("LLMTRACE_LISTEN_ADDR") {
        config.listen_addr = val;
    }
    if let Ok(val) = std::env::var("LLMTRACE_UPSTREAM_URL") {
        config.upstream_url = val;
    }
    if let Ok(val) = std::env::var("LLMTRACE_STORAGE_PROFILE") {
        config.storage.profile = val;
    }
    if let Ok(val) = std::env::var("LLMTRACE_STORAGE_DATABASE_PATH") {
        config.storage.database_path = val;
    }
    if let Ok(val) = std::env::var("LLMTRACE_CLICKHOUSE_URL") {
        config.storage.clickhouse_url = Some(val);
    }
    if let Ok(val) = std::env::var("LLMTRACE_CLICKHOUSE_DATABASE") {
        config.storage.clickhouse_database = Some(val);
    }
    if let Ok(val) = std::env::var("LLMTRACE_POSTGRES_URL") {
        config.storage.postgres_url = Some(val);
    }
    if let Ok(val) = std::env::var("LLMTRACE_REDIS_URL") {
        config.storage.redis_url = Some(val);
    }
}

/// Validate a [`ProxyConfig`] for common configuration errors.
///
/// Returns `Ok(())` when valid, or an error listing all detected issues.
pub fn validate_config(config: &ProxyConfig) -> anyhow::Result<()> {
    let mut errors: Vec<String> = Vec::new();

    if config.listen_addr.is_empty() {
        errors.push("listen_addr must not be empty".to_string());
    }

    if config.upstream_url.is_empty() {
        errors.push("upstream_url must not be empty".to_string());
    } else if !config.upstream_url.starts_with("http://")
        && !config.upstream_url.starts_with("https://")
    {
        errors.push("upstream_url must start with http:// or https://".to_string());
    }

    match config.storage.profile.as_str() {
        "lite" | "memory" | "production" => {}
        other => errors.push(format!(
            "storage.profile must be 'lite', 'memory', or 'production', got '{other}'"
        )),
    }

    match config.logging.level.as_str() {
        "trace" | "debug" | "info" | "warn" | "error" => {}
        other => errors.push(format!(
            "logging.level must be trace/debug/info/warn/error, got '{other}'"
        )),
    }

    match config.logging.format.as_str() {
        "text" | "json" => {}
        other => errors.push(format!(
            "logging.format must be 'text' or 'json', got '{other}'"
        )),
    }

    if config.timeout_ms == 0 {
        errors.push("timeout_ms must be greater than 0".to_string());
    }

    if config.connection_timeout_ms == 0 {
        errors.push("connection_timeout_ms must be greater than 0".to_string());
    }

    if config.enable_tls {
        if config.tls_cert_file.is_none() {
            errors.push("tls_cert_file is required when enable_tls is true".to_string());
        }
        if config.tls_key_file.is_none() {
            errors.push("tls_key_file is required when enable_tls is true".to_string());
        }
    }

    // Enforcement config validation
    let enf = &config.enforcement;
    if !(0.0..=1.0).contains(&enf.min_confidence) {
        errors.push(format!(
            "enforcement.min_confidence must be between 0.0 and 1.0, got {}",
            enf.min_confidence
        ));
    }
    if enf.timeout_ms == 0 {
        errors.push("enforcement.timeout_ms must be greater than 0".to_string());
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "Configuration errors:\n  - {}",
            errors.join("\n  - ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use llmtrace_core::LoggingConfig;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Helper to write YAML to a temp file and return the path.
    fn write_yaml(yaml: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(yaml.as_bytes()).unwrap();
        f
    }

    #[test]
    fn test_load_config_minimal() {
        let yaml = r#"
listen_addr: "127.0.0.1:9090"
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
"#;
        let f = write_yaml(yaml);
        let config = load_config(f.path()).unwrap();
        assert_eq!(config.listen_addr, "127.0.0.1:9090");
        assert_eq!(config.upstream_url, "http://localhost:11434");
        assert_eq!(config.timeout_ms, 60000);
        // logging should use defaults when omitted from YAML
        assert_eq!(config.logging.level, "info");
        assert_eq!(config.logging.format, "text");
    }

    #[test]
    fn test_load_config_with_logging() {
        let yaml = r#"
listen_addr: "0.0.0.0:8080"
upstream_url: "https://api.openai.com"
timeout_ms: 30000
connection_timeout_ms: 5000
max_connections: 1000
enable_tls: false
enable_security_analysis: true
enable_trace_storage: true
enable_streaming: true
max_request_size_bytes: 52428800
security_analysis_timeout_ms: 5000
trace_storage_timeout_ms: 10000
logging:
  level: "debug"
  format: "json"
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
"#;
        let f = write_yaml(yaml);
        let config = load_config(f.path()).unwrap();
        assert_eq!(config.logging.level, "debug");
        assert_eq!(config.logging.format, "json");
    }

    #[test]
    fn test_load_config_missing_file() {
        let result = load_config(Path::new("/nonexistent/config.yaml"));
        assert!(result.is_err());
    }

    #[test]
    fn test_load_config_invalid_yaml() {
        let f = write_yaml("not: [valid: yaml: {{{}}}");
        let result = load_config(f.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_apply_env_overrides_listen_addr() {
        let mut config = ProxyConfig::default();
        std::env::set_var("LLMTRACE_LISTEN_ADDR", "127.0.0.1:3000");
        apply_env_overrides(&mut config);
        assert_eq!(config.listen_addr, "127.0.0.1:3000");
        std::env::remove_var("LLMTRACE_LISTEN_ADDR");
    }

    #[test]
    fn test_apply_env_overrides_upstream_url() {
        let mut config = ProxyConfig::default();
        std::env::set_var("LLMTRACE_UPSTREAM_URL", "http://my-llm:8000");
        apply_env_overrides(&mut config);
        assert_eq!(config.upstream_url, "http://my-llm:8000");
        std::env::remove_var("LLMTRACE_UPSTREAM_URL");
    }

    #[test]
    fn test_apply_env_overrides_storage() {
        let mut config = ProxyConfig::default();
        std::env::set_var("LLMTRACE_STORAGE_PROFILE", "memory");
        std::env::set_var("LLMTRACE_STORAGE_DATABASE_PATH", "/tmp/test.db");
        apply_env_overrides(&mut config);
        assert_eq!(config.storage.profile, "memory");
        assert_eq!(config.storage.database_path, "/tmp/test.db");
        std::env::remove_var("LLMTRACE_STORAGE_PROFILE");
        std::env::remove_var("LLMTRACE_STORAGE_DATABASE_PATH");
    }

    #[test]
    fn test_validate_config_valid() {
        let config = ProxyConfig::default();
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_validate_config_empty_listen_addr() {
        let config = ProxyConfig {
            listen_addr: String::new(),
            ..ProxyConfig::default()
        };
        let err = validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("listen_addr must not be empty"));
    }

    #[test]
    fn test_validate_config_empty_upstream_url() {
        let config = ProxyConfig {
            upstream_url: String::new(),
            ..ProxyConfig::default()
        };
        let err = validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("upstream_url must not be empty"));
    }

    #[test]
    fn test_validate_config_bad_upstream_url_scheme() {
        let config = ProxyConfig {
            upstream_url: "ftp://example.com".to_string(),
            ..ProxyConfig::default()
        };
        let err = validate_config(&config).unwrap_err();
        assert!(err
            .to_string()
            .contains("upstream_url must start with http://"));
    }

    #[test]
    fn test_validate_config_invalid_storage_profile() {
        let config = ProxyConfig {
            storage: llmtrace_core::StorageConfig {
                profile: "postgres".to_string(),
                database_path: String::new(),
                ..llmtrace_core::StorageConfig::default()
            },
            ..ProxyConfig::default()
        };
        let err = validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("storage.profile"));
    }

    #[test]
    fn test_validate_config_invalid_log_level() {
        let config = ProxyConfig {
            logging: LoggingConfig {
                level: "verbose".to_string(),
                format: "text".to_string(),
            },
            ..ProxyConfig::default()
        };
        let err = validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("logging.level"));
    }

    #[test]
    fn test_validate_config_invalid_log_format() {
        let config = ProxyConfig {
            logging: LoggingConfig {
                level: "info".to_string(),
                format: "xml".to_string(),
            },
            ..ProxyConfig::default()
        };
        let err = validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("logging.format"));
    }

    #[test]
    fn test_validate_config_zero_timeout() {
        let config = ProxyConfig {
            timeout_ms: 0,
            ..ProxyConfig::default()
        };
        let err = validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("timeout_ms"));
    }

    #[test]
    fn test_validate_config_tls_without_cert() {
        let config = ProxyConfig {
            enable_tls: true,
            tls_cert_file: None,
            tls_key_file: None,
            ..ProxyConfig::default()
        };
        let err = validate_config(&config).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("tls_cert_file"));
        assert!(msg.contains("tls_key_file"));
    }

    #[test]
    fn test_validate_config_enforcement_bad_confidence() {
        let config = ProxyConfig {
            enforcement: llmtrace_core::EnforcementConfig {
                min_confidence: 1.5,
                ..llmtrace_core::EnforcementConfig::default()
            },
            ..ProxyConfig::default()
        };
        let err = validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("enforcement.min_confidence"));
    }

    #[test]
    fn test_validate_config_enforcement_negative_confidence() {
        let config = ProxyConfig {
            enforcement: llmtrace_core::EnforcementConfig {
                min_confidence: -0.1,
                ..llmtrace_core::EnforcementConfig::default()
            },
            ..ProxyConfig::default()
        };
        let err = validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("enforcement.min_confidence"));
    }

    #[test]
    fn test_validate_config_enforcement_zero_timeout() {
        let config = ProxyConfig {
            enforcement: llmtrace_core::EnforcementConfig {
                timeout_ms: 0,
                ..llmtrace_core::EnforcementConfig::default()
            },
            ..ProxyConfig::default()
        };
        let err = validate_config(&config).unwrap_err();
        assert!(err.to_string().contains("enforcement.timeout_ms"));
    }

    #[test]
    fn test_validate_config_multiple_errors() {
        let config = ProxyConfig {
            listen_addr: String::new(),
            upstream_url: String::new(),
            timeout_ms: 0,
            ..ProxyConfig::default()
        };
        let err = validate_config(&config).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("listen_addr"));
        assert!(msg.contains("upstream_url"));
        assert!(msg.contains("timeout_ms"));
    }
}
