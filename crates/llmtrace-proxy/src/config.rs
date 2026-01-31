//! YAML configuration loading for the proxy server.
//!
//! Loads [`ProxyConfig`] from a YAML file on disk, falling back to defaults
//! when no file is specified.

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

#[cfg(test)]
mod tests {
    use super::*;
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
}
