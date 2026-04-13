//! Thread-safe runtime-mutable wrapper around [`ProxyConfig`].
//!
//! Reads on the proxy hot path are lock-free via [`arc_swap::ArcSwap`].
//! Writes are serialized by an internal mutex so concurrent updates cannot
//! lose changes (clone → validate → atomic swap).

use arc_swap::ArcSwap;
use llmtrace_core::ProxyConfig;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Error returned when a config mutation fails validation.
#[derive(Debug, thiserror::Error)]
pub enum ConfigUpdateError {
    #[error("validation failed: {0}")]
    Validation(String),
    #[error("writer lock poisoned")]
    Poisoned,
}

/// Runtime-mutable config wrapper shared across handlers.
///
/// `load()` returns a lock-free guard suitable for synchronous reads that
/// do not cross `.await` points. Hot-path callers that hold the config
/// across an `await` must use [`ConfigHandle::snapshot`] instead, because
/// the guard returned by `load()` is `!Send`.
pub struct ConfigHandle {
    inner: ArcSwap<ProxyConfig>,
    /// Path to the base `config.yaml` (never mutated by this handle — the
    /// file may be a read-only ConfigMap mount on Kubernetes).
    config_path: Option<PathBuf>,
    /// Path to the sidecar `config.runtime.yaml` where runtime overrides
    /// are persisted (Phase 3). `None` disables persistence entirely.
    persist_path: Option<PathBuf>,
    /// Serializes concurrent writers so clone-validate-swap races cannot
    /// lose updates even though reads remain lock-free.
    write_lock: Mutex<()>,
}

impl ConfigHandle {
    pub fn new(
        config: ProxyConfig,
        config_path: Option<PathBuf>,
        persist_path: Option<PathBuf>,
    ) -> Self {
        Self {
            inner: ArcSwap::from_pointee(config),
            config_path,
            persist_path,
            write_lock: Mutex::new(()),
        }
    }

    /// Lock-free read. The returned guard must not cross an `.await`
    /// boundary because it is `!Send`.
    #[inline]
    pub fn load(&self) -> arc_swap::Guard<Arc<ProxyConfig>> {
        self.inner.load()
    }

    /// Full `Arc` clone of the current config. Cheap, `Send + 'static`.
    #[inline]
    pub fn snapshot(&self) -> Arc<ProxyConfig> {
        self.inner.load_full()
    }

    /// Atomically mutate the config through a validator closure.
    ///
    /// The mutator receives a mutable clone of the live config. If it
    /// returns `Ok(())`, the clone is swapped into place and returned to
    /// the caller. If it returns `Err`, the live config is untouched.
    /// Writers are serialized via an internal mutex so two concurrent
    /// callers cannot each base on the same snapshot and overwrite each
    /// other.
    pub fn update<F>(&self, mutator: F) -> Result<Arc<ProxyConfig>, ConfigUpdateError>
    where
        F: FnOnce(&mut ProxyConfig) -> Result<(), String>,
    {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| ConfigUpdateError::Poisoned)?;
        let current = self.inner.load_full();
        let mut next = (*current).clone();
        mutator(&mut next).map_err(ConfigUpdateError::Validation)?;
        let new_arc = Arc::new(next);
        self.inner.store(new_arc.clone());
        Ok(new_arc)
    }

    pub fn config_path(&self) -> Option<&PathBuf> {
        self.config_path.as_ref()
    }

    pub fn persist_path(&self) -> Option<&PathBuf> {
        self.persist_path.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    fn test_config() -> ProxyConfig {
        ProxyConfig::default()
    }

    #[test]
    fn load_returns_current_value() {
        let handle = ConfigHandle::new(test_config(), None, None);
        let snap = handle.load();
        assert_eq!(snap.max_request_size_bytes, test_config().max_request_size_bytes);
    }

    #[test]
    fn update_applies_mutation() {
        let handle = ConfigHandle::new(test_config(), None, None);
        let result = handle.update(|c| {
            c.max_request_size_bytes = 12345;
            Ok(())
        });
        assert!(result.is_ok());
        assert_eq!(handle.snapshot().max_request_size_bytes, 12345);
    }

    #[test]
    fn update_rollback_on_validation_error() {
        let handle = ConfigHandle::new(test_config(), None, None);
        let original = handle.snapshot().max_request_size_bytes;
        let result = handle.update(|c| {
            c.max_request_size_bytes = 9999;
            Err("nope".to_string())
        });
        assert!(matches!(result, Err(ConfigUpdateError::Validation(_))));
        assert_eq!(handle.snapshot().max_request_size_bytes, original);
    }

    #[test]
    fn concurrent_writers_do_not_lose_updates() {
        let handle = Arc::new(ConfigHandle::new(test_config(), None, None));
        let n = 100;
        let handles: Vec<_> = (0..n)
            .map(|_| {
                let h = handle.clone();
                thread::spawn(move || {
                    h.update(|c| {
                        c.max_request_size_bytes += 1;
                        Ok(())
                    })
                    .unwrap();
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let expected = test_config().max_request_size_bytes + n as u64;
        assert_eq!(handle.snapshot().max_request_size_bytes, expected);
    }
}
