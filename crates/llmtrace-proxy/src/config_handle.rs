//! Thread-safe runtime-mutable wrapper around [`ProxyConfig`].
//!
//! Reads on the proxy hot path are lock-free via [`arc_swap::ArcSwap`].
//! Writes are serialized by an internal mutex so concurrent updates cannot
//! lose changes (clone → validate → atomic swap).

use arc_swap::ArcSwap;
use llmtrace_core::ProxyConfig;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Lock-free read guard returned by [`ConfigHandle::load`].
///
/// Wraps `arc_swap::Guard<Arc<ProxyConfig>>` so the `arc_swap` type
/// never appears in the public `llmtrace_proxy` API surface. Callers
/// access fields via `Deref` (`guard.grpc.enabled`); the guard is
/// `!Send` — callers crossing an `.await` should use
/// [`ConfigHandle::snapshot`] instead.
pub struct ConfigLoadGuard(arc_swap::Guard<Arc<ProxyConfig>>);

impl Deref for ConfigLoadGuard {
    type Target = ProxyConfig;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

/// Error returned when a config mutation fails validation.
///
/// Generic over the mutator's error type so callers do not have to
/// encode typed validation failures into opaque strings. The API
/// handler passes its own [`ValidationError`](crate::feature_flags::ValidationError)
/// here directly without a prefix-encoding dance.
#[derive(Debug, thiserror::Error)]
pub enum ConfigUpdateError<E: std::fmt::Debug + std::fmt::Display> {
    #[error("validation failed: {0}")]
    Validation(E),
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
    /// boundary because it is `!Send`. Callers needing a
    /// `Send + 'static` value should use [`ConfigHandle::snapshot`]
    /// instead.
    #[inline]
    #[must_use]
    pub fn load(&self) -> ConfigLoadGuard {
        ConfigLoadGuard(self.inner.load())
    }

    /// Full `Arc` clone of the current config. Cheap, `Send + 'static`.
    #[inline]
    #[must_use]
    pub fn snapshot(&self) -> Arc<ProxyConfig> {
        self.inner.load_full()
    }

    /// Atomically mutate the config through a validator closure.
    ///
    /// The mutator receives a mutable clone of the live config. If it
    /// returns `Ok(())`, the clone is swapped into place and returned to
    /// the caller. If it returns `Err(E)`, the live config is untouched
    /// and the typed error is propagated as
    /// [`ConfigUpdateError::Validation`].
    ///
    /// Writers are serialized via an internal mutex so two concurrent
    /// callers cannot each base on the same snapshot and overwrite each
    /// other.
    pub fn update<F, E>(&self, mutator: F) -> Result<Arc<ProxyConfig>, ConfigUpdateError<E>>
    where
        F: FnOnce(&mut ProxyConfig) -> Result<(), E>,
        E: std::fmt::Debug + std::fmt::Display,
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

    #[must_use]
    pub fn config_path(&self) -> Option<&PathBuf> {
        self.config_path.as_ref()
    }

    #[must_use]
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
        assert_eq!(
            snap.max_request_size_bytes,
            test_config().max_request_size_bytes
        );
    }

    #[test]
    fn update_applies_mutation() {
        let handle = ConfigHandle::new(test_config(), None, None);
        let result = handle.update::<_, String>(|c| {
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
        let result = handle.update::<_, String>(|c| {
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
                    h.update::<_, String>(|c| {
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

    #[test]
    fn concurrent_mixed_results_no_partial_state() {
        // Half the writers fail validation. The live state must reflect
        // exactly the successful writes and no intermediate value.
        use std::sync::atomic::{AtomicU64, Ordering};
        let handle = Arc::new(ConfigHandle::new(test_config(), None, None));
        let successes = Arc::new(AtomicU64::new(0));
        let n = 200usize;
        let threads: Vec<_> = (0..n)
            .map(|i| {
                let h = handle.clone();
                let s = successes.clone();
                thread::spawn(move || {
                    // Even tasks succeed, odd tasks fail validation.
                    let result = h.update::<_, String>(|c| {
                        c.max_request_size_bytes += 1;
                        if i % 2 == 0 {
                            Ok(())
                        } else {
                            Err("intentional failure".to_string())
                        }
                    });
                    if result.is_ok() {
                        s.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let success_count = successes.load(Ordering::Relaxed);
        let expected = test_config().max_request_size_bytes + success_count;
        assert_eq!(handle.snapshot().max_request_size_bytes, expected);
        assert_eq!(success_count, (n / 2) as u64);
    }
}
