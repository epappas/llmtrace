//! Runtime handle for toggling ensemble feature flags at runtime.
//!
//! This module is always compiled (including when the `ml` feature is
//! disabled) so the proxy can expose a uniform feature-flag admin API
//! regardless of whether ML is active. On the regex-only fallback path,
//! the handle is constructed via [`EnsembleRuntimeHandle::inert`] and
//! writes round-trip through standalone atomics without being observed
//! by any analyzer — matching the "store-only" semantics agreed for the
//! `llm_judge_enabled` flag in issue #42.
//!
//! The `ml`-gated [`crate::ensemble::EnsembleSecurityAnalyzer`] exposes
//! [`crate::ensemble::EnsembleSecurityAnalyzer::runtime_handle`] which
//! returns a handle whose atomics are shared with the live ensemble; in
//! that case writes immediately take effect on the next request without
//! rebuilding the analyzer.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::thresholds::{OperatingPoint, ResolvedThresholds};

/// Runtime handle for toggling ensemble feature flags from outside the
/// crate without holding a direct reference to the ensemble's trait
/// object.
#[derive(Clone)]
pub struct EnsembleRuntimeHandle {
    pub(crate) ml_enabled: Arc<AtomicBool>,
    pub(crate) injecguard_enabled: Arc<AtomicBool>,
    pub(crate) piguard_enabled: Arc<AtomicBool>,
    pub(crate) over_defence_enabled: Arc<AtomicBool>,
    pub(crate) thresholds: Arc<ArcSwap<ResolvedThresholds>>,
    pub(crate) jailbreak_enabled: Arc<AtomicBool>,
}

impl EnsembleRuntimeHandle {
    /// Construct an inert handle for code paths that do not build an
    /// actual ensemble. All setters still succeed (writing to standalone
    /// atomics), but nothing reads them.
    #[must_use]
    pub fn inert() -> Self {
        Self {
            ml_enabled: Arc::new(AtomicBool::new(true)),
            injecguard_enabled: Arc::new(AtomicBool::new(true)),
            piguard_enabled: Arc::new(AtomicBool::new(true)),
            over_defence_enabled: Arc::new(AtomicBool::new(false)),
            thresholds: Arc::new(ArcSwap::from_pointee(ResolvedThresholds::default())),
            jailbreak_enabled: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn set_ml(&self, enabled: bool) {
        self.ml_enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn set_injecguard(&self, enabled: bool) {
        self.injecguard_enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn set_piguard(&self, enabled: bool) {
        self.piguard_enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn set_over_defence(&self, enabled: bool) {
        self.over_defence_enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn set_jailbreak(&self, enabled: bool) {
        self.jailbreak_enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn set_operating_point(&self, point: OperatingPoint) {
        self.thresholds
            .store(Arc::new(ResolvedThresholds::from_operating_point(
                &point, None,
            )));
    }

    /// Returns the shared jailbreak flag. Used by the proxy to construct
    /// a second `RegexSecurityAnalyzer` that reads the same atomic as
    /// the ensemble's inner regex.
    #[must_use]
    pub fn jailbreak_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.jailbreak_enabled)
    }

    /// Read the live ml-enabled state. Test helper.
    #[must_use]
    pub fn ml(&self) -> bool {
        self.ml_enabled.load(Ordering::Relaxed)
    }

    /// Read the live injecguard-enabled state. Test helper.
    #[must_use]
    pub fn injecguard(&self) -> bool {
        self.injecguard_enabled.load(Ordering::Relaxed)
    }

    /// Read the live piguard-enabled state. Test helper.
    #[must_use]
    pub fn piguard(&self) -> bool {
        self.piguard_enabled.load(Ordering::Relaxed)
    }

    /// Read the live over-defence state. Test helper.
    #[must_use]
    pub fn over_defence(&self) -> bool {
        self.over_defence_enabled.load(Ordering::Relaxed)
    }

    /// Read the live jailbreak-enabled state. Test helper.
    #[must_use]
    pub fn jailbreak(&self) -> bool {
        self.jailbreak_enabled.load(Ordering::Relaxed)
    }
}
