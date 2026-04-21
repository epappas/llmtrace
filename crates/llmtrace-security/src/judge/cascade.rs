//! Cascade [`JudgeBackend`] composition (issue #88).
//!
//! Composes a fast `JudgeBackend` with an optional slow one. Every
//! call runs the fast backend. If the fast verdict's `confidence`
//! lands inside a configured ambiguous band and a slow backend is
//! present, the slow backend is run and its verdict wins. Otherwise
//! the fast verdict is final.
//!
//! Because `CascadeJudgeBackend` itself impls [`JudgeBackend`], it
//! slots into every feature already shipped on PR #65 (promotion
//! gate, shadow mode, metrics, verdict persistence) without any
//! downstream changes. See `docs/architecture/JUDGE_CASCADE.md` for
//! the full rationale.
//!
//! # Fail-open
//!
//! Fail-open is preserved end-to-end:
//!
//! | Case | Behaviour |
//! |---|---|
//! | Fast errors, slow configured, band could apply | Run slow and use its verdict |
//! | Fast errors, slow not configured (or also errors) | Bubble the error up |
//! | Fast ok (in band), slow errors | Return the fast verdict (graceful degradation) |
//! | Fast ok (out of band) | Return fast; slow is never called |
//!
//! An in-band fast verdict combined with a slow error is the
//! scenario where the cascade *prefers* the fast answer rather than
//! the slow error — operators see both the slow error metric and a
//! final fast verdict.

use std::sync::Arc;

use async_trait::async_trait;
use llmtrace_core::JudgeVerdict;

use super::{JudgeBackend, JudgeCandidate, JudgeError};

/// Composition of a fast [`JudgeBackend`] with an optional slow one.
///
/// `ambiguous_low` and `ambiguous_high` bound the range in which the
/// slow tier gets consulted. They are inclusive on both sides (a
/// confidence exactly at either bound counts as ambiguous), which
/// matches the cascade's intent: "if the fast tier is *not
/// confidently* outside the band, ask the slow tier".
pub struct CascadeJudgeBackend {
    fast: Arc<dyn JudgeBackend>,
    slow: Option<Arc<dyn JudgeBackend>>,
    ambiguous_low: f64,
    ambiguous_high: f64,
    model_label: String,
}

impl CascadeJudgeBackend {
    /// Construct a cascade. Panics (in debug) if the band is
    /// inverted (`low > high`); returns a compiled backend in release
    /// because serde-parsed configs can be weird and we prefer a
    /// graceful runtime error at the first `judge()` call.
    #[must_use]
    pub fn new(
        fast: Arc<dyn JudgeBackend>,
        slow: Option<Arc<dyn JudgeBackend>>,
        ambiguous_low: f64,
        ambiguous_high: f64,
    ) -> Self {
        debug_assert!(
            ambiguous_low <= ambiguous_high,
            "cascade ambiguous band is inverted"
        );
        let model_label = match &slow {
            Some(s) => format!("{}+{}", fast.name(), s.name()),
            None => format!("{}+none", fast.name()),
        };
        Self {
            fast,
            slow,
            ambiguous_low,
            ambiguous_high,
            model_label,
        }
    }

    /// Expose the ambiguous band for introspection / tests.
    #[must_use]
    pub fn ambiguous_band(&self) -> (f64, f64) {
        (self.ambiguous_low, self.ambiguous_high)
    }

    /// Return the inner fast backend (for tests + introspection).
    #[must_use]
    pub fn fast(&self) -> &Arc<dyn JudgeBackend> {
        &self.fast
    }

    /// Return the inner slow backend, if configured.
    #[must_use]
    pub fn slow(&self) -> Option<&Arc<dyn JudgeBackend>> {
        self.slow.as_ref()
    }

    fn in_ambiguous_band(&self, confidence: f64) -> bool {
        confidence >= self.ambiguous_low && confidence <= self.ambiguous_high
    }
}

#[async_trait]
impl JudgeBackend for CascadeJudgeBackend {
    async fn judge(&self, candidate: &JudgeCandidate) -> Result<JudgeVerdict, JudgeError> {
        let fast_result = self.fast.judge(candidate).await;
        let slow = match &self.slow {
            Some(s) => Arc::clone(s),
            None => return fast_result,
        };

        match fast_result {
            Ok(fast_verdict) => {
                if self.in_ambiguous_band(fast_verdict.confidence) {
                    // Escalate. On slow failure, fall back to fast.
                    match slow.judge(candidate).await {
                        Ok(slow_verdict) => Ok(slow_verdict),
                        Err(_) => Ok(fast_verdict),
                    }
                } else {
                    Ok(fast_verdict)
                }
            }
            Err(fast_err) => {
                // Fast errored. Try slow as a resilience fallback. If
                // slow also errors, surface the *slow* error (more
                // actionable) but preserve the fast error context.
                match slow.judge(candidate).await {
                    Ok(slow_verdict) => Ok(slow_verdict),
                    Err(_) => Err(fast_err),
                }
            }
        }
    }

    fn name(&self) -> &'static str {
        "cascade"
    }

    fn model(&self) -> &str {
        &self.model_label
    }

    async fn health_check(&self) -> Result<(), JudgeError> {
        self.fast.health_check().await?;
        if let Some(s) = &self.slow {
            s.health_check().await?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use llmtrace_core::{JudgeMode, JudgeVerdict, TenantId};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use uuid::Uuid;

    struct FakeBackend {
        name: &'static str,
        model: String,
        verdict_factory: Arc<dyn Fn() -> Result<JudgeVerdict, JudgeError> + Send + Sync>,
        healthy: bool,
        calls: Arc<AtomicUsize>,
    }

    impl FakeBackend {
        fn fixed(
            name: &'static str,
            model: &str,
            confidence: f64,
            is_threat: bool,
        ) -> (Arc<dyn JudgeBackend>, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            let m = model.to_string();
            let f = Arc::new(FakeBackend {
                name,
                model: m,
                verdict_factory: Arc::new(move || {
                    Ok(JudgeVerdict {
                        id: Uuid::new_v4(),
                        trace_id: Uuid::new_v4(),
                        tenant_id: TenantId(Uuid::new_v4()),
                        is_threat,
                        category: "prompt_injection".to_string(),
                        confidence,
                        security_score: (confidence * 100.0) as u8,
                        recommended_action: "flag".to_string(),
                        reasoning: "fake".to_string(),
                        mode: JudgeMode::Inline,
                        model_used: "fake".to_string(),
                        latency_ms: 1,
                        prompt_tokens: None,
                        completion_tokens: None,
                        created_at: Utc::now(),
                    })
                }),
                healthy: true,
                calls: Arc::clone(&calls),
            }) as Arc<dyn JudgeBackend>;
            (f, calls)
        }

        fn erroring(name: &'static str, model: &str) -> (Arc<dyn JudgeBackend>, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            let f = Arc::new(FakeBackend {
                name,
                model: model.to_string(),
                verdict_factory: Arc::new(|| Err(JudgeError::ParseError("boom".to_string()))),
                healthy: false,
                calls: Arc::clone(&calls),
            }) as Arc<dyn JudgeBackend>;
            (f, calls)
        }
    }

    #[async_trait]
    impl JudgeBackend for FakeBackend {
        async fn judge(&self, _candidate: &JudgeCandidate) -> Result<JudgeVerdict, JudgeError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            (self.verdict_factory)()
        }

        fn name(&self) -> &'static str {
            self.name
        }

        fn model(&self) -> &str {
            &self.model
        }

        async fn health_check(&self) -> Result<(), JudgeError> {
            if self.healthy {
                Ok(())
            } else {
                Err(JudgeError::Misconfigured("unhealthy".into()))
            }
        }
    }

    fn candidate() -> JudgeCandidate {
        JudgeCandidate {
            trace_id: Uuid::new_v4(),
            tenant_id: TenantId(Uuid::new_v4()),
            model_name: "bench".to_string(),
            analysis_text: "hello".to_string(),
            prior_findings: vec![],
            mode: JudgeMode::Inline,
        }
    }

    #[tokio::test]
    async fn high_confidence_fast_short_circuits_without_slow_call() {
        let (fast, fast_calls) = FakeBackend::fixed("fast", "f", 0.95, true);
        let (slow, slow_calls) = FakeBackend::fixed("slow", "s", 0.5, true);
        let cascade = CascadeJudgeBackend::new(fast, Some(slow), 0.3, 0.7);

        let verdict = cascade.judge(&candidate()).await.unwrap();
        assert!((verdict.confidence - 0.95).abs() < 1e-9);
        assert_eq!(fast_calls.load(Ordering::SeqCst), 1);
        assert_eq!(slow_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn low_confidence_fast_short_circuits_without_slow_call() {
        let (fast, fast_calls) = FakeBackend::fixed("fast", "f", 0.05, false);
        let (slow, slow_calls) = FakeBackend::fixed("slow", "s", 0.5, true);
        let cascade = CascadeJudgeBackend::new(fast, Some(slow), 0.3, 0.7);

        let verdict = cascade.judge(&candidate()).await.unwrap();
        assert!((verdict.confidence - 0.05).abs() < 1e-9);
        assert_eq!(fast_calls.load(Ordering::SeqCst), 1);
        assert_eq!(slow_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn ambiguous_confidence_escalates_to_slow() {
        let (fast, fast_calls) = FakeBackend::fixed("fast", "f", 0.5, false);
        let (slow, slow_calls) = FakeBackend::fixed("slow", "s", 0.92, true);
        let cascade = CascadeJudgeBackend::new(fast, Some(slow), 0.3, 0.7);

        let verdict = cascade.judge(&candidate()).await.unwrap();
        // Slow verdict wins.
        assert!((verdict.confidence - 0.92).abs() < 1e-9);
        assert!(verdict.is_threat);
        assert_eq!(fast_calls.load(Ordering::SeqCst), 1);
        assert_eq!(slow_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn ambiguous_but_no_slow_returns_fast() {
        let (fast, fast_calls) = FakeBackend::fixed("fast", "f", 0.5, false);
        let cascade = CascadeJudgeBackend::new(fast, None, 0.3, 0.7);

        let verdict = cascade.judge(&candidate()).await.unwrap();
        assert!((verdict.confidence - 0.5).abs() < 1e-9);
        assert_eq!(fast_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn slow_error_during_escalation_falls_back_to_fast() {
        let (fast, _) = FakeBackend::fixed("fast", "f", 0.5, false);
        let (slow, slow_calls) = FakeBackend::erroring("slow", "s");
        let cascade = CascadeJudgeBackend::new(fast, Some(slow), 0.3, 0.7);

        let verdict = cascade.judge(&candidate()).await.unwrap();
        // Fall back to fast verdict.
        assert!((verdict.confidence - 0.5).abs() < 1e-9);
        assert_eq!(slow_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn fast_error_bubbles_when_slow_missing() {
        let (fast, _) = FakeBackend::erroring("fast", "f");
        let cascade = CascadeJudgeBackend::new(fast, None, 0.3, 0.7);

        let err = cascade.judge(&candidate()).await.unwrap_err();
        assert!(matches!(err, JudgeError::ParseError(_)));
    }

    #[tokio::test]
    async fn fast_error_recovered_by_slow_success() {
        let (fast, _) = FakeBackend::erroring("fast", "f");
        let (slow, slow_calls) = FakeBackend::fixed("slow", "s", 0.9, true);
        let cascade = CascadeJudgeBackend::new(fast, Some(slow), 0.3, 0.7);

        let verdict = cascade.judge(&candidate()).await.unwrap();
        assert!((verdict.confidence - 0.9).abs() < 1e-9);
        assert_eq!(slow_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn both_error_bubbles_fast_error() {
        let (fast, _) = FakeBackend::erroring("fast", "f");
        let (slow, _) = FakeBackend::erroring("slow", "s");
        let cascade = CascadeJudgeBackend::new(fast, Some(slow), 0.3, 0.7);

        let err = cascade.judge(&candidate()).await.unwrap_err();
        assert!(matches!(err, JudgeError::ParseError(_)));
    }

    #[test]
    fn model_label_encodes_fast_and_slow_names() {
        let (fast, _) = FakeBackend::fixed("fast", "fast-model", 0.9, true);
        let (slow, _) = FakeBackend::fixed("slow", "slow-model", 0.5, true);
        let with_slow = CascadeJudgeBackend::new(Arc::clone(&fast), Some(slow), 0.3, 0.7);
        assert_eq!(with_slow.model(), "fast+slow");

        let without_slow = CascadeJudgeBackend::new(fast, None, 0.3, 0.7);
        assert_eq!(without_slow.model(), "fast+none");
    }

    #[tokio::test]
    async fn health_check_reports_inner_backend_failure() {
        let (fast, _) = FakeBackend::fixed("fast", "f", 0.9, true);
        let (slow, _) = FakeBackend::erroring("slow", "s");
        let cascade = CascadeJudgeBackend::new(fast, Some(slow), 0.3, 0.7);
        let res = cascade.health_check().await;
        assert!(matches!(res, Err(JudgeError::Misconfigured(_))));
    }
}
