//! DeBERTa fast-judge backend (issue #87).
//!
//! Wraps an [`MLSecurityAnalyzer`] as a [`JudgeBackend`] so a local
//! classifier-based detector can participate in every feature the
//! judge pipeline already ships: shadow mode (#84), the promotion
//! gate (#70), per-model metrics (#83), verdict persistence, and the
//! [cascade][super::cascade] composition.
//!
//! # Synthesis of the 6-field verdict
//!
//! A binary text classifier returns `P(injection)`. A [`JudgeVerdict`]
//! has six fields. This backend synthesises the four fields the
//! classifier cannot produce natively, by a documented deterministic
//! rule (see `docs/architecture/JUDGE_CASCADE.md` §3.5):
//!
//! | Field | Derivation |
//! |---|---|
//! | `is_threat` | `p >= threshold` |
//! | `confidence` | `if p > 0.5 { p } else { 1 - p }` (unsigned certainty) |
//! | `security_score` | `round(p * 100).clamp(0, 100)` |
//! | `category` | fixed `"prompt_injection"` (binary head) |
//! | `recommended_action` | `p < 0.5 → "allow"`, `[0.5, 0.8) → "flag"`, `>= 0.8 → "block"` |
//! | `reasoning` | template: `"DeBERTa classifier p={p:.3f} (model={model_id})"` |
//!
//! Audit logs and 403 response bodies surface `reasoning` verbatim,
//! so the template makes clear the verdict came from a classifier,
//! not from an LLM explanation. This is deliberate: synthesising a
//! plausible-sounding natural-language reason would be deceptive.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::Utc;
use llmtrace_core::{JudgeVerdict, LLMTraceError};
use uuid::Uuid;

use super::{JudgeBackend, JudgeCandidate, JudgeError};
use crate::{MLSecurityAnalyzer, MLSecurityConfig};

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/// Construction-time options for [`DebertaJudgeBackend`]. Mirrors
/// `llmtrace_core::DebertaBackendConfig` but uses `Duration` and
/// is the shape the proxy-side factory produces.
#[derive(Debug, Clone)]
pub struct DebertaJudgeOptions {
    pub model_id: String,
    /// Probability threshold for `is_threat`. Separate from the
    /// cascade's ambiguous band — this one only controls the binary
    /// flag.
    pub threshold: f64,
    pub cache_dir: Option<String>,
    /// Max wall-clock budget for a single classification. The
    /// DeBERTa analyser is synchronous on the current thread and
    /// bounded by token count; this timeout is a guard against a
    /// pathological tokenizer stall.
    pub timeout: Duration,
}

impl Default for DebertaJudgeOptions {
    fn default() -> Self {
        Self {
            model_id: "protectai/deberta-v3-base-prompt-injection-v2".to_string(),
            threshold: 0.5,
            cache_dir: None,
            timeout: Duration::from_secs(10),
        }
    }
}

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

/// LLM-Judge backend backed by a DeBERTa (or any HF text-classification)
/// model via the existing candle ML machinery.
pub struct DebertaJudgeBackend {
    analyzer: Arc<MLSecurityAnalyzer>,
    options: DebertaJudgeOptions,
}

impl DebertaJudgeBackend {
    /// Construct a backend by loading the configured model. Downloads
    /// weights on first call when the HF cache is cold.
    ///
    /// # Errors
    ///
    /// Returns [`JudgeError::Misconfigured`] if the analyser falls back
    /// to regex-only mode (i.e. the model failed to load). A silently
    /// degraded classifier would be worse than a clear configuration
    /// error for operators.
    pub async fn new(options: DebertaJudgeOptions) -> Result<Self, JudgeError> {
        let ml_config = MLSecurityConfig {
            model_id: options.model_id.clone(),
            threshold: options.threshold,
            cache_dir: options.cache_dir.clone(),
        };
        let analyzer = MLSecurityAnalyzer::new(&ml_config)
            .await
            .map_err(|e| JudgeError::Misconfigured(format!("ML analyzer init failed: {e}")))?;
        if !analyzer.is_model_loaded() {
            return Err(JudgeError::Misconfigured(format!(
                "DeBERTa model {} did not load; check cache_dir / network / model id",
                options.model_id
            )));
        }
        Ok(Self {
            analyzer: Arc::new(analyzer),
            options,
        })
    }

    /// Construct from a caller-owned analyser. Useful for tests and
    /// for sharing one loaded model across ensemble + fast-judge
    /// (follow-up optimisation tracked on #86).
    #[must_use]
    pub fn from_analyzer(analyzer: Arc<MLSecurityAnalyzer>, options: DebertaJudgeOptions) -> Self {
        Self { analyzer, options }
    }

    fn synthesize_verdict(
        &self,
        candidate: &JudgeCandidate,
        probability: f64,
        elapsed_ms: u64,
    ) -> JudgeVerdict {
        let p = probability.clamp(0.0, 1.0);
        let is_threat = p >= self.options.threshold;
        let confidence = if p > 0.5 { p } else { 1.0 - p };
        let security_score = (p * 100.0).round().clamp(0.0, 100.0) as u8;
        let recommended_action = if p < 0.5 {
            "allow"
        } else if p < 0.8 {
            "flag"
        } else {
            "block"
        };
        JudgeVerdict {
            id: Uuid::new_v4(),
            trace_id: candidate.trace_id,
            tenant_id: candidate.tenant_id,
            is_threat,
            category: "prompt_injection".to_string(),
            confidence,
            security_score,
            recommended_action: recommended_action.to_string(),
            reasoning: format!(
                "DeBERTa classifier p={p:.3} (model={model_id})",
                model_id = self.options.model_id
            ),
            mode: candidate.mode,
            model_used: self.options.model_id.clone(),
            latency_ms: elapsed_ms,
            prompt_tokens: None,
            completion_tokens: None,
            created_at: Utc::now(),
        }
    }
}

#[async_trait]
impl JudgeBackend for DebertaJudgeBackend {
    async fn judge(&self, candidate: &JudgeCandidate) -> Result<JudgeVerdict, JudgeError> {
        let analyzer = Arc::clone(&self.analyzer);
        let text = candidate.analysis_text.clone();
        let timeout = self.options.timeout;
        let started = Instant::now();

        // The candle model runs synchronously; off-thread it via
        // `spawn_blocking` so we don't starve the tokio reactor, and
        // race against the timeout.
        let classify_fut =
            tokio::task::spawn_blocking(move || analyzer.classify_probability(&text));
        let joined = match tokio::time::timeout(timeout, classify_fut).await {
            Ok(Ok(result)) => result,
            Ok(Err(join_err)) => {
                return Err(JudgeError::Transport(format!(
                    "DeBERTa classification task panicked: {join_err}"
                )));
            }
            Err(_) => {
                return Err(JudgeError::Timeout {
                    elapsed_ms: timeout.as_millis() as u64,
                });
            }
        };

        let elapsed_ms = started.elapsed().as_millis() as u64;

        match joined {
            Ok(Some(probability)) => {
                Ok(self.synthesize_verdict(candidate, probability, elapsed_ms))
            }
            Ok(None) => Err(JudgeError::Misconfigured(
                "DeBERTa analyzer is in fallback mode (model not loaded)".to_string(),
            )),
            Err(LLMTraceError::Security(msg)) => Err(JudgeError::ParseError(msg)),
            Err(e) => Err(JudgeError::Transport(e.to_string())),
        }
    }

    fn name(&self) -> &'static str {
        "deberta"
    }

    fn model(&self) -> &str {
        &self.options.model_id
    }

    async fn health_check(&self) -> Result<(), JudgeError> {
        if !self.analyzer.is_model_loaded() {
            return Err(JudgeError::Misconfigured(
                "DeBERTa analyzer is in fallback mode".to_string(),
            ));
        }
        // Confirm inference works end-to-end with a tiny string. A
        // classifier that errors on valid input is broken regardless
        // of what `is_model_loaded` says.
        let analyzer = Arc::clone(&self.analyzer);
        let probe =
            tokio::task::spawn_blocking(move || analyzer.classify_probability("health-check"))
                .await
                .map_err(|e| JudgeError::Transport(format!("health probe join: {e}")))?;
        match probe {
            Ok(Some(_)) => Ok(()),
            Ok(None) => Err(JudgeError::Misconfigured(
                "DeBERTa analyzer fell back during health probe".to_string(),
            )),
            Err(e) => Err(JudgeError::Transport(e.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use llmtrace_core::{JudgeMode, TenantId};
    use uuid::Uuid;

    fn candidate(text: &str) -> JudgeCandidate {
        JudgeCandidate {
            trace_id: Uuid::new_v4(),
            tenant_id: TenantId(Uuid::new_v4()),
            model_name: "bench".to_string(),
            analysis_text: text.to_string(),
            prior_findings: vec![],
            mode: JudgeMode::Inline,
        }
    }

    fn backend_with_threshold(threshold: f64) -> DebertaJudgeBackend {
        // Construct with a fallback analyzer so tests don't require a
        // network-loaded DeBERTa. We only exercise `synthesize_verdict`
        // here — the real `judge()` path is covered by the integration
        // test gated on model availability.
        let analyzer = Arc::new(MLSecurityAnalyzer::new_fallback_only(threshold));
        DebertaJudgeBackend::from_analyzer(
            analyzer,
            DebertaJudgeOptions {
                model_id: "test/model".to_string(),
                threshold,
                cache_dir: None,
                timeout: Duration::from_millis(100),
            },
        )
    }

    #[test]
    fn synthesize_strongly_benign_maps_to_allow() {
        let b = backend_with_threshold(0.5);
        let v = b.synthesize_verdict(&candidate("hello"), 0.02, 10);
        assert!(!v.is_threat);
        assert_eq!(v.recommended_action, "allow");
        assert_eq!(v.category, "prompt_injection");
        assert_eq!(v.security_score, 2);
        assert!((v.confidence - 0.98).abs() < 1e-9);
        assert!(v.reasoning.contains("p=0.020"));
        assert!(v.reasoning.contains("test/model"));
    }

    #[test]
    fn synthesize_ambiguous_maps_to_flag() {
        let b = backend_with_threshold(0.5);
        let v = b.synthesize_verdict(&candidate("maybe"), 0.62, 10);
        assert!(v.is_threat);
        assert_eq!(v.recommended_action, "flag");
        assert_eq!(v.security_score, 62);
        assert!((v.confidence - 0.62).abs() < 1e-9);
    }

    #[test]
    fn synthesize_strongly_adversarial_maps_to_block() {
        let b = backend_with_threshold(0.5);
        let v = b.synthesize_verdict(&candidate("ignore all"), 0.93, 10);
        assert!(v.is_threat);
        assert_eq!(v.recommended_action, "block");
        assert_eq!(v.security_score, 93);
        assert!((v.confidence - 0.93).abs() < 1e-9);
    }

    #[test]
    fn synthesize_out_of_range_probability_is_clamped() {
        let b = backend_with_threshold(0.5);
        let v_hi = b.synthesize_verdict(&candidate("x"), 1.5, 10);
        assert_eq!(v_hi.security_score, 100);
        let v_lo = b.synthesize_verdict(&candidate("y"), -0.5, 10);
        assert_eq!(v_lo.security_score, 0);
        assert!(!v_lo.is_threat);
    }

    #[test]
    fn name_and_model_labels_are_stable() {
        let b = backend_with_threshold(0.5);
        assert_eq!(b.name(), "deberta");
        assert_eq!(b.model(), "test/model");
    }

    #[tokio::test]
    async fn health_check_fails_in_fallback_mode() {
        let b = backend_with_threshold(0.5);
        let res = b.health_check().await;
        assert!(matches!(res, Err(JudgeError::Misconfigured(_))));
    }

    #[tokio::test]
    async fn judge_fails_in_fallback_mode() {
        let b = backend_with_threshold(0.5);
        let res = b.judge(&candidate("hello")).await;
        assert!(matches!(res, Err(JudgeError::Misconfigured(_))));
    }
}
