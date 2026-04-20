//! LLM-as-a-Judge analysis tier (issue #43).
//!
//! This module provides a pluggable backend for invoking a dedicated
//! language model as a third security detector alongside the regex
//! and DeBERTa ensembles. See `docs/architecture/LLM_JUDGE.md` for the
//! full specification.
//!
//! # Crate boundary
//!
//! This module is scoped to **pure LLM IO and classification**:
//!
//! - The [`JudgeBackend`] trait, request/response types, and
//!   backend implementations (vLLM now; OpenAI and Anthropic in
//!   follow-up phases).
//! - The hardened system prompt and JSON-schema parser.
//! - Verdict-to-[`SecurityFinding`] conversion for ensemble
//!   integration.
//!
//! Worker lifecycle, channel plumbing, storage persistence, and
//! metrics live in the `llmtrace-proxy` crate.

use async_trait::async_trait;
use llmtrace_core::{JudgeMode, JudgeVerdict, SecurityFinding, TenantId};
use uuid::Uuid;

mod anthropic;
mod finding;
mod openai;
mod openai_compat;
mod parser;
mod prompt;
mod retry;
mod truncate_helper;
mod vllm;

pub use anthropic::{
    AnthropicJudgeBackend, AnthropicJudgeOptions, API_KEY_ENV as ANTHROPIC_API_KEY_ENV,
};
pub use finding::{severity_from_score, verdict_to_finding, JUDGE_FINDING_TYPE};
pub use openai::{OpenAIJudgeBackend, OpenAiJudgeOptions, API_KEY_ENV as OPENAI_API_KEY_ENV};
pub use parser::{parse_verdict_json, RawVerdict};
pub use prompt::{build_system_prompt, build_user_message_json, DEFAULT_SYSTEM_PROMPT};
pub use vllm::{VllmJudgeBackend, VllmJudgeOptions};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors emitted by [`JudgeBackend`] implementations. The judge worker
/// translates these into fail-open metric increments -- a judge failure
/// never changes the outcome of a request versus the no-judge baseline.
#[derive(Debug, thiserror::Error)]
pub enum JudgeError {
    #[error("backend HTTP timeout after {elapsed_ms}ms")]
    Timeout { elapsed_ms: u64 },

    #[error("backend returned HTTP {status}: {message}")]
    BackendError {
        status: u16,
        message: String,
        /// Issue #75: parsed `Retry-After` hint in milliseconds, when
        /// the backend returned one (e.g., a 429 with
        /// `Retry-After: 3`). The retry wrapper uses this to override
        /// the computed exponential backoff, capped at the remaining
        /// total deadline.
        retry_after_ms: Option<u64>,
    },

    #[error("failed to parse verdict: {0}")]
    ParseError(String),

    #[error("backend disabled or misconfigured: {0}")]
    Misconfigured(String),

    #[error("transport error: {0}")]
    Transport(String),
}

impl JudgeError {
    /// When this error carries a server-supplied `Retry-After` hint
    /// (currently only `BackendError`), return it in milliseconds.
    /// Used by [`retry::with_retry`](super::retry::with_retry) to
    /// honor provider guidance instead of the computed backoff.
    #[must_use]
    pub fn retry_after_ms(&self) -> Option<u64> {
        match self {
            JudgeError::BackendError { retry_after_ms, .. } => *retry_after_ms,
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Request / response shapes for the backend call (no channels here -- the
// action-router oneshot wrapper lives in llmtrace-proxy).
// ---------------------------------------------------------------------------

/// A single candidate for judge analysis.
///
/// Carries only data the backend needs to classify the text plus
/// enough trace/tenant context to stamp the returned verdict. The
/// action-router [`JudgeRequest`](https://docs.rs/llmtrace_proxy) wraps
/// this structure with the oneshot response channel for the inline
/// path.
#[derive(Debug, Clone)]
pub struct JudgeCandidate {
    pub trace_id: Uuid,
    pub tenant_id: TenantId,
    pub model_name: String,
    pub analysis_text: String,
    pub prior_findings: Vec<SecurityFinding>,
    pub mode: JudgeMode,
}

impl JudgeCandidate {
    /// Compute the highest prior `security_score`-equivalent from the
    /// prior findings vector so the worker can apply the
    /// `min_score_threshold` gate without reaching into internal
    /// finding fields.
    ///
    /// Uses the canonical `severity_to_score` mapping from
    /// `llmtrace-core` so the min-score-threshold semantics match the
    /// judge's own severity bands (issue #76).
    #[must_use]
    pub fn peak_prior_severity_score(&self) -> u8 {
        self.prior_findings
            .iter()
            .map(|f| llmtrace_core::severity_to_score(&f.severity))
            .max()
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Backend trait
// ---------------------------------------------------------------------------

/// Abstraction over a judge backend. Implementations are responsible
/// for HTTP transport, prompt formatting, response parsing, and
/// returning a fully-populated [`JudgeVerdict`].
#[async_trait]
pub trait JudgeBackend: Send + Sync {
    /// Produce a verdict for `candidate`. Implementations must set
    /// `verdict.mode` to `candidate.mode` and `verdict.trace_id /
    /// tenant_id` to mirror the candidate.
    async fn judge(&self, candidate: &JudgeCandidate) -> Result<JudgeVerdict, JudgeError>;

    /// Human-readable backend identifier used as a metric label.
    fn name(&self) -> &'static str;

    /// Lightweight health probe the worker can issue on startup or
    /// after repeated failures. Implementations should issue a
    /// minimal request (e.g. a GET against a `/v1/models` endpoint)
    /// and return `Ok(())` when the backend is reachable.
    async fn health_check(&self) -> Result<(), JudgeError>;
}
