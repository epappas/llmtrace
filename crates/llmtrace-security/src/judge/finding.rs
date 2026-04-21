//! Judge verdict -> SecurityFinding conversion.
//!
//! The canonical implementation lives in `llmtrace-core` so both this
//! crate and `llmtrace-proxy::action_router` use one source of truth
//! for `JUDGE_FINDING_TYPE`, severity bands, and metadata stamping
//! (issue #76). This module exists as a thin re-export to keep the
//! existing `llmtrace_security::judge::{JUDGE_FINDING_TYPE,
//! severity_from_score, verdict_to_finding}` import path stable for
//! downstream callers.

pub use llmtrace_core::{severity_from_score, verdict_to_finding, JUDGE_FINDING_TYPE};
