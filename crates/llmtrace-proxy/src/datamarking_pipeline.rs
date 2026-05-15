//! Proxy-side datamarking pipeline (IS-060 PR-2).
//!
//! Bridges the security crate's [`DatamarkingTransform`] (pure
//! per-zone transform) and the proxy's HTTP request body. The
//! pipeline:
//!
//! 1. Consumes the [`ZonePipelineOutcome`] produced by PR-1, so it
//!    operates on the post-strip, post-header-parse coordinate
//!    system (one shared coordinate system across heuristics,
//!    inline markers, and operator headers).
//! 2. Marks every `ZoneKind::Data` span in every message via
//!    [`DatamarkingTransform::apply`]. Instruction zones pass
//!    through unchanged.
//! 3. Splices the marked content back into the message strings,
//!    re-serialises the JSON body, and returns the rewritten bytes.
//!    Idempotent — re-running the pipeline on an already-marked body
//!    is a no-op because the marker codepoint is not Unicode
//!    whitespace.
//! 4. When `shadow_mode = true` the pipeline still computes the
//!    transform (so metrics and audit findings are real) but the
//!    proxy forwards the *un-marked* bytes upstream. The pipeline
//!    surface returns both so the caller picks.
//! 5. When the configured boundary-token system reminder was
//!    injected, the pipeline can also be asked to amend that reminder
//!    with a sentence describing the marker. We only do this in
//!    active mode — telling the model a marker exists when shadow
//!    mode is forwarding the original bytes would be a lie.
//!
//! Fail-open: every parse / re-serialise error is logged via the
//! `failures` field and the outcome reports `body_rewritten = false`
//! with the original bytes intact. This matches the rest of the
//! proxy's defence pipeline contract.

use std::ops::Range;

use llmtrace_core::DatamarkingConfig;
use llmtrace_security::datamarking::{DatamarkingTransform, MarkedZone};
use llmtrace_security::zone_detector::ZoneKind;

use crate::zone_pipeline::ZonePipelineOutcome;

/// Outcome of running the datamarking pipeline. Always returned, even
/// when datamarking is disabled — in that case the outcome reports a
/// passthrough.
#[derive(Debug, Default)]
pub struct DatamarkingPipelineOutcome {
    /// Rewritten body bytes when the transform actually rewrote
    /// something AND shadow_mode is OFF. In shadow mode this is
    /// equal to the input bytes — the proxy forwards the original
    /// because shadow_mode promises the upstream sees no
    /// modification.
    pub body: Vec<u8>,
    /// True iff the upstream-forwarded body differs from the input
    /// (i.e. active mode and at least one data zone had whitespace).
    pub body_rewritten: bool,
    /// Number of data zones we marked. Counted in shadow AND active
    /// mode so the metrics reflect the would-be load.
    pub zones_marked: u32,
    /// Cumulative byte delta across all marked zones (in bytes added
    /// by marker substitution). May be negative when the marker is
    /// narrower than the whitespace it replaced — typically positive
    /// because the default marker is 3 bytes in UTF-8 while ASCII
    /// whitespace is 1.
    pub byte_delta_total: i64,
    /// Number of zones whose first marker sample collided with the
    /// zone content and triggered a resample. Drives
    /// `llmtrace_spotlighting_marker_collision_total`.
    pub marker_collisions: u32,
    /// The byte ranges, per message, of every Data zone we marked.
    /// Used by the audit-trail `spotlighting_applied` finding.
    pub zone_byte_ranges_per_message: Vec<Vec<Range<usize>>>,
    /// The marker codepoint actually used per message. `None` for
    /// messages with no Data zones. When more than one marker fired
    /// inside one message (collision in zone 1, no collision in zone
    /// 2, etc.) the *first* marker is recorded for telemetry
    /// simplicity.
    pub marker_per_message: Vec<Option<char>>,
    /// `true` when shadow_mode was on for this invocation. Recorded
    /// here so the proxy can stamp the audit finding without
    /// re-reading the config.
    pub shadow_mode: bool,
    /// Failure reasons collected during the pipeline. Empty in the
    /// happy path.
    pub failures: Vec<&'static str>,
}

/// Run the datamarking pipeline against the proxy's current request
/// body. When `cfg.enabled = false` this is a pure no-op — the
/// outcome reports passthrough and no work is done.
///
/// `body_bytes` is the body the upstream will receive if datamarking
/// does nothing; the caller must pass the post-boundary, post-zone
/// body (i.e. the same `forward_body` that would have been used
/// otherwise).
pub fn run(
    body_bytes: &[u8],
    zone_outcome: &ZonePipelineOutcome,
    cfg: &DatamarkingConfig,
) -> DatamarkingPipelineOutcome {
    if !cfg.enabled {
        return DatamarkingPipelineOutcome {
            body: body_bytes.to_vec(),
            body_rewritten: false,
            shadow_mode: cfg.shadow_mode,
            ..Default::default()
        };
    }

    if zone_outcome.zones_per_message.is_empty() {
        // Zone pipeline did not produce any zones (zone detection
        // disabled or the body could not be parsed). Datamarking
        // needs zone metadata; nothing to do.
        return DatamarkingPipelineOutcome {
            body: body_bytes.to_vec(),
            body_rewritten: false,
            shadow_mode: cfg.shadow_mode,
            failures: vec!["no_zones_available"],
            ..Default::default()
        };
    }

    let transform = DatamarkingTransform::new(cfg.clone());
    let marked_per_message = mark_each_message(&transform, zone_outcome);

    let mut zones_marked = 0u32;
    let mut byte_delta_total = 0i64;
    let mut marker_collisions = 0u32;
    let mut zone_byte_ranges_per_message: Vec<Vec<Range<usize>>> =
        Vec::with_capacity(marked_per_message.len());
    let mut marker_per_message: Vec<Option<char>> = Vec::with_capacity(marked_per_message.len());
    for marked in &marked_per_message {
        let mut ranges = Vec::new();
        let mut first_marker: Option<char> = None;
        for mz in marked {
            if mz.kind == ZoneKind::Data && !mz.content.is_empty() {
                zones_marked += 1;
                byte_delta_total += mz.byte_delta;
                if mz.marker_resampled {
                    marker_collisions += 1;
                }
                if first_marker.is_none() {
                    first_marker = mz.marker;
                }
                ranges.push(mz.byte_range.clone());
            }
        }
        zone_byte_ranges_per_message.push(ranges);
        marker_per_message.push(first_marker);
    }

    // Compute the substituted body — needed in active mode, and in
    // shadow mode we still compute it so the metrics path is honest
    // about cost. We just do not forward it.
    // Compute the reminder addendum only when datamarking is active
    // (not shadow). Shadow mode must not tell the model about a
    // transform the bytes do not carry. Pick the first non-None marker
    // across messages for the addendum interpolation.
    let addendum_text = if cfg.shadow_mode {
        None
    } else {
        marked_per_message
            .iter()
            .flat_map(|zs| zs.iter())
            .find_map(|mz| mz.marker)
            .map(|m| transform.reminder_addendum(m))
    };
    let rewritten_body = match build_substituted_body(
        body_bytes,
        zone_outcome,
        &marked_per_message,
        addendum_text.as_deref(),
    ) {
        Ok(b) => b,
        Err(reason) => {
            return DatamarkingPipelineOutcome {
                body: body_bytes.to_vec(),
                body_rewritten: false,
                zones_marked,
                byte_delta_total,
                marker_collisions,
                zone_byte_ranges_per_message,
                marker_per_message,
                shadow_mode: cfg.shadow_mode,
                failures: vec![reason],
            };
        }
    };

    let forward_body = if cfg.shadow_mode {
        body_bytes.to_vec()
    } else {
        rewritten_body.clone()
    };
    let body_rewritten = !cfg.shadow_mode && forward_body != body_bytes;

    DatamarkingPipelineOutcome {
        body: forward_body,
        body_rewritten,
        zones_marked,
        byte_delta_total,
        marker_collisions,
        zone_byte_ranges_per_message,
        marker_per_message,
        shadow_mode: cfg.shadow_mode,
        failures: Vec::new(),
    }
}

/// Apply the transform to each message's zones in turn. The output
/// `Vec<Vec<MarkedZone>>` mirrors `zone_outcome.zones_per_message`
/// exactly so callers can zip them.
fn mark_each_message(
    transform: &DatamarkingTransform,
    zone_outcome: &ZonePipelineOutcome,
) -> Vec<Vec<MarkedZone>> {
    let mut out = Vec::with_capacity(zone_outcome.zones_per_message.len());
    for (zones, text) in zone_outcome
        .zones_per_message
        .iter()
        .zip(&zone_outcome.texts)
    {
        let inputs: Vec<_> = zones
            .iter()
            .map(|z| {
                let slice = text.get(z.byte_range.clone()).unwrap_or("").to_string();
                (z.clone(), slice)
            })
            .collect();
        out.push(transform.apply(&inputs));
    }
    out
}

/// Re-serialise the request body with each marked message content
/// substituted in place. The proxy upstream-side expects a complete
/// JSON document, so we parse, mutate, and re-serialise.
///
/// When `reminder_addendum` is `Some`, the function also appends the
/// addendum to the first existing `role: "system"` message (or creates
/// one at the front when none exists). The addendum is intentionally
/// added ONLY in active mode — telling the model that whitespace is
/// marked when the proxy is actually forwarding the original bytes
/// (shadow_mode) would be a lie.
fn build_substituted_body(
    body_bytes: &[u8],
    zone_outcome: &ZonePipelineOutcome,
    marked_per_message: &[Vec<MarkedZone>],
    reminder_addendum: Option<&str>,
) -> Result<Vec<u8>, &'static str> {
    let mut doc: serde_json::Value =
        serde_json::from_slice(body_bytes).map_err(|_| "body_parse_failed")?;
    let messages = doc
        .get_mut("messages")
        .and_then(|m| m.as_array_mut())
        .ok_or("body_missing_messages")?;

    for (i, msg) in messages.iter_mut().enumerate() {
        let Some(marked_zones) = marked_per_message.get(i) else {
            continue;
        };
        if marked_zones.is_empty() {
            continue;
        }
        // Only rewrite the message content when at least one Data
        // zone actually substituted whitespace. Otherwise leave the
        // body bytes as the upstream pipeline (boundary defense,
        // zone-marker strip) handed them to us — that preserves
        // composition with `boundary.rs` which wraps tool messages
        // BEFORE datamarking runs and the wrapping must survive.
        let Some(text) = zone_outcome.texts.get(i) else {
            continue;
        };
        let any_substitution = marked_zones.iter().any(|mz| {
            mz.kind == ZoneKind::Data
                && text
                    .get(mz.byte_range.clone())
                    .map(|s| s != mz.content)
                    .unwrap_or(false)
        });
        if !any_substitution {
            continue;
        }
        let Some(content_field) = msg.get_mut("content") else {
            continue;
        };
        if !matches!(content_field, serde_json::Value::String(_)) {
            continue;
        }

        let rebuilt = splice_message_content(text, marked_zones);
        *content_field = serde_json::Value::String(rebuilt);
    }

    if let Some(addendum) = reminder_addendum {
        append_to_system_reminder(messages, addendum);
    }

    serde_json::to_vec(&doc).map_err(|_| "body_reserialize_failed")
}

/// Append `addendum` to the first existing string-valued `role:
/// "system"` message. When no system message exists, prepend a new
/// one carrying only the addendum. Mirrors `boundary.rs::inject_system_reminder`
/// so the two reminder injectors compose deterministically.
fn append_to_system_reminder(messages: &mut Vec<serde_json::Value>, addendum: &str) {
    for msg in messages.iter_mut() {
        if msg.get("role").and_then(|r| r.as_str()) == Some("system") {
            if let Some(serde_json::Value::String(s)) = msg.get_mut("content") {
                *s = format!("{s}{addendum}");
                return;
            }
        }
    }
    // No existing system message; prepend one with the addendum text
    // trimmed of its leading space (the addendum was crafted to append
    // to an existing reminder).
    messages.insert(
        0,
        serde_json::json!({
            "role": "system",
            "content": addendum.trim_start().to_string(),
        }),
    );
}

/// Reassemble one message's text from its marked zones. Zones cover
/// the input contiguously and in source order (per
/// `zone_detector::build_message_zones`), so the rebuild is a simple
/// concat.
fn splice_message_content(_original_text: &str, marked_zones: &[MarkedZone]) -> String {
    let total: usize = marked_zones.iter().map(|mz| mz.content.len()).sum();
    let mut out = String::with_capacity(total);
    for mz in marked_zones {
        out.push_str(&mz.content);
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use llmtrace_core::{
        DatamarkingConfig, MarkerStrategy, ZoneDetectionConfig, ZoneDetectionMode,
    };

    fn zone_cfg() -> ZoneDetectionConfig {
        ZoneDetectionConfig {
            enabled: true,
            mode: ZoneDetectionMode::Both,
            scan_instruction_zones: false,
        }
    }

    fn fixed_marker_cfg(shadow: bool) -> DatamarkingConfig {
        DatamarkingConfig {
            enabled: true,
            shadow_mode: shadow,
            marker_strategy: MarkerStrategy::Fixed('\u{E000}'),
        }
    }

    fn body_with_inline_data(text: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "model": "gpt-4",
            "messages": [
                {"role": "user", "content": text}
            ],
        }))
        .unwrap()
    }

    #[test]
    fn disabled_is_passthrough_no_op() {
        let body = body_with_inline_data(
            "answer based on:\n<llmtrace-data>tool out</llmtrace-data>\nplease.",
        );
        let zone_outcome = crate::zone_pipeline::run(&body, None, &zone_cfg());
        let cfg = DatamarkingConfig::default(); // enabled = false
        let out = run(&zone_outcome.body, &zone_outcome, &cfg);
        assert!(!out.body_rewritten);
        assert_eq!(out.body, zone_outcome.body);
        assert_eq!(out.zones_marked, 0);
        assert!(out.failures.is_empty());
    }

    #[test]
    fn shadow_mode_forwards_original_but_records_metrics() {
        let body = body_with_inline_data(
            "context:\n<llmtrace-data>tool output with spaces</llmtrace-data>\ndone.",
        );
        let zone_outcome = crate::zone_pipeline::run(&body, None, &zone_cfg());
        let cfg = fixed_marker_cfg(true);
        let out = run(&zone_outcome.body, &zone_outcome, &cfg);
        // Body forwarded is unchanged in shadow mode.
        assert_eq!(out.body, zone_outcome.body);
        assert!(!out.body_rewritten);
        // But the metrics carry the would-be work.
        assert!(out.zones_marked >= 1);
        assert!(out.byte_delta_total > 0);
        assert!(out.shadow_mode);
    }

    #[test]
    fn active_mode_marks_data_zone_in_body() {
        let body = body_with_inline_data(
            "context:\n<llmtrace-data>tool output with spaces</llmtrace-data>\ndone.",
        );
        let zone_outcome = crate::zone_pipeline::run(&body, None, &zone_cfg());
        let cfg = fixed_marker_cfg(false);
        let out = run(&zone_outcome.body, &zone_outcome, &cfg);
        assert!(out.body_rewritten);
        let parsed: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
        // Active mode prepends a system reminder addendum, shifting
        // the user message to index 1. The first message is the
        // synthetic system reminder describing the marker; the second
        // is the user message with its data zone marked.
        let messages = parsed["messages"].as_array().unwrap();
        let sys_content = messages[0]["content"].as_str().unwrap();
        assert_eq!(messages[0]["role"], "system");
        assert!(sys_content.contains("untrusted data"));
        assert!(sys_content.contains('\u{E000}'));
        // User message at index 1; data zone marked, instruction
        // segments preserved.
        let user_content = messages[1]["content"].as_str().unwrap();
        assert_eq!(messages[1]["role"], "user");
        assert!(user_content.contains('\u{E000}'));
        assert!(user_content.contains("context:\n"));
        assert!(user_content.contains("\ndone."));
    }

    #[test]
    fn instruction_zones_passthrough_byte_identical() {
        let body = serde_json::to_vec(&serde_json::json!({
            "model": "gpt-4",
            "messages": [
                {"role": "user", "content": "just a plain user question, no data zone."}
            ],
        }))
        .unwrap();
        let zone_outcome = crate::zone_pipeline::run(&body, None, &zone_cfg());
        let cfg = fixed_marker_cfg(false);
        let out = run(&zone_outcome.body, &zone_outcome, &cfg);
        // No data zones -> no substitution; body should be identical.
        assert!(!out.body_rewritten);
        assert_eq!(out.body, zone_outcome.body);
        assert_eq!(out.zones_marked, 0);
    }

    #[test]
    fn idempotence_apply_twice_no_additional_substitution() {
        let body = body_with_inline_data(
            "ctx:\n<llmtrace-data>tool output one two three</llmtrace-data>\ntail.",
        );
        let zone_outcome = crate::zone_pipeline::run(&body, None, &zone_cfg());
        let cfg = fixed_marker_cfg(false);
        let first = run(&zone_outcome.body, &zone_outcome, &cfg);
        assert!(first.body_rewritten);
        // Re-run zone pipeline against the marked body and apply again.
        let second_zone = crate::zone_pipeline::run(&first.body, None, &zone_cfg());
        let second = run(&second_zone.body, &second_zone, &cfg);
        assert_eq!(second.body, first.body, "datamarking must be idempotent");
    }

    #[test]
    fn empty_messages_array_is_handled_gracefully() {
        let body = serde_json::to_vec(&serde_json::json!({
            "model": "gpt-4",
            "messages": [],
        }))
        .unwrap();
        let zone_outcome = crate::zone_pipeline::run(&body, None, &zone_cfg());
        let cfg = fixed_marker_cfg(false);
        let out = run(&zone_outcome.body, &zone_outcome, &cfg);
        assert!(!out.body_rewritten);
        assert_eq!(out.zones_marked, 0);
    }

    #[test]
    fn no_zones_available_when_zone_detection_off_is_recorded() {
        let body = body_with_inline_data("hello world");
        // Zone detection disabled => zone_outcome has empty zones.
        let mut zone_cfg_off = zone_cfg();
        zone_cfg_off.enabled = false;
        let zone_outcome = crate::zone_pipeline::run(&body, None, &zone_cfg_off);
        let cfg = fixed_marker_cfg(false);
        let out = run(&zone_outcome.body, &zone_outcome, &cfg);
        assert!(!out.body_rewritten);
        assert!(out.failures.contains(&"no_zones_available"));
    }

    #[test]
    fn collision_with_default_marker_resamples_and_counts() {
        let body = body_with_inline_data(
            "ctx:\n<llmtrace-data>tool \u{E000} output</llmtrace-data>\ntail.",
        );
        let zone_outcome = crate::zone_pipeline::run(&body, None, &zone_cfg());
        let cfg = fixed_marker_cfg(false);
        let out = run(&zone_outcome.body, &zone_outcome, &cfg);
        assert_eq!(
            out.marker_collisions, 1,
            "U+E000 in content must trigger a resample once"
        );
    }
}
