//! Proxy-side zone pipeline (IS-060 PR-1).
//!
//! Wraps three concerns that compose at the proxy boundary but live
//! conceptually inside the security crate's `zone_detector`:
//!
//!   1. Stripping operator-supplied inline markers
//!      (`<llmtrace-data>...</llmtrace-data>`) from each chat message
//!      so they do not leak upstream, and recovering the data spans
//!      they enclosed.
//!   2. Parsing the `X-LLMTrace-Data-Boundary` request header into
//!      per-message data spans (range-clipped to the post-strip
//!      content text).
//!   3. Building the zone layout for each message via
//!      [`zone_detector::build_message_zones`] and producing the
//!      `(zone, text)` tuples the ensemble's
//!      `analyze_request_with_zones` consumes.
//!
//! The pipeline is fail-open at every step: malformed JSON or invalid
//! header entries log a counter and degrade to the non-zone-aware
//! request path. This matches `boundary.rs`'s contract.
//!
//! All byte ranges in the returned zones index into the **stripped**
//! message text (i.e. after `<llmtrace-data>` markers are removed),
//! so callers reuse a single coordinate system across heuristic,
//! inline, and header zones.

use std::ops::Range;

use llmtrace_core::ZoneDetectionConfig;
use llmtrace_security::zone_detector::{
    self, OperatorHeaderParse, StrippedInlineMarkers, Zone, ZoneKind, ZoneOrigin,
};

/// Header name carrying operator-supplied data zones.
pub const DATA_BOUNDARY_HEADER: &str = "x-llmtrace-data-boundary";

/// Outcome of running the proxy-side zone pipeline.
#[derive(Debug, Default)]
pub struct ZonePipelineOutcome {
    /// Rewritten request body bytes with inline markers stripped.
    /// Equal to the input bytes when zone detection is disabled OR
    /// when no markers were present.
    pub body: Vec<u8>,
    /// True iff `body` was rewritten and the upstream request should
    /// forward `body` instead of the original.
    pub body_rewritten: bool,
    /// Per-message zone layouts. Each entry is the list of zones for
    /// `messages[i]`, in source order.
    pub zones_per_message: Vec<Vec<Zone>>,
    /// Stripped text for each message, in source order. The substring
    /// for `zones_per_message[i][k]` is `texts[i][zone.byte_range]`.
    pub texts: Vec<String>,
    /// Failures recorded by the pipeline (`header_parse_failed`,
    /// `header_range_out_of_bounds`, etc.). One entry per failure
    /// occurrence — the proxy bumps `zone_detection_failures_total`
    /// per entry.
    pub failures: Vec<&'static str>,
}

impl ZonePipelineOutcome {
    /// Flatten zones across all messages into the
    /// `analyze_request_with_zones` input shape: `(zone, owned text)`.
    /// Allocates fresh `String`s; the ensemble's spawn pool needs
    /// `'static` payloads.
    pub fn into_zone_inputs(self, scan_instruction_zones: bool) -> Vec<(Zone, String)> {
        let mut out = Vec::new();
        for (zones, text) in self.zones_per_message.into_iter().zip(self.texts) {
            for zone in zones {
                if zone.kind == ZoneKind::Instruction && !scan_instruction_zones {
                    continue;
                }
                let slice = text.get(zone.byte_range.clone()).unwrap_or("").to_string();
                out.push((zone, slice));
            }
        }
        out
    }

    /// Flat list of `(kind_label, origin_label, framing_label)` for
    /// every emitted zone, used by `Metrics::record_zone_detection`.
    pub fn metric_zones(&self) -> Vec<(&'static str, &'static str, &'static str)> {
        let mut out = Vec::new();
        for zones in &self.zones_per_message {
            for z in zones {
                out.push((z.kind.as_str(), z.origin.as_str(), z.framing.unwrap_or("_")));
            }
        }
        out
    }
}

/// Run the proxy-side zone pipeline. `enabled = false` short-circuits
/// to a passthrough outcome with empty zones — callers compare
/// `outcome.zones_per_message` and skip the zone-aware ensemble path
/// when nothing was emitted.
pub fn run(
    body_bytes: &[u8],
    header_value: Option<&str>,
    config: &ZoneDetectionConfig,
) -> ZonePipelineOutcome {
    if !config.enabled {
        return ZonePipelineOutcome {
            body: body_bytes.to_vec(),
            body_rewritten: false,
            ..Default::default()
        };
    }

    // 1. Parse body into a generic JSON document so we can extract
    //    message contents without committing to the boundary defense's
    //    typed `RequestBody`. We re-serialize from this Value when
    //    inline markers were present.
    let mut doc: serde_json::Value = match serde_json::from_slice(body_bytes) {
        Ok(v) => v,
        Err(_) => {
            return ZonePipelineOutcome {
                body: body_bytes.to_vec(),
                body_rewritten: false,
                failures: vec!["body_parse_failed"],
                ..Default::default()
            };
        }
    };

    // 2. Extract message contents (only string-valued ones; arrays /
    //    nulls are left as-is and treated as zero-zone messages).
    let mut texts: Vec<String> = Vec::new();
    let mut content_was_string: Vec<bool> = Vec::new();
    if let Some(messages) = doc.get("messages").and_then(|m| m.as_array()) {
        for msg in messages {
            match msg.get("content") {
                Some(serde_json::Value::String(s)) => {
                    texts.push(s.clone());
                    content_was_string.push(true);
                }
                _ => {
                    texts.push(String::new());
                    content_was_string.push(false);
                }
            }
        }
    }

    // 3. Strip inline markers, but only from string-content messages.
    let inline_use = matches!(
        config.mode,
        llmtrace_core::ZoneDetectionMode::Both | llmtrace_core::ZoneDetectionMode::Operator
    );
    let mut inline_spans_per_message: Vec<Vec<Range<usize>>> =
        (0..texts.len()).map(|_| Vec::new()).collect();
    let mut body_rewritten = false;
    if inline_use {
        for (i, text) in texts.iter_mut().enumerate() {
            if !content_was_string[i] {
                continue;
            }
            let stripped: StrippedInlineMarkers =
                zone_detector::strip_inline_markers(text, zone_detector::DEFAULT_INLINE_TAG);
            if stripped.text != *text {
                body_rewritten = true;
            }
            *text = stripped.text;
            inline_spans_per_message[i] = stripped.data_spans;
        }
    }

    // 4. Parse the X-LLMTrace-Data-Boundary header.
    let header_use = matches!(
        config.mode,
        llmtrace_core::ZoneDetectionMode::Both | llmtrace_core::ZoneDetectionMode::Operator
    );
    let mut failures: Vec<&'static str> = Vec::new();
    let mut header_spans_per_message: Vec<Vec<Range<usize>>> =
        (0..texts.len()).map(|_| Vec::new()).collect();
    if header_use {
        if let Some(value) = header_value {
            let OperatorHeaderParse { zones, rejected } =
                zone_detector::parse_data_boundary_header(value);
            failures.extend(std::iter::repeat_n(
                "header_parse_failed",
                rejected as usize,
            ));
            for hz in zones {
                if let Some(slot) = header_spans_per_message.get_mut(hz.message_index) {
                    let len = texts.get(hz.message_index).map(String::len).unwrap_or(0);
                    if hz.byte_range.start >= len || hz.byte_range.end > len {
                        failures.push("header_range_out_of_bounds");
                        continue;
                    }
                    slot.push(hz.byte_range);
                } else {
                    failures.push("header_message_index_out_of_bounds");
                }
            }
        }
    }

    // 5. Build per-message zone layouts.
    let enable_heuristics = matches!(
        config.mode,
        llmtrace_core::ZoneDetectionMode::Both | llmtrace_core::ZoneDetectionMode::Heuristic
    );
    let mut zones_per_message: Vec<Vec<Zone>> = Vec::with_capacity(texts.len());
    for i in 0..texts.len() {
        let zones = if content_was_string[i] {
            zone_detector::build_message_zones(
                &texts[i],
                &inline_spans_per_message[i],
                &header_spans_per_message[i],
                enable_heuristics,
            )
        } else {
            Vec::new()
        };
        zones_per_message.push(zones);
    }

    // 6. If we rewrote any message text, re-serialize the body so the
    //    forwarded bytes match the stripped contents.
    let body = if body_rewritten {
        if let Some(messages) = doc.get_mut("messages").and_then(|m| m.as_array_mut()) {
            for (i, msg) in messages.iter_mut().enumerate() {
                if content_was_string[i] {
                    if let Some(content) = msg.get_mut("content") {
                        *content = serde_json::Value::String(texts[i].clone());
                    }
                }
            }
        }
        match serde_json::to_vec(&doc) {
            Ok(b) => b,
            Err(_) => {
                failures.push("body_reserialize_failed");
                body_bytes.to_vec()
            }
        }
    } else {
        body_bytes.to_vec()
    };

    let _ = ZoneOrigin::Role; // keep the import live for clippy when
                              // future expansions reference it; cheap
                              // no-op at the binary level.

    let final_rewritten = body_rewritten && body.as_slice() != body_bytes;
    ZonePipelineOutcome {
        body,
        body_rewritten: final_rewritten,
        zones_per_message,
        texts,
        failures,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(enabled: bool) -> ZoneDetectionConfig {
        ZoneDetectionConfig {
            enabled,
            mode: llmtrace_core::ZoneDetectionMode::Both,
            scan_instruction_zones: false,
        }
    }

    fn body_with(messages: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "model": "gpt-4",
            "messages": messages,
        }))
        .unwrap()
    }

    #[test]
    fn disabled_passthrough() {
        let body = body_with(serde_json::json!([
            {"role": "user", "content": "hello <llmtrace-data>secret</llmtrace-data> world"},
        ]));
        let out = run(&body, None, &config(false));
        assert!(!out.body_rewritten);
        assert_eq!(out.body, body);
        assert!(out.zones_per_message.is_empty());
    }

    #[test]
    fn inline_markers_stripped_and_body_rewritten() {
        let body = body_with(serde_json::json!([
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "answer based on:\n<llmtrace-data>untrusted</llmtrace-data>\nplease."},
        ]));
        let out = run(&body, None, &config(true));
        assert!(out.body_rewritten);
        let parsed: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
        let user_content = parsed["messages"][1]["content"].as_str().unwrap();
        assert!(!user_content.contains("<llmtrace-data>"));
        assert!(!user_content.contains("</llmtrace-data>"));
        assert!(user_content.contains("untrusted"));
        // user message has Data zone from the inline marker
        let user_zones = &out.zones_per_message[1];
        assert!(user_zones
            .iter()
            .any(|z| z.kind == ZoneKind::Data && z.origin == ZoneOrigin::OperatorInline));
    }

    #[test]
    fn header_zone_parses_and_clips_to_message_text() {
        let body = body_with(serde_json::json!([
            {"role": "user", "content": "abcdefghij"},
        ]));
        let out = run(&body, Some("0:2-6"), &config(true));
        assert!(out.failures.is_empty());
        let zones = &out.zones_per_message[0];
        let data: Vec<&Zone> = zones.iter().filter(|z| z.kind == ZoneKind::Data).collect();
        assert_eq!(data.len(), 1);
        assert_eq!(data[0].origin, ZoneOrigin::OperatorHeader);
        assert_eq!(data[0].byte_range, 2..6);
    }

    #[test]
    fn header_out_of_range_logged_as_failure_no_zone() {
        let body = body_with(serde_json::json!([
            {"role": "user", "content": "short"},
        ]));
        let out = run(&body, Some("0:0-1000"), &config(true));
        assert!(out
            .failures
            .iter()
            .any(|r| *r == "header_range_out_of_bounds"));
        let zones = &out.zones_per_message[0];
        assert!(zones.iter().all(|z| z.kind == ZoneKind::Instruction));
    }

    #[test]
    fn invalid_body_is_passthrough_with_failure() {
        let out = run(b"not json", None, &config(true));
        assert!(!out.body_rewritten);
        assert_eq!(out.body, b"not json");
        assert!(out.failures.contains(&"body_parse_failed"));
        assert!(out.zones_per_message.is_empty());
    }

    #[test]
    fn into_zone_inputs_skips_instruction_zones_by_default() {
        let body = body_with(serde_json::json!([
            {"role": "user", "content": "<llmtrace-data>data span</llmtrace-data> tail"},
        ]));
        let out = run(&body, None, &config(true));
        let inputs = out.into_zone_inputs(false);
        assert!(inputs.iter().all(|(z, _)| z.kind == ZoneKind::Data));
    }

    #[test]
    fn into_zone_inputs_includes_instruction_when_requested() {
        let body = body_with(serde_json::json!([
            {"role": "user", "content": "<llmtrace-data>data</llmtrace-data> tail"},
        ]));
        let out = run(&body, None, &config(true));
        let inputs = out.into_zone_inputs(true);
        assert!(inputs.iter().any(|(z, _)| z.kind == ZoneKind::Instruction));
        assert!(inputs.iter().any(|(z, _)| z.kind == ZoneKind::Data));
    }
}
