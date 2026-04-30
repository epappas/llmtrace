//! Zone detection for IS-060 PR-1 (spotlighting indirect injection).
//!
//! A *zone* is a contiguous span of bytes inside a chat message text
//! tagged either [`ZoneKind::Instruction`] (trusted) or [`ZoneKind::Data`]
//! (untrusted). The proxy uses zones to fan ensemble scanning out per
//! data span and to tag findings with provenance metadata so the
//! over-defence suppressor (see `ensemble::apply_over_defence`) can
//! treat data-zone findings differently from instruction-zone ones.
//!
//! This module is detection-only: it never modifies the bytes that are
//! forwarded upstream. Operator-supplied inline markers
//! (`<llmtrace-data>...</llmtrace-data>`) are stripped from the
//! forwarding path *by the proxy*, not here — see
//! `crates/llmtrace-proxy/src/proxy.rs`. Datamarking (whitespace
//! substitution) is the surface of PR-2 and lives elsewhere.
//!
//! # Threat model and design notes
//!
//! Reference: `docs/architecture/SPOTLIGHTING_INDIRECT_INJECTION.md`
//! sections §4.1–§4.5. The implementation here matches the doc's
//! "single FSM with format precedence over per-format extractors"
//! recommendation. Failure mode is "fail Data": malformed framings
//! (e.g. an HTML `<table>` opened but never closed) tag the rest of
//! the message as Data so injection scanning cannot be hidden behind
//! a broken structure.

use std::ops::Range;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Trust kind of a zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoneKind {
    /// Trusted instruction surface (system prompt, user's own question).
    Instruction,
    /// Untrusted data surface (tool output, RAG content, scraped HTML,
    /// pasted email body). Subject to per-zone scanning under
    /// `ZoneDetectionConfig`.
    Data,
}

impl ZoneKind {
    /// Stable wire string for the `zone_kind` finding metadata key.
    pub fn as_str(&self) -> &'static str {
        match self {
            ZoneKind::Instruction => "instruction",
            ZoneKind::Data => "data",
        }
    }
}

/// Where the zone classification came from. Used in metrics labels
/// and as the `zone_origin` finding metadata key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoneOrigin {
    /// Default classification by chat role: `system`/`user` text without
    /// any heuristic match is Instruction; `tool`/`assistant` content is
    /// Data without any further scanning.
    Role,
    /// FSM matched one of the five framings (HTML table, code fence,
    /// email header block, JSON document, CSV).
    Heuristic,
    /// Operator-supplied inline marker (`<llmtrace-data>...
    /// </llmtrace-data>`).
    OperatorInline,
    /// Operator-supplied via the `X-LLMTrace-Data-Boundary` header.
    OperatorHeader,
}

impl ZoneOrigin {
    /// Stable wire string for the `zone_origin` finding metadata key.
    pub fn as_str(&self) -> &'static str {
        match self {
            ZoneOrigin::Role => "role",
            ZoneOrigin::Heuristic => "heuristic",
            ZoneOrigin::OperatorInline => "operator_inline",
            ZoneOrigin::OperatorHeader => "operator_header",
        }
    }
}

/// One contiguous span of zoned text. `byte_range` indexes into the
/// source string the zone was extracted from. Heuristic-detected zones
/// also carry a `framing` label so metrics can attribute zone counts
/// back to which heuristic fired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zone {
    pub kind: ZoneKind,
    pub origin: ZoneOrigin,
    /// Half-open byte range `[start, end)` into the source text.
    pub byte_range: Range<usize>,
    /// `Some(_)` only for `ZoneOrigin::Heuristic`; `None` otherwise.
    /// Stable, lower-snake-case label for the framing that matched.
    pub framing: Option<&'static str>,
}

impl Zone {
    /// Construct a zone covering the whole text.
    pub fn whole(kind: ZoneKind, origin: ZoneOrigin, len: usize) -> Self {
        Self {
            kind,
            origin,
            byte_range: 0..len,
            framing: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Operator-supplied zones from the X-LLMTrace-Data-Boundary header
// ---------------------------------------------------------------------------

/// Pointer to a data zone produced from `X-LLMTrace-Data-Boundary`.
///
/// Header grammar:
///
/// ```text
/// header   := boundary ("," boundary)*
/// boundary := message_index ":" byte_start "-" byte_end
/// ```
///
/// Example: `X-LLMTrace-Data-Boundary: 2:0-512,3:0-1000`. Whitespace
/// between tokens is permitted; entries that fail to parse are skipped
/// (and counted as `failures{reason="header_parse_failed"}` by the
/// caller — this module returns the parsed-and-rejected counts so the
/// proxy can record them deterministically).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorHeaderZone {
    /// Index into the chat `messages` array.
    pub message_index: usize,
    /// Byte range inside that message's content text.
    pub byte_range: Range<usize>,
}

/// Result of parsing the `X-LLMTrace-Data-Boundary` header.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OperatorHeaderParse {
    pub zones: Vec<OperatorHeaderZone>,
    /// Number of comma-separated entries that failed to parse. The
    /// proxy aggregates this into the `zone_detection_failures_total`
    /// metric under `reason="header_parse_failed"`.
    pub rejected: u32,
}

/// Parse the value of `X-LLMTrace-Data-Boundary` into a list of
/// operator-supplied zones. An invalid entry never aborts the parse
/// — it bumps `rejected` and the loop moves on. This matches the
/// fail-open contract of `boundary.rs::apply_boundary_defense`.
pub fn parse_data_boundary_header(value: &str) -> OperatorHeaderParse {
    let mut out = OperatorHeaderParse::default();
    for raw in value.split(',') {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        match parse_one_boundary(trimmed) {
            Some(z) => out.zones.push(z),
            None => out.rejected += 1,
        }
    }
    out
}

/// Parse a single `<index>:<start>-<end>` entry. Returns `None` on any
/// shape mismatch.
fn parse_one_boundary(entry: &str) -> Option<OperatorHeaderZone> {
    let (idx, rest) = entry.split_once(':')?;
    let (start, end) = rest.split_once('-')?;
    let message_index: usize = idx.trim().parse().ok()?;
    let start: usize = start.trim().parse().ok()?;
    let end: usize = end.trim().parse().ok()?;
    if end <= start {
        return None;
    }
    Some(OperatorHeaderZone {
        message_index,
        byte_range: start..end,
    })
}

// ---------------------------------------------------------------------------
// Inline markers — `<llmtrace-data>...</llmtrace-data>`
// ---------------------------------------------------------------------------

/// Default inline marker tag name. The default is intentionally
/// distinct from `boundary.rs`'s `<llmtrace-boundary>` so the two
/// defences never double-wrap the same span.
pub const DEFAULT_INLINE_TAG: &str = "llmtrace-data";

/// Strip operator inline markers from a text and return the rewritten
/// text together with the data spans the markers enclosed.
///
/// The byte ranges in the returned [`StrippedInlineMarkers::data_spans`]
/// index into the **stripped** output, not the original. This is what
/// downstream zone composition expects: heuristics, header zones, and
/// inline zones all live in the same coordinate system once the markers
/// have been removed.
///
/// Failure modes:
///   * Unclosed open tag: the tag itself is removed, and the text from
///     the open tag onward becomes a single Data span (fail-Data).
///   * Stray close tag without an opener: removed from the text, no
///     span is emitted.
///   * Nested open tags: the outermost pair wins; inner tags are
///     removed but do not produce additional spans.
pub fn strip_inline_markers(text: &str, tag: &str) -> StrippedInlineMarkers {
    let open_lit = format!("<{tag}>");
    let close_lit = format!("</{tag}>");
    let mut out = String::with_capacity(text.len());
    let mut data_spans: Vec<Range<usize>> = Vec::new();
    let mut had_unclosed = false;

    let mut cursor = 0usize;
    while cursor < text.len() {
        let remaining = &text[cursor..];
        let next_open = remaining.find(&open_lit);
        let next_close = remaining.find(&close_lit);
        match (next_open, next_close) {
            (None, None) => {
                out.push_str(remaining);
                cursor = text.len();
            }
            (None, Some(c)) => {
                // Stray close at top level — drop it, keep the prefix
                // and recurse over the suffix on the next iteration.
                out.push_str(&remaining[..c]);
                cursor += c + close_lit.len();
            }
            (Some(o), Some(c)) if c < o => {
                // Stray close before the next open — same as None/Some.
                out.push_str(&remaining[..c]);
                cursor += c + close_lit.len();
            }
            (Some(o), _) => {
                out.push_str(&remaining[..o]);
                cursor += o + open_lit.len();
                cursor = consume_nested_data_block(
                    text,
                    cursor,
                    &open_lit,
                    &close_lit,
                    &mut out,
                    &mut data_spans,
                    &mut had_unclosed,
                );
            }
        }
    }

    StrippedInlineMarkers {
        text: out,
        data_spans,
        had_unclosed,
    }
}

/// Consume one data block that has just had its outer open tag stripped.
/// Tracks nested open/close pairs so the outermost pair wins (per
/// §4.3.1's "outer pair wins" rule). Returns the new cursor in `text`.
fn consume_nested_data_block(
    text: &str,
    mut cursor: usize,
    open_lit: &str,
    close_lit: &str,
    out: &mut String,
    data_spans: &mut Vec<Range<usize>>,
    had_unclosed: &mut bool,
) -> usize {
    let span_start_in_out = out.len();
    let mut depth: u32 = 1;
    while cursor < text.len() && depth > 0 {
        let remaining = &text[cursor..];
        let next_open = remaining.find(open_lit);
        let next_close = remaining.find(close_lit);
        match (next_open, next_close) {
            (Some(o), Some(c)) if o < c => {
                out.push_str(&remaining[..o]);
                cursor += o + open_lit.len();
                depth += 1;
            }
            (_, Some(c)) => {
                out.push_str(&remaining[..c]);
                cursor += c + close_lit.len();
                depth -= 1;
            }
            (Some(_), None) | (None, None) => {
                out.push_str(remaining);
                cursor = text.len();
                *had_unclosed = true;
                depth = 0;
            }
        }
    }
    let span_end_in_out = out.len();
    if span_start_in_out < span_end_in_out {
        data_spans.push(span_start_in_out..span_end_in_out);
    }
    cursor
}

/// Output of [`strip_inline_markers`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrippedInlineMarkers {
    /// Text with `<{tag}>` and `</{tag}>` markers removed.
    pub text: String,
    /// Byte ranges (into `text`) of the data spans the operator marked.
    pub data_spans: Vec<Range<usize>>,
    /// True iff at least one open tag had no matching close — the
    /// rest of the text was tagged Data via fail-Data semantics.
    pub had_unclosed: bool,
}

// ---------------------------------------------------------------------------
// Heuristic FSM — the five framings, in precedence order
// ---------------------------------------------------------------------------

/// Detect the outermost structured-data framing in `text` and return
/// `Some(start..end)` for the first match. Precedence:
///
/// 1. HTML `<table>...</table>` (case-insensitive)
/// 2. Markdown fenced code block (lines starting with ``` ```)
/// 3. RFC822 / email header block
/// 4. Top-level JSON document (`{...}` or `[...]` spanning the bulk)
/// 5. CSV (≥ 3 lines with consistent comma column count)
///
/// Returns the framing label so callers can attribute metrics. A
/// `None` result means no framing matched and the entire text should
/// be treated as a single Instruction span by the caller.
///
/// On a malformed open without a matching close (e.g. `<table>` with no
/// `</table>`), the span runs from the opener to end-of-text — the
/// fail-Data behaviour described in §4.2.2 of the design doc.
pub fn detect_data_framing(text: &str) -> Option<(Range<usize>, &'static str)> {
    if let Some(r) = scan_html_table(text) {
        return Some((r, "html_table"));
    }
    if let Some(r) = scan_code_fence(text) {
        return Some((r, "code_fence"));
    }
    if let Some(r) = scan_email_header(text) {
        return Some((r, "email_header"));
    }
    if let Some(r) = scan_json_document(text) {
        return Some((r, "json_document"));
    }
    if let Some(r) = scan_csv(text) {
        return Some((r, "csv"));
    }
    None
}

fn scan_html_table(text: &str) -> Option<Range<usize>> {
    let lower = text.to_ascii_lowercase();
    let open = lower.find("<table")?;
    // Find the matching close tag at depth 0 (no nesting tracking — a
    // nested `<table>` is rare in real RAG and the conservative read
    // is to treat the whole outer span as one Data zone anyway).
    let close = lower[open..].find("</table>");
    let end = match close {
        Some(rel) => open + rel + "</table>".len(),
        None => text.len(), // fail-Data: opener with no closer
    };
    Some(open..end)
}

fn scan_code_fence(text: &str) -> Option<Range<usize>> {
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    while i < len {
        let line_end = next_line_end(bytes, i);
        let line = &text[i..line_end];
        if line.trim_start().starts_with("```") {
            let opener_start = i;
            let after = line_end + 1;
            // Find a closing fence on its own line.
            let mut j = after;
            while j < len {
                let je = next_line_end(bytes, j);
                let l2 = &text[j..je];
                if l2.trim() == "```" {
                    return Some(opener_start..je);
                }
                j = je + 1;
            }
            // Fail-Data: opening fence without a close.
            return Some(opener_start..len);
        }
        i = line_end + 1;
    }
    None
}

fn scan_email_header(text: &str) -> Option<Range<usize>> {
    let bytes = text.as_bytes();
    let len = bytes.len();
    // Look for ≥ 2 consecutive header-shaped lines, then the block ends
    // at the first blank line.
    let mut i = 0usize;
    let mut block_start: Option<usize> = None;
    let mut header_lines = 0u32;
    while i < len {
        let je = next_line_end(bytes, i);
        let line = &text[i..je];
        if is_email_header_line(line) {
            if block_start.is_none() {
                block_start = Some(i);
            }
            header_lines += 1;
        } else if header_lines >= 2 {
            // Block ended; consume the optional blank line and any
            // trailing body until end-of-text — RFC822 bodies are
            // attacker surface.
            let end = if line.trim().is_empty() { len } else { je };
            return block_start.map(|s| s..end);
        } else {
            block_start = None;
            header_lines = 0;
        }
        i = je + 1;
    }
    if header_lines >= 2 {
        return block_start.map(|s| s..len);
    }
    None
}

fn is_email_header_line(line: &str) -> bool {
    let bytes = line.as_bytes();
    let Some(colon) = line.find(':') else {
        return false;
    };
    if colon == 0 || colon > 40 {
        return false;
    }
    // Header name MUST start uppercase ASCII and contain only
    // [A-Za-z0-9-]. After the colon there must be a space.
    let name = &bytes[..colon];
    let first = match name.first() {
        Some(b) => *b,
        None => return false,
    };
    if !first.is_ascii_uppercase() {
        return false;
    }
    if !name.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-') {
        return false;
    }
    let after = &bytes[colon + 1..];
    matches!(after.first(), Some(b' ') | Some(b'\t'))
}

fn scan_json_document(text: &str) -> Option<Range<usize>> {
    let trimmed = text.trim_start();
    let leading = text.len() - trimmed.len();
    let first = trimmed.chars().next()?;
    let (open, close) = match first {
        '{' => ('{', '}'),
        '[' => ('[', ']'),
        _ => return None,
    };
    // Match brace/bracket depth, treating ASCII strings as opaque.
    let bytes = trimmed.as_bytes();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escape = false;
    for (i, &b) in bytes.iter().enumerate() {
        if in_string {
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            x if x as char == open => depth += 1,
            x if x as char == close => {
                depth -= 1;
                if depth == 0 {
                    let absolute_end = leading + i + 1;
                    // Only treat as JSON document if it covers the
                    // bulk (≥ 50%) of the message — heuristic guard
                    // against flagging short inline JSON snippets in
                    // an instruction zone.
                    let span_len = absolute_end - leading;
                    if span_len * 2 >= text.len() {
                        return Some(leading..absolute_end);
                    }
                    return None;
                }
            }
            _ => {}
        }
    }
    if depth > 0 {
        // Fail-Data on unclosed JSON.
        return Some(leading..text.len());
    }
    None
}

fn scan_csv(text: &str) -> Option<Range<usize>> {
    let bytes = text.as_bytes();
    let len = bytes.len();
    // Walk line by line; require ≥ 3 consecutive lines with the same
    // (≥ 2) comma count.
    let mut i = 0usize;
    let mut block_start: Option<usize> = None;
    let mut expected_commas: Option<usize> = None;
    let mut consecutive = 0u32;
    while i < len {
        let je = next_line_end(bytes, i);
        let line = &text[i..je];
        let commas = line.matches(',').count();
        if commas >= 2 {
            match expected_commas {
                Some(c) if c == commas => {
                    consecutive += 1;
                }
                _ => {
                    block_start = Some(i);
                    expected_commas = Some(commas);
                    consecutive = 1;
                }
            }
        } else if consecutive >= 3 {
            return block_start.map(|s| s..i);
        } else {
            block_start = None;
            expected_commas = None;
            consecutive = 0;
        }
        i = je + 1;
    }
    if consecutive >= 3 {
        return block_start.map(|s| s..len);
    }
    None
}

/// Return the byte index of the end of the line starting at `start`.
/// The `\n` is not included in the returned index.
fn next_line_end(bytes: &[u8], start: usize) -> usize {
    let mut j = start;
    while j < bytes.len() && bytes[j] != b'\n' {
        j += 1;
    }
    j
}

// ---------------------------------------------------------------------------
// Top-level zone layout for a single message
// ---------------------------------------------------------------------------

/// Build the zone layout for one message text after operator inline
/// markers have been stripped. The returned zones are non-overlapping
/// and cover the whole input contiguously.
///
/// Inputs:
///   * `text` — message content with inline markers already removed
///     (i.e. the `text` field of [`StrippedInlineMarkers`]).
///   * `inline_data_spans` — data spans recovered from inline markers,
///     indexed into `text`.
///   * `header_data_spans` — data spans pinned by
///     `X-LLMTrace-Data-Boundary` for this specific message, also
///     indexed into `text`. Out-of-range spans must be filtered by the
///     caller before calling this function.
///   * `enable_heuristics` — when `false`, only role-classified +
///     operator spans are used. Mirrors `ZoneDetectionMode`.
///
/// Operator spans (inline + header) take precedence over heuristic
/// spans on overlap, per §4.5 / open question Q5. Overlapping operator
/// spans are coalesced into a single Data zone.
pub fn build_message_zones(
    text: &str,
    inline_data_spans: &[Range<usize>],
    header_data_spans: &[Range<usize>],
    enable_heuristics: bool,
) -> Vec<Zone> {
    if text.is_empty() {
        return vec![Zone::whole(ZoneKind::Instruction, ZoneOrigin::Role, 0)];
    }

    let mut data_spans: Vec<(Range<usize>, ZoneOrigin, Option<&'static str>)> = Vec::new();
    for s in inline_data_spans {
        data_spans.push((s.clone(), ZoneOrigin::OperatorInline, None));
    }
    for s in header_data_spans {
        data_spans.push((s.clone(), ZoneOrigin::OperatorHeader, None));
    }
    if enable_heuristics && data_spans.is_empty() {
        if let Some((r, framing)) = detect_data_framing(text) {
            data_spans.push((r, ZoneOrigin::Heuristic, Some(framing)));
        }
    }

    if data_spans.is_empty() {
        return vec![Zone::whole(
            ZoneKind::Instruction,
            ZoneOrigin::Role,
            text.len(),
        )];
    }

    data_spans.sort_by_key(|(r, _, _)| (r.start, r.end));
    let merged = merge_data_spans(data_spans, text.len());
    interleave_with_instruction(merged, text.len())
}

/// Merge overlapping or touching data spans. Origin/framing are taken
/// from the first contributing span (operator wins because operator
/// spans appear earlier in the input list).
fn merge_data_spans(
    spans: Vec<(Range<usize>, ZoneOrigin, Option<&'static str>)>,
    text_len: usize,
) -> Vec<(Range<usize>, ZoneOrigin, Option<&'static str>)> {
    let mut out: Vec<(Range<usize>, ZoneOrigin, Option<&'static str>)> = Vec::new();
    for (range, origin, framing) in spans {
        let clipped = range.start.min(text_len)..range.end.min(text_len);
        if clipped.start >= clipped.end {
            continue;
        }
        if let Some(last) = out.last_mut() {
            if clipped.start <= last.0.end {
                last.0.end = last.0.end.max(clipped.end);
                continue;
            }
        }
        out.push((clipped, origin, framing));
    }
    out
}

/// Given disjoint, sorted data spans, produce the contiguous zone
/// layout `[Instruction prefix?, Data, Instruction gap?, Data, …,
/// Instruction suffix?]`.
fn interleave_with_instruction(
    data_spans: Vec<(Range<usize>, ZoneOrigin, Option<&'static str>)>,
    text_len: usize,
) -> Vec<Zone> {
    let mut zones: Vec<Zone> = Vec::with_capacity(data_spans.len() * 2 + 1);
    let mut cursor = 0usize;
    for (range, origin, framing) in data_spans {
        if range.start > cursor {
            zones.push(Zone {
                kind: ZoneKind::Instruction,
                origin: ZoneOrigin::Role,
                byte_range: cursor..range.start,
                framing: None,
            });
        }
        cursor = range.end;
        zones.push(Zone {
            kind: ZoneKind::Data,
            origin,
            byte_range: range,
            framing,
        });
    }
    if cursor < text_len {
        zones.push(Zone {
            kind: ZoneKind::Instruction,
            origin: ZoneOrigin::Role,
            byte_range: cursor..text_len,
            framing: None,
        });
    }
    zones
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
