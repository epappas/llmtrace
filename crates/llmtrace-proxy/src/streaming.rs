//! Server-Sent Events (SSE) streaming support.
//!
//! Parses OpenAI-compatible SSE chunks as they arrive, extracts token data
//! incrementally, and tracks streaming metrics (TTFT, completion tokens).

use serde::Deserialize;

// ---------------------------------------------------------------------------
// SSE line parsing
// ---------------------------------------------------------------------------

/// Extract the JSON payload from an SSE `data:` line.
///
/// Returns `None` for blank lines, comment lines, non-data fields,
/// and the terminal `data: [DONE]` sentinel.
pub fn extract_sse_data(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with(':') {
        return None;
    }
    let payload = trimmed.strip_prefix("data:")?;
    let payload = payload.trim_start();
    if payload == "[DONE]" {
        return None;
    }
    Some(payload)
}

// ---------------------------------------------------------------------------
// OpenAI-compatible SSE chunk types
// ---------------------------------------------------------------------------

/// Minimal representation of an OpenAI streaming chunk.
#[derive(Debug, Deserialize)]
pub struct SseChunk {
    /// Choices returned in this chunk.
    #[serde(default)]
    pub choices: Vec<SseChoice>,
    /// Usage data (only present in the final chunk for some providers).
    #[serde(default)]
    pub usage: Option<SseUsage>,
}

/// A single choice within an SSE chunk.
#[derive(Debug, Deserialize)]
pub struct SseChoice {
    /// The delta content for this chunk.
    #[serde(default)]
    pub delta: Option<SseDelta>,
    /// Finish reason (e.g. `"stop"`). `None` while streaming.
    pub finish_reason: Option<String>,
}

/// Delta content within a streaming choice.
#[derive(Debug, Deserialize)]
pub struct SseDelta {
    /// The token text (may be absent for role-only or empty deltas).
    pub content: Option<String>,
}

/// Token usage data that some providers include in the final chunk.
#[derive(Debug, Deserialize)]
pub struct SseUsage {
    pub prompt_tokens: Option<u32>,
    pub completion_tokens: Option<u32>,
    pub total_tokens: Option<u32>,
}

// ---------------------------------------------------------------------------
// Streaming accumulator
// ---------------------------------------------------------------------------

/// Accumulates data from a streaming SSE response.
///
/// Feed it raw bytes from the upstream response; it splits on newlines,
/// parses SSE data lines, extracts token content, and tracks metrics.
pub struct StreamingAccumulator {
    /// Buffer for incomplete lines across chunk boundaries.
    line_buffer: String,
    /// All response content tokens concatenated.
    pub content: String,
    /// Number of completion tokens observed (each non-empty delta counts as 1).
    pub completion_token_count: u32,
    /// Whether the first content token has been received.
    pub first_token_received: bool,
    /// Provider-reported usage (if present in the final chunk).
    pub reported_usage: Option<SseUsage>,
    /// Whether the stream has ended (`data: [DONE]` received).
    pub done: bool,
}

impl StreamingAccumulator {
    /// Create a new empty accumulator.
    pub fn new() -> Self {
        Self {
            line_buffer: String::new(),
            content: String::new(),
            completion_token_count: 0,
            first_token_received: false,
            reported_usage: None,
            done: false,
        }
    }

    /// Process a raw byte chunk from the upstream response.
    ///
    /// Returns `true` if this chunk contained the first content token
    /// (useful for recording TTFT).
    pub fn process_chunk(&mut self, bytes: &[u8]) -> bool {
        let text = String::from_utf8_lossy(bytes);
        self.line_buffer.push_str(&text);

        let mut first_token_in_this_chunk = false;

        // Process all complete lines (terminated by '\n')
        while let Some(newline_pos) = self.line_buffer.find('\n') {
            let line: String = self.line_buffer[..newline_pos].to_string();
            self.line_buffer = self.line_buffer[newline_pos + 1..].to_string();

            // Check for [DONE]
            let trimmed = line.trim();
            if trimmed.strip_prefix("data:").map(|s| s.trim()) == Some("[DONE]") {
                self.done = true;
                continue;
            }

            if let Some(json_str) = extract_sse_data(&line) {
                if let Ok(chunk) = serde_json::from_str::<SseChunk>(json_str) {
                    // Extract content tokens
                    for choice in &chunk.choices {
                        if let Some(delta) = &choice.delta {
                            if let Some(ref token_text) = delta.content {
                                if !token_text.is_empty() {
                                    if !self.first_token_received {
                                        self.first_token_received = true;
                                        first_token_in_this_chunk = true;
                                    }
                                    self.content.push_str(token_text);
                                    self.completion_token_count += 1;
                                }
                            }
                        }
                    }

                    // Capture provider-reported usage from final chunk
                    if let Some(usage) = chunk.usage {
                        self.reported_usage = Some(usage);
                    }
                }
            }
        }

        first_token_in_this_chunk
    }

    /// Get the final completion token count.
    ///
    /// Prefers the provider-reported count if available, otherwise uses
    /// the observed delta count.
    pub fn final_completion_tokens(&self) -> u32 {
        self.reported_usage
            .as_ref()
            .and_then(|u| u.completion_tokens)
            .unwrap_or(self.completion_token_count)
    }

    /// Get the provider-reported prompt token count, if available.
    pub fn prompt_tokens(&self) -> Option<u32> {
        self.reported_usage.as_ref().and_then(|u| u.prompt_tokens)
    }

    /// Get the provider-reported total token count, if available.
    pub fn total_tokens(&self) -> Option<u32> {
        self.reported_usage.as_ref().and_then(|u| u.total_tokens)
    }
}

impl Default for StreamingAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_sse_data_normal() {
        let line = r#"data: {"choices":[]}"#;
        assert_eq!(extract_sse_data(line), Some(r#"{"choices":[]}"#));
    }

    #[test]
    fn test_extract_sse_data_with_space() {
        let line = r#"data:  {"choices":[]}"#;
        assert_eq!(extract_sse_data(line), Some(r#"{"choices":[]}"#));
    }

    #[test]
    fn test_extract_sse_data_done() {
        assert_eq!(extract_sse_data("data: [DONE]"), None);
    }

    #[test]
    fn test_extract_sse_data_blank() {
        assert_eq!(extract_sse_data(""), None);
        assert_eq!(extract_sse_data("  "), None);
    }

    #[test]
    fn test_extract_sse_data_comment() {
        assert_eq!(extract_sse_data(": this is a comment"), None);
    }

    #[test]
    fn test_extract_sse_data_non_data_field() {
        assert_eq!(extract_sse_data("event: message"), None);
    }

    #[test]
    fn test_accumulator_single_chunk() {
        let mut acc = StreamingAccumulator::new();
        let chunk =
            b"data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"},\"finish_reason\":null}]}\n\n";
        let first = acc.process_chunk(chunk);
        assert!(first);
        assert_eq!(acc.content, "Hello");
        assert_eq!(acc.completion_token_count, 1);
        assert!(acc.first_token_received);
    }

    #[test]
    fn test_accumulator_multiple_chunks() {
        let mut acc = StreamingAccumulator::new();

        let chunk1 =
            b"data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"},\"finish_reason\":null}]}\n\n";
        let first1 = acc.process_chunk(chunk1);
        assert!(first1);

        let chunk2 = b"data: {\"choices\":[{\"delta\":{\"content\":\" world\"},\"finish_reason\":null}]}\n\n";
        let first2 = acc.process_chunk(chunk2);
        assert!(!first2); // not the first token anymore

        assert_eq!(acc.content, "Hello world");
        assert_eq!(acc.completion_token_count, 2);
    }

    #[test]
    fn test_accumulator_done_sentinel() {
        let mut acc = StreamingAccumulator::new();
        let chunk = b"data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"},\"finish_reason\":null}]}\n\ndata: [DONE]\n\n";
        acc.process_chunk(chunk);
        assert!(acc.done);
        assert_eq!(acc.content, "Hi");
    }

    #[test]
    fn test_accumulator_usage_in_final_chunk() {
        let mut acc = StreamingAccumulator::new();
        let chunk = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"total_tokens\":15}}\n\n",
            "data: [DONE]\n\n"
        );
        acc.process_chunk(chunk.as_bytes());

        assert_eq!(acc.final_completion_tokens(), 5); // prefers reported
        assert_eq!(acc.prompt_tokens(), Some(10));
        assert_eq!(acc.total_tokens(), Some(15));
        assert_eq!(acc.content, "Hi");
        assert!(acc.done);
    }

    #[test]
    fn test_accumulator_cross_boundary_line() {
        let mut acc = StreamingAccumulator::new();
        // Line split across two byte chunks
        let part1 = b"data: {\"choices\":[{\"delta\":{\"con";
        let part2 = b"tent\":\"Hi\"},\"finish_reason\":null}]}\n\n";
        let first1 = acc.process_chunk(part1);
        assert!(!first1); // no complete line yet
        let first2 = acc.process_chunk(part2);
        assert!(first2);
        assert_eq!(acc.content, "Hi");
    }

    #[test]
    fn test_accumulator_empty_delta() {
        let mut acc = StreamingAccumulator::new();
        // Role-only delta with no content
        let chunk = b"data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n\n";
        let first = acc.process_chunk(chunk);
        assert!(!first);
        assert!(acc.content.is_empty());
        assert_eq!(acc.completion_token_count, 0);
    }

    #[test]
    fn test_accumulator_no_usage_falls_back_to_count() {
        let mut acc = StreamingAccumulator::new();
        let chunk = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"a\"},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"b\"},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"c\"},\"finish_reason\":null}]}\n\n",
            "data: [DONE]\n\n"
        );
        acc.process_chunk(chunk.as_bytes());
        assert_eq!(acc.final_completion_tokens(), 3);
        assert_eq!(acc.prompt_tokens(), None);
    }

    #[test]
    fn test_accumulator_default() {
        let acc = StreamingAccumulator::default();
        assert!(acc.content.is_empty());
        assert!(!acc.first_token_received);
        assert!(!acc.done);
    }
}
