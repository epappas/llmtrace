//! UTF-8-safe string truncation used when including backend-returned
//! bodies in error messages. Keeps error payloads bounded so a huge
//! response body does not balloon the error string.

/// Truncate `s` to at most `max` bytes, respecting UTF-8 character
/// boundaries, and append a trailing marker when truncation occurred.
#[must_use]
pub fn truncate_for_error(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}... [truncated]", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_string_unchanged() {
        assert_eq!(truncate_for_error("hello", 64), "hello");
    }

    #[test]
    fn long_ascii_truncates_with_marker() {
        let s = "a".repeat(100);
        let out = truncate_for_error(&s, 10);
        assert!(out.starts_with("aaaaaaaaaa"));
        assert!(out.contains("[truncated]"));
    }

    #[test]
    fn truncation_respects_utf8_boundary() {
        // 3-byte chars; truncating mid-char would panic without the
        // boundary walk.
        let s = "\u{1F600}\u{1F600}\u{1F600}";
        let out = truncate_for_error(s, 5);
        // Should cut at the boundary between emojis (byte 4) and append marker.
        assert!(out.contains("[truncated]"));
        assert!(out.starts_with('\u{1F600}'));
    }
}
