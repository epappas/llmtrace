//! Unicode normalisation layer for security analysis.
//!
//! This module provides text normalisation as a preprocessing step before all
//! security analysis. It applies NFKC normalisation, strips zero-width and
//! invisible Unicode characters, and maps common homoglyphs to their ASCII
//! equivalents.
//!
//! # Why?
//!
//! Attackers can bypass regex-based detection by using visually identical but
//! distinct Unicode code points — for example, Cyrillic `а` (U+0430) instead
//! of Latin `a` (U+0061), or embedding zero-width characters inside keywords.
//! Normalising text before analysis neutralises these evasion techniques.

use unicode_normalization::UnicodeNormalization;

/// Characters that are zero-width or invisible and should be stripped.
const ZERO_WIDTH_CHARS: &[char] = &[
    '\u{200B}', // Zero-width space
    '\u{200C}', // Zero-width non-joiner
    '\u{200D}', // Zero-width joiner
    '\u{FEFF}', // BOM / zero-width no-break space
    '\u{00AD}', // Soft hyphen
    '\u{2060}', // Word joiner
    '\u{2028}', // Line separator
    '\u{2029}', // Paragraph separator
    // Bidirectional control characters (U+202A-U+202E)
    '\u{202A}', // Left-to-right embedding
    '\u{202B}', // Right-to-left embedding
    '\u{202C}', // Pop directional formatting
    '\u{202D}', // Left-to-right override
    '\u{202E}', // Right-to-left override
    // Bidirectional isolate characters (U+2066-U+2069)
    '\u{2066}', // Left-to-right isolate
    '\u{2067}', // Right-to-left isolate
    '\u{2068}', // First strong isolate
    '\u{2069}', // Pop directional isolate
];

/// Normalise text for security analysis.
///
/// This function:
/// 1. Applies Unicode NFKC normalisation (compatibility decomposition + canonical composition)
/// 2. Strips zero-width and invisible characters
/// 3. Maps common homoglyphs (e.g., Cyrillic letters that look like Latin) to ASCII
///
/// # Examples
///
/// ```
/// use llmtrace_security::normalise::normalise_text;
///
/// // NFKC normalisation: fullwidth "Ａ" → "A"
/// assert_eq!(normalise_text("\u{FF21}"), "A");
///
/// // Zero-width stripping
/// assert_eq!(normalise_text("he\u{200B}llo"), "hello");
///
/// // Homoglyph mapping: Cyrillic "а" → Latin "a"
/// assert_eq!(normalise_text("\u{0430}"), "a");
/// ```
pub fn normalise_text(input: &str) -> String {
    // Step 1: NFKC normalisation
    let nfkc: String = input.nfkc().collect();

    // Step 2: Strip zero-width and invisible characters
    let stripped: String = nfkc
        .chars()
        .filter(|c| !ZERO_WIDTH_CHARS.contains(c))
        .collect();

    // Step 3: Map homoglyphs to ASCII equivalents
    let mapped: String = stripped.chars().map(map_homoglyph).collect();

    mapped
}

/// Map a single character to its ASCII equivalent if it is a known homoglyph.
///
/// Covers the most common Cyrillic-to-Latin confusables, Greek confusables,
/// and a few other visually identical characters used in homoglyph attacks.
fn map_homoglyph(c: char) -> char {
    match c {
        // Cyrillic → Latin (lowercase)
        '\u{0430}' => 'a', // Cyrillic а
        '\u{0435}' => 'e', // Cyrillic е
        '\u{043E}' => 'o', // Cyrillic о
        '\u{0440}' => 'p', // Cyrillic р
        '\u{0441}' => 'c', // Cyrillic с
        '\u{0445}' => 'x', // Cyrillic х
        '\u{0443}' => 'y', // Cyrillic у
        '\u{0456}' => 'i', // Cyrillic і (Ukrainian i)
        '\u{0458}' => 'j', // Cyrillic ј
        '\u{04BB}' => 'h', // Cyrillic һ

        // Cyrillic → Latin (uppercase)
        '\u{0410}' => 'A', // Cyrillic А
        '\u{0412}' => 'B', // Cyrillic В
        '\u{0415}' => 'E', // Cyrillic Е
        '\u{041A}' => 'K', // Cyrillic К
        '\u{041C}' => 'M', // Cyrillic М
        '\u{041D}' => 'H', // Cyrillic Н
        '\u{041E}' => 'O', // Cyrillic О
        '\u{0420}' => 'P', // Cyrillic Р
        '\u{0421}' => 'C', // Cyrillic С
        '\u{0422}' => 'T', // Cyrillic Т
        '\u{0425}' => 'X', // Cyrillic Х

        // Greek → Latin
        '\u{03BF}' => 'o', // Greek omicron ο
        '\u{03B1}' => 'a', // Greek alpha α (after NFKC, still distinct)
        '\u{0391}' => 'A', // Greek Alpha Α
        '\u{0392}' => 'B', // Greek Beta Β
        '\u{0395}' => 'E', // Greek Epsilon Ε
        '\u{0396}' => 'Z', // Greek Zeta Ζ
        '\u{0397}' => 'H', // Greek Eta Η
        '\u{0399}' => 'I', // Greek Iota Ι
        '\u{039A}' => 'K', // Greek Kappa Κ
        '\u{039C}' => 'M', // Greek Mu Μ
        '\u{039D}' => 'N', // Greek Nu Ν
        '\u{039F}' => 'O', // Greek Omicron Ο
        '\u{03A1}' => 'P', // Greek Rho Ρ
        '\u{03A4}' => 'T', // Greek Tau Τ
        '\u{03A5}' => 'Y', // Greek Upsilon Υ
        '\u{03A7}' => 'X', // Greek Chi Χ

        _ => c,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- NFKC normalisation ------------------------------------------------

    #[test]
    fn test_nfkc_fullwidth_to_ascii() {
        // Fullwidth "ＨＥＬＬＯ" → "HELLO"
        assert_eq!(
            normalise_text("\u{FF28}\u{FF25}\u{FF2C}\u{FF2C}\u{FF2F}"),
            "HELLO"
        );
    }

    #[test]
    fn test_nfkc_superscript_digits() {
        // Superscript "²" → "2"
        assert_eq!(normalise_text("\u{00B2}"), "2");
    }

    #[test]
    fn test_nfkc_ligature_fi() {
        // Ligature "ﬁ" → "fi"
        assert_eq!(normalise_text("\u{FB01}"), "fi");
    }

    #[test]
    fn test_nfkc_roman_numeral() {
        // Roman numeral Ⅳ (U+2163) → "IV"
        assert_eq!(normalise_text("\u{2163}"), "IV");
    }

    #[test]
    fn test_nfkc_preserves_normal_ascii() {
        let text = "Hello, world! 123";
        assert_eq!(normalise_text(text), text);
    }

    // -- Zero-width character stripping ------------------------------------

    #[test]
    fn test_strip_zero_width_space() {
        assert_eq!(normalise_text("ig\u{200B}nore"), "ignore");
    }

    #[test]
    fn test_strip_zero_width_non_joiner() {
        assert_eq!(normalise_text("in\u{200C}structions"), "instructions");
    }

    #[test]
    fn test_strip_zero_width_joiner() {
        assert_eq!(normalise_text("pr\u{200D}ompt"), "prompt");
    }

    #[test]
    fn test_strip_bom() {
        assert_eq!(normalise_text("\u{FEFF}hello"), "hello");
    }

    #[test]
    fn test_strip_soft_hyphen() {
        assert_eq!(normalise_text("ig\u{00AD}nore"), "ignore");
    }

    #[test]
    fn test_strip_word_joiner() {
        assert_eq!(normalise_text("sys\u{2060}tem"), "system");
    }

    #[test]
    fn test_strip_line_separator() {
        assert_eq!(normalise_text("a\u{2028}b"), "ab");
    }

    #[test]
    fn test_strip_paragraph_separator() {
        assert_eq!(normalise_text("a\u{2029}b"), "ab");
    }

    #[test]
    fn test_strip_bidi_controls() {
        let input = "\u{202A}system\u{202C}: override\u{202E}";
        assert_eq!(normalise_text(input), "system: override");
    }

    #[test]
    fn test_strip_bidi_isolates() {
        let input = "\u{2066}ignore\u{2069} previous";
        assert_eq!(normalise_text(input), "ignore previous");
    }

    #[test]
    fn test_strip_multiple_zero_width_in_keyword() {
        // "i\u{200B}g\u{200C}n\u{200D}o\u{FEFF}re" → "ignore"
        assert_eq!(
            normalise_text("i\u{200B}g\u{200C}n\u{200D}o\u{FEFF}re"),
            "ignore"
        );
    }

    // -- Homoglyph mapping --------------------------------------------------

    #[test]
    fn test_cyrillic_a_to_latin_a() {
        assert_eq!(normalise_text("\u{0430}"), "a");
    }

    #[test]
    fn test_cyrillic_e_to_latin_e() {
        assert_eq!(normalise_text("\u{0435}"), "e");
    }

    #[test]
    fn test_cyrillic_o_to_latin_o() {
        assert_eq!(normalise_text("\u{043E}"), "o");
    }

    #[test]
    fn test_cyrillic_p_to_latin_p() {
        assert_eq!(normalise_text("\u{0440}"), "p");
    }

    #[test]
    fn test_cyrillic_c_to_latin_c() {
        assert_eq!(normalise_text("\u{0441}"), "c");
    }

    #[test]
    fn test_mixed_script_homoglyph_attack() {
        // "ignоre" with Cyrillic о (U+043E) → "ignore" with Latin o
        let malicious = "ign\u{043E}re";
        assert_eq!(normalise_text(malicious), "ignore");
    }

    #[test]
    fn test_full_cyrillic_word_looks_like_ignore() {
        // Cyrillic: і + g + n + о + r + е
        let malicious = "\u{0456}gnor\u{0435}";
        assert_eq!(normalise_text(malicious), "ignore");
    }

    #[test]
    fn test_cyrillic_uppercase_confusables() {
        // Cyrillic А, С, Е, О, Р → Latin A, C, E, O, P
        let text = "\u{0410}\u{0421}\u{0415}\u{041E}\u{0420}";
        assert_eq!(normalise_text(text), "ACEOP");
    }

    #[test]
    fn test_greek_omicron_to_latin_o() {
        assert_eq!(normalise_text("\u{03BF}"), "o");
    }

    #[test]
    fn test_greek_uppercase_confusables() {
        // Greek Α, Β, Ε → Latin A, B, E
        let text = "\u{0391}\u{0392}\u{0395}";
        assert_eq!(normalise_text(text), "ABE");
    }

    // -- Combined attacks --------------------------------------------------

    #[test]
    fn test_combined_zero_width_and_homoglyph() {
        // "ign\u{200B}\u{043E}re" — zero-width space + Cyrillic о
        let malicious = "ign\u{200B}\u{043E}re";
        assert_eq!(normalise_text(malicious), "ignore");
    }

    #[test]
    fn test_combined_fullwidth_and_zero_width() {
        // Fullwidth "Ｓ" + zero-width + "ystem"
        let malicious = "\u{FF33}\u{200B}ystem";
        assert_eq!(normalise_text(malicious), "System");
    }

    #[test]
    fn test_realistic_evasion_ignore_previous_instructions() {
        // Attacker uses: Cyrillic і, zero-width space, Cyrillic о
        let evasion = "\u{0456}gn\u{200B}\u{043E}re previ\u{043E}us instructi\u{043E}ns";
        let normalised = normalise_text(evasion);
        assert_eq!(normalised, "ignore previous instructions");
    }

    #[test]
    fn test_empty_string() {
        assert_eq!(normalise_text(""), "");
    }

    #[test]
    fn test_only_zero_width_chars() {
        assert_eq!(normalise_text("\u{200B}\u{200C}\u{200D}\u{FEFF}"), "");
    }

    #[test]
    fn test_preserves_normal_unicode() {
        // CJK, emoji, etc. should pass through unchanged
        let text = "你好世界 🌍";
        assert_eq!(normalise_text(text), text);
    }

    #[test]
    fn test_preserves_accented_latin() {
        // Accented characters that are NOT homoglyphs should be preserved
        // (after NFKC, composed forms are used)
        let text = "café résumé naïve";
        let result = normalise_text(text);
        assert!(result.contains("café"));
        assert!(result.contains("résumé"));
    }
}
