//! PII checksum validation to reduce false positives.
//!
//! This module provides validation functions for PII patterns that have
//! well-defined checksum or structural validation rules:
//!
//! - **Credit card numbers**: Luhn algorithm (ISO/IEC 7812)
//! - **IBAN**: MOD-97 check (ISO 7064 / ISO 13616)
//! - **US SSN**: Area number validation (no 000, 666, or 900-999)
//!
//! These validators are called after a regex match to confirm that the matched
//! text is structurally valid. Invalid matches are downgraded or suppressed,
//! significantly reducing false positive rates.

/// Validate a credit card number using the Luhn algorithm.
///
/// Strips spaces and dashes, then checks:
/// 1. All remaining characters are digits
/// 2. The digit count is between 13 and 19 (standard card lengths)
/// 3. The Luhn checksum passes
///
/// # Examples
///
/// ```
/// use llmtrace_security::pii_validation::validate_credit_card;
///
/// assert!(validate_credit_card("4111 1111 1111 1111")); // Valid Visa test
/// assert!(!validate_credit_card("4111 1111 1111 1112")); // Invalid checksum
/// ```
pub fn validate_credit_card(input: &str) -> bool {
    let digits: Vec<u32> = input
        .chars()
        .filter(|c| !matches!(c, ' ' | '-'))
        .map(|c| c.to_digit(10))
        .collect::<Option<Vec<_>>>()
        .unwrap_or_default();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    luhn_check(&digits)
}

/// Perform the Luhn checksum validation on a slice of digits.
///
/// The algorithm:
/// 1. Starting from the rightmost digit, double every second digit
/// 2. If doubling results in a value > 9, subtract 9
/// 3. Sum all digits
/// 4. If the total modulo 10 is 0, the number is valid
fn luhn_check(digits: &[u32]) -> bool {
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 {
                    doubled - 9
                } else {
                    doubled
                }
            } else {
                d
            }
        })
        .sum();

    sum.is_multiple_of(10)
}

/// Validate an IBAN using the MOD-97 check (ISO 7064 / ISO 13616).
///
/// Steps:
/// 1. Strip spaces
/// 2. Check minimum length (≥ 15) and that it starts with 2 letters + 2 digits
/// 3. Move the first 4 characters to the end
/// 4. Replace letters with numbers (A=10, B=11, ..., Z=35)
/// 5. Compute the remainder when dividing by 97; valid if remainder == 1
///
/// # Examples
///
/// ```
/// use llmtrace_security::pii_validation::validate_iban;
///
/// assert!(validate_iban("DE89 3704 0044 0532 0130 00")); // Valid German IBAN
/// assert!(validate_iban("GB29 NWBK 6016 1331 9268 19")); // Valid UK IBAN
/// assert!(!validate_iban("DE00 0000 0000 0000 0000 00")); // Invalid
/// ```
pub fn validate_iban(input: &str) -> bool {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_uppercase();

    // Minimum IBAN length is 15 (Norway), max is 34
    if cleaned.len() < 15 || cleaned.len() > 34 {
        return false;
    }

    // First 2 chars must be letters, next 2 must be digits
    let chars: Vec<char> = cleaned.chars().collect();
    if !chars[0].is_ascii_alphabetic()
        || !chars[1].is_ascii_alphabetic()
        || !chars[2].is_ascii_digit()
        || !chars[3].is_ascii_digit()
    {
        return false;
    }

    // Move first 4 characters to end
    let rearranged = format!("{}{}", &cleaned[4..], &cleaned[..4]);

    // Convert letters to numbers (A=10, B=11, ..., Z=35)
    let numeric_str: String = rearranged
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let val = (c as u32) - ('A' as u32) + 10;
                val.to_string()
            } else {
                c.to_string()
            }
        })
        .collect();

    // Compute MOD 97 using iterative approach (handles large numbers)
    let remainder = mod97(&numeric_str);
    remainder == 1
}

/// Compute number MOD 97 for a large numeric string, using iterative chunking.
fn mod97(numeric_str: &str) -> u64 {
    let mut remainder: u64 = 0;
    for chunk in numeric_str.as_bytes().chunks(9) {
        let chunk_str = std::str::from_utf8(chunk).unwrap_or("0");
        let combined = format!("{}{}", remainder, chunk_str);
        remainder = combined.parse::<u64>().unwrap_or(0) % 97;
    }
    remainder
}

/// Validate a US Social Security Number by area number rules.
///
/// After extracting the 3-digit area number (first 3 digits), checks that:
/// - Area number is not 000
/// - Area number is not 666
/// - Area number is not in range 900-999
/// - Group number (middle 2 digits) is not 00
/// - Serial number (last 4 digits) is not 0000
///
/// # Examples
///
/// ```
/// use llmtrace_security::pii_validation::validate_ssn;
///
/// assert!(validate_ssn("456-78-9012"));   // Valid
/// assert!(!validate_ssn("000-12-3456"));  // Invalid: area 000
/// assert!(!validate_ssn("666-12-3456"));  // Invalid: area 666
/// assert!(!validate_ssn("900-12-3456"));  // Invalid: area 900+
/// assert!(!validate_ssn("123-00-4567"));  // Invalid: group 00
/// assert!(!validate_ssn("123-45-0000"));  // Invalid: serial 0000
/// ```
pub fn validate_ssn(input: &str) -> bool {
    let digits: String = input.chars().filter(|c| c.is_ascii_digit()).collect();

    if digits.len() != 9 {
        return false;
    }

    let area: u32 = digits[0..3].parse().unwrap_or(0);
    let group: u32 = digits[3..5].parse().unwrap_or(0);
    let serial: u32 = digits[5..9].parse().unwrap_or(0);

    // Area cannot be 000, 666, or 900-999
    if area == 0 || area == 666 || area >= 900 {
        return false;
    }

    // Group cannot be 00
    if group == 0 {
        return false;
    }

    // Serial cannot be 0000
    if serial == 0 {
        return false;
    }

    true
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Credit card (Luhn) tests ------------------------------------------

    #[test]
    fn test_valid_visa_test_card() {
        assert!(validate_credit_card("4111 1111 1111 1111"));
    }

    #[test]
    fn test_valid_visa_no_spaces() {
        assert!(validate_credit_card("4111111111111111"));
    }

    #[test]
    fn test_valid_visa_with_dashes() {
        assert!(validate_credit_card("4111-1111-1111-1111"));
    }

    #[test]
    fn test_valid_mastercard_test() {
        assert!(validate_credit_card("5500 0000 0000 0004"));
    }

    #[test]
    fn test_valid_amex_test() {
        // Amex is 15 digits
        assert!(validate_credit_card("3782 822463 10005"));
    }

    #[test]
    fn test_invalid_checksum() {
        assert!(!validate_credit_card("4111 1111 1111 1112"));
    }

    #[test]
    fn test_invalid_too_short() {
        assert!(!validate_credit_card("411111111111"));
    }

    #[test]
    fn test_invalid_too_long() {
        assert!(!validate_credit_card("41111111111111111111"));
    }

    #[test]
    fn test_invalid_non_digits() {
        assert!(!validate_credit_card("4111-ABCD-1111-1111"));
    }

    #[test]
    fn test_invalid_all_zeros() {
        // All zeros technically passes Luhn (0 mod 10 = 0) but is not a real card.
        // Our validator allows it since Luhn is the defined check; the regex
        // false-positive suppression in lib.rs handles all-zero cards separately.
        // Here we just verify Luhn returns true for all zeros.
        assert!(validate_credit_card("0000 0000 0000 0000"));
    }

    #[test]
    fn test_valid_discover() {
        assert!(validate_credit_card("6011 1111 1111 1117"));
    }

    // -- IBAN tests --------------------------------------------------------

    #[test]
    fn test_valid_german_iban() {
        assert!(validate_iban("DE89 3704 0044 0532 0130 00"));
    }

    #[test]
    fn test_valid_german_iban_no_spaces() {
        assert!(validate_iban("DE89370400440532013000"));
    }

    #[test]
    fn test_valid_uk_iban() {
        assert!(validate_iban("GB29 NWBK 6016 1331 9268 19"));
    }

    #[test]
    fn test_valid_french_iban() {
        assert!(validate_iban("FR76 3000 6000 0112 3456 7890 189"));
    }

    #[test]
    fn test_valid_spanish_iban() {
        assert!(validate_iban("ES91 2100 0418 4502 0005 1332"));
    }

    #[test]
    fn test_valid_italian_iban() {
        assert!(validate_iban("IT60 X054 2811 1010 0000 0123 456"));
    }

    #[test]
    fn test_invalid_iban_bad_checksum() {
        assert!(!validate_iban("DE00 3704 0044 0532 0130 00"));
    }

    #[test]
    fn test_invalid_iban_too_short() {
        assert!(!validate_iban("DE89 3704 0044"));
    }

    #[test]
    fn test_invalid_iban_no_letter_prefix() {
        assert!(!validate_iban("1234 5678 9012 3456"));
    }

    #[test]
    fn test_iban_case_insensitive() {
        assert!(validate_iban("gb29 nwbk 6016 1331 9268 19"));
    }

    // -- SSN tests ---------------------------------------------------------

    #[test]
    fn test_valid_ssn() {
        assert!(validate_ssn("456-78-9012"));
    }

    #[test]
    fn test_valid_ssn_no_dashes() {
        assert!(validate_ssn("456789012"));
    }

    #[test]
    fn test_invalid_ssn_area_000() {
        assert!(!validate_ssn("000-12-3456"));
    }

    #[test]
    fn test_invalid_ssn_area_666() {
        assert!(!validate_ssn("666-12-3456"));
    }

    #[test]
    fn test_invalid_ssn_area_900() {
        assert!(!validate_ssn("900-12-3456"));
    }

    #[test]
    fn test_invalid_ssn_area_999() {
        assert!(!validate_ssn("999-12-3456"));
    }

    #[test]
    fn test_invalid_ssn_group_00() {
        assert!(!validate_ssn("123-00-4567"));
    }

    #[test]
    fn test_invalid_ssn_serial_0000() {
        assert!(!validate_ssn("123-45-0000"));
    }

    #[test]
    fn test_valid_ssn_boundary_area_001() {
        assert!(validate_ssn("001-01-0001"));
    }

    #[test]
    fn test_valid_ssn_boundary_area_899() {
        assert!(validate_ssn("899-99-9999"));
    }

    #[test]
    fn test_invalid_ssn_wrong_length() {
        assert!(!validate_ssn("12-34-5678"));
    }
}
