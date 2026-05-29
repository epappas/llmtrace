//! Authenticated encryption (AEAD) for secrets at rest.
//!
//! Encrypts per-tenant upstream provider credentials before they are written
//! to the metadata store. Uses AES-256-GCM (`aes-gcm` crate) with a random
//! 96-bit nonce per encryption. The wire format is base64(`nonce || ciphertext`)
//! where `ciphertext` already includes the GCM authentication tag.
//!
//! The master key is read from the `LLMTRACE_SECRET_ENCRYPTION_KEY` environment
//! variable. It must decode to exactly 32 bytes. Two encodings are accepted:
//! 64-char hex, or standard base64. Hex is tried first; base64 is the fallback.
//!
//! **Fail-closed contract:** if the master key is unset or invalid, [`SecretBox::from_env`]
//! returns an error. Callers that SET a per-tenant secret must surface that
//! error as a `400 Bad Request`. The proxy itself still boots and the global
//! credential fallback continues to work because decryption is only attempted
//! when a tenant actually has a stored ciphertext.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use rand::RngCore;

/// Environment variable holding the 32-byte master encryption key.
pub const SECRET_ENCRYPTION_KEY_ENV: &str = "LLMTRACE_SECRET_ENCRYPTION_KEY";

/// Required master key length in bytes (AES-256).
const KEY_LEN: usize = 32;

/// AES-GCM nonce length in bytes (96 bits, the standard for GCM).
const NONCE_LEN: usize = 12;

/// Errors raised by [`SecretBox`] operations.
#[derive(Debug, thiserror::Error)]
pub enum SecretBoxError {
    /// The master key env var is unset.
    #[error("{SECRET_ENCRYPTION_KEY_ENV} is not set")]
    KeyMissing,
    /// The master key could not be decoded to exactly 32 bytes.
    #[error(
        "{SECRET_ENCRYPTION_KEY_ENV} must decode to {KEY_LEN} bytes (64-char hex or base64); {0}"
    )]
    KeyInvalid(String),
    /// Encryption failed (should be infallible for valid inputs).
    #[error("encryption failed")]
    EncryptFailed,
    /// The stored ciphertext is malformed (bad base64 or too short).
    #[error("ciphertext is malformed: {0}")]
    CiphertextMalformed(String),
    /// Decryption/authentication failed (wrong key or tampered data).
    #[error("decryption failed: ciphertext could not be authenticated")]
    DecryptFailed,
}

/// An AEAD cipher bound to a 32-byte master key.
pub struct SecretBox {
    cipher: Aes256Gcm,
}

impl std::fmt::Debug for SecretBox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose key material in debug output.
        f.debug_struct("SecretBox").finish_non_exhaustive()
    }
}

impl SecretBox {
    /// Construct a [`SecretBox`] from the `LLMTRACE_SECRET_ENCRYPTION_KEY` env var.
    ///
    /// # Errors
    ///
    /// Returns [`SecretBoxError::KeyMissing`] when unset and
    /// [`SecretBoxError::KeyInvalid`] when it does not decode to 32 bytes.
    pub fn from_env() -> Result<Self, SecretBoxError> {
        let raw =
            std::env::var(SECRET_ENCRYPTION_KEY_ENV).map_err(|_| SecretBoxError::KeyMissing)?;
        Self::from_master_key_str(&raw)
    }

    /// Construct a [`SecretBox`] from a hex- or base64-encoded master key string.
    ///
    /// # Errors
    ///
    /// Returns [`SecretBoxError::KeyInvalid`] when the string does not decode to
    /// exactly 32 bytes under either encoding.
    pub fn from_master_key_str(raw: &str) -> Result<Self, SecretBoxError> {
        let key_bytes = decode_master_key(raw)?;
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        Ok(Self {
            cipher: Aes256Gcm::new(key),
        })
    }

    /// Encrypt `plaintext`, returning base64(`nonce || ciphertext`).
    ///
    /// A fresh random nonce is generated per call.
    ///
    /// # Errors
    ///
    /// Returns [`SecretBoxError::EncryptFailed`] if the underlying AEAD fails.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<String, SecretBoxError> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| SecretBoxError::EncryptFailed)?;

        let mut combined = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);
        Ok(BASE64.encode(combined))
    }

    /// Decrypt a base64(`nonce || ciphertext`) string back to plaintext bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SecretBoxError::CiphertextMalformed`] for bad base64 / short
    /// input and [`SecretBoxError::DecryptFailed`] when authentication fails.
    pub fn decrypt(&self, encoded: &str) -> Result<Vec<u8>, SecretBoxError> {
        let combined = BASE64
            .decode(encoded.as_bytes())
            .map_err(|e| SecretBoxError::CiphertextMalformed(e.to_string()))?;
        if combined.len() <= NONCE_LEN {
            return Err(SecretBoxError::CiphertextMalformed(
                "shorter than nonce".to_string(),
            ));
        }
        let (nonce_bytes, ciphertext) = combined.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| SecretBoxError::DecryptFailed)
    }
}

/// Decode a master key string (hex first, base64 fallback) into 32 bytes.
fn decode_master_key(raw: &str) -> Result<[u8; KEY_LEN], SecretBoxError> {
    let trimmed = raw.trim();
    // Try hex (exactly 64 chars => 32 bytes).
    if let Ok(bytes) = hex::decode(trimmed) {
        return to_key_array(bytes);
    }
    // Fall back to standard base64.
    if let Ok(bytes) = BASE64.decode(trimmed.as_bytes()) {
        return to_key_array(bytes);
    }
    Err(SecretBoxError::KeyInvalid(
        "not valid hex or base64".to_string(),
    ))
}

/// Convert a decoded byte vector to a fixed 32-byte array, or error.
fn to_key_array(bytes: Vec<u8>) -> Result<[u8; KEY_LEN], SecretBoxError> {
    let len = bytes.len();
    <[u8; KEY_LEN]>::try_from(bytes.as_slice())
        .map_err(|_| SecretBoxError::KeyInvalid(format!("decoded to {len} bytes, need {KEY_LEN}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid 32-byte key encoded as 64 hex chars.
    const HEX_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    fn box_from_hex() -> SecretBox {
        SecretBox::from_master_key_str(HEX_KEY).unwrap()
    }

    #[test]
    fn test_round_trip_hex_key() {
        let sb = box_from_hex();
        let secret = b"sk-super-secret-provider-key";
        let ct = sb.encrypt(secret).unwrap();
        let pt = sb.decrypt(&ct).unwrap();
        assert_eq!(pt, secret);
    }

    #[test]
    fn test_round_trip_base64_key() {
        // 32 zero bytes, base64-encoded.
        let b64_key = BASE64.encode([0u8; KEY_LEN]);
        let sb = SecretBox::from_master_key_str(&b64_key).unwrap();
        let secret = b"another-secret";
        let ct = sb.encrypt(secret).unwrap();
        assert_eq!(sb.decrypt(&ct).unwrap(), secret);
    }

    #[test]
    fn test_ciphertext_is_not_plaintext() {
        let sb = box_from_hex();
        let secret = b"do-not-leak";
        let ct = sb.encrypt(secret).unwrap();
        assert!(!ct.as_bytes().windows(secret.len()).any(|w| w == secret));
    }

    #[test]
    fn test_nonce_is_random_per_encryption() {
        let sb = box_from_hex();
        let secret = b"same-input";
        let a = sb.encrypt(secret).unwrap();
        let b = sb.encrypt(secret).unwrap();
        assert_ne!(a, b, "two encryptions of the same plaintext must differ");
    }

    #[test]
    fn test_wrong_key_fails_to_decrypt() {
        let sb = box_from_hex();
        let ct = sb.encrypt(b"secret").unwrap();
        let other = SecretBox::from_master_key_str(&BASE64.encode([0xAAu8; KEY_LEN])).unwrap();
        assert!(matches!(
            other.decrypt(&ct),
            Err(SecretBoxError::DecryptFailed)
        ));
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let sb = box_from_hex();
        let ct = sb.encrypt(b"secret").unwrap();
        let mut bytes = BASE64.decode(ct.as_bytes()).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        let tampered = BASE64.encode(bytes);
        assert!(matches!(
            sb.decrypt(&tampered),
            Err(SecretBoxError::DecryptFailed)
        ));
    }

    #[test]
    fn test_short_key_rejected() {
        // 16 bytes hex => too short.
        let err = SecretBox::from_master_key_str("00112233445566778899aabbccddeeff").unwrap_err();
        assert!(matches!(err, SecretBoxError::KeyInvalid(_)));
    }

    #[test]
    fn test_garbage_key_rejected() {
        let err = SecretBox::from_master_key_str("not-a-key!!!").unwrap_err();
        assert!(matches!(err, SecretBoxError::KeyInvalid(_)));
    }

    #[test]
    fn test_malformed_ciphertext_rejected() {
        let sb = box_from_hex();
        assert!(matches!(
            sb.decrypt("not-base64-???"),
            Err(SecretBoxError::CiphertextMalformed(_))
        ));
        // Valid base64 but too short to contain a nonce.
        let short = BASE64.encode([0u8; 4]);
        assert!(matches!(
            sb.decrypt(&short),
            Err(SecretBoxError::CiphertextMalformed(_))
        ));
    }
}
