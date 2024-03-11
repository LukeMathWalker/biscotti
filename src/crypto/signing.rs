use crate::Key;
use anyhow::Context;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::digest::OutputSizeUser;
use hmac::{Hmac, Mac};
use sha2::Sha256;

#[derive(Clone, Copy)]
pub(crate) struct SigningKey([u8; 32]);

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SigningKey").field(&"***").finish()
    }
}

impl PartialEq for SigningKey {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;

        self.0.ct_eq(&other.0).into()
    }
}

impl SigningKey {
    /// Derives the HMAC-256 key from the master key.
    pub(crate) fn derive(key: &Key) -> Self {
        let mut derived = [0; 32];
        hkdf::Hkdf::<Sha256>::from_prk(key.master())
            .expect("Couldn't create HKDF from PRK")
            .expand(b"COOKIE;HMAC-SHA256", &mut derived)
            .expect("Failed to derive HMAC-SHA256 key from PRK");
        Self(derived)
    }

    /// Signs the cookie's value providing integrity and authenticity.
    pub(crate) fn sign(&self, name: &str, value: &str) -> String {
        // Compute HMAC-SHA256 of the cookie's value prepended with the cookie's name.
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("Key is too short");
        mac.update(name.as_bytes());
        mac.update(&[SEPARATOR]);
        mac.update(value.as_bytes());

        // Cookie's new value is [MAC | original-value].
        let mut new_value = Vec::with_capacity(Hmac::<Sha256>::output_size() + value.len());
        new_value.extend(mac.finalize().into_bytes());
        new_value.extend(value.as_bytes());
        BASE64_URL_SAFE_NO_PAD.encode(&new_value)
    }

    /// Given a signed value `str` where the signature is prepended to `value`,
    /// verifies the signed value and returns it. If there's a problem, returns
    /// an `Err` with a string describing the issue.
    pub(crate) fn verify(&self, name: &str, value: &str) -> Result<String, anyhow::Error> {
        let value = BASE64_URL_SAFE_NO_PAD
            .decode(value)
            .context("Failed to decode cookie value using base64 (URL-safe, no padding)")?;

        let digest_len = Hmac::<Sha256>::output_size();
        if value.len() <= digest_len {
            anyhow::bail!("The cookie value was too short to contain a MAC signature");
        }

        // Split [MAC | original-value] into its two parts.
        let (digest, value) = value.split_at(Hmac::<Sha256>::output_size());

        // Perform the verification.
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("Key is too short");
        mac.update(name.as_bytes());
        mac.update(&[SEPARATOR]);
        mac.update(value);
        mac.verify_slice(digest)
            .context("Failed to verify cookie value using HMAC")?;

        Ok(std::str::from_utf8(value)
            .context("Cookie value was not valid UTF-8")?
            .to_string())
    }
}

/// `0xFF` is not valid UTF8 (https://en.wikipedia.org/wiki/UTF-8#Invalid_sequences_and_error_handling).
/// Thus we can use it as a separator to ensure that there is no confusion as to where the cookie name ends
/// and the cookie value begins.
///
/// This prevents an attacker from taking a signed cookie, splitting `CONCAT(name, value)` at a different point than the
/// original and being able to reuse the original signature.
const SEPARATOR: u8 = 0;
