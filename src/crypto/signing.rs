use anyhow::Context;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::digest::OutputSizeUser;
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub(crate) fn sign(name: &[u8], value: &str, key: &[u8]) -> String {
    // Compute HMAC-SHA256 of the cookie's value prepended with the cookie's name.
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("good key");
    mac.update(name);
    mac.update(value.as_bytes());

    // Cookie's new value is [MAC | original-value].
    let mut new_value = Vec::with_capacity(Hmac::<Sha256>::output_size() + value.len());
    new_value.extend(mac.finalize().into_bytes());
    new_value.extend(value.as_bytes());
    BASE64_URL_SAFE_NO_PAD.encode(&new_value)
}

pub(crate) fn verify(name: &[u8], value: &str, key: &[u8]) -> Result<String, anyhow::Error> {
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
    let mut mac = Hmac::<Sha256>::new_from_slice(key).context("Invalid signing key")?;
    mac.update(name);
    mac.update(value);
    mac.verify_slice(digest)
        .context("Failed to verify cookie value using HMAC")?;

    Ok(std::str::from_utf8(value)
        .context("Cookie value was not valid UTF-8")?
        .to_string())
}
