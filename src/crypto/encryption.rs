use aes_gcm::aead::{generic_array::GenericArray, Aead, AeadInPlace, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use anyhow::Context;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;

pub(crate) const NONCE_LEN: usize = 12;
pub(crate) const TAG_LEN: usize = 16;

/// Encrypts a cookie value using the given key.  
/// The encrypted value is tied to the cookie's name to prevent value swapping.
pub(crate) fn encrypt(name: &[u8], value: &[u8], key: &[u8]) -> String {
    // Create a vec to hold the [nonce | cookie value | tag].
    let mut data =
        vec![
            0;
            crate::crypto::encryption::NONCE_LEN + value.len() + crate::crypto::encryption::TAG_LEN
        ];

    // Split data into three: nonce, input/output, tag. Copy input.
    let (nonce, in_out) = data.split_at_mut(crate::crypto::encryption::NONCE_LEN);
    let (in_out, tag) = in_out.split_at_mut(value.len());
    in_out.copy_from_slice(value);

    // Fill nonce piece with random data.
    let mut rng = rand::thread_rng();
    rng.try_fill_bytes(nonce)
        .expect("couldn't random fill nonce");
    let nonce = GenericArray::clone_from_slice(nonce);

    // Perform the actual sealing operation, using the cookie's name as
    // associated data to prevent value swapping.
    let aad = name;
    let aead = Aes256Gcm::new(GenericArray::from_slice(key));
    let aad_tag = aead
        .encrypt_in_place_detached(&nonce, aad, in_out)
        .expect("encryption failed!");

    // Copy the tag into the tag piece.
    tag.copy_from_slice(&aad_tag);

    // Base64 encode [nonce | encrypted value | tag].
    BASE64_URL_SAFE_NO_PAD.encode(&data)
}

/// Decrypts a cookie value using the given key.
/// It requires the cookie name
/// since the encryption routine ties together the value with the name
/// to prevent value swapping.
pub(crate) fn decrypt(name: &[u8], value: &[u8], key: &[u8]) -> Result<String, anyhow::Error> {
    let data = BASE64_URL_SAFE_NO_PAD
        .decode(value)
        .context("Failed to decode cookie value using base64 (URL-safe, no padding)")?;
    if data.len() <= crate::crypto::encryption::NONCE_LEN {
        anyhow::bail!("The cookie value was too short to contain a nonce");
    }

    let (nonce, cipher) = data.split_at(crate::crypto::encryption::NONCE_LEN);
    let payload = Payload {
        msg: cipher,
        aad: name,
    };

    let aead = Aes256Gcm::new(GenericArray::from_slice(key));
    let s = aead
        .decrypt(GenericArray::from_slice(nonce), payload)
        .map_err(|_| anyhow::anyhow!("Failed to decrypt cookie value using AES-GCM"))?;
    String::from_utf8(s).context("Cookie value was not valid UTF-8")
}
