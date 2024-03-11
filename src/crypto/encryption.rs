use crate::Key;
use aes_gcm_siv::aead::consts::U32;
use aes_gcm_siv::aead::generic_array::GenericArray;
use aes_gcm_siv::aead::{Aead, Payload};
use aes_gcm_siv::{AeadInPlace, Aes256GcmSiv, KeyInit};
use anyhow::Context;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use sha2::Sha256;

pub(crate) const NONCE_LEN: usize = 12;
pub(crate) const TAG_LEN: usize = 16;

#[derive(Clone, Copy)]
pub(crate) struct EncryptionKey(GenericArray<u8, U32>);

impl std::fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("EncryptionKey").field(&"***").finish()
    }
}

impl PartialEq for EncryptionKey {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;

        self.0.ct_eq(&other.0).into()
    }
}

impl EncryptionKey {
    /// Derives the AES-GCM-SIV key from the master key.
    pub(crate) fn derive(key: &Key) -> Self {
        let mut derived = [0; 32];
        hkdf::Hkdf::<Sha256>::from_prk(key.master())
            .expect("Couldn't create HKDF from PRK")
            .expand(b"COOKIE;AEAD-AES-256-GCM-SIV", &mut derived)
            .expect("Failed to derive AEAD-AES-256-GCM-SIV key from PRK");
        Self(GenericArray::from(derived))
    }

    /// Encrypts a cookie value using the given key.  
    /// The encrypted value is tied to the cookie's name to prevent value swapping.
    pub(crate) fn encrypt(&self, name: &[u8], value: &[u8]) -> String {
        // Create a vec to hold the [nonce | cookie value | tag].
        let mut data = vec![0; NONCE_LEN + value.len() + TAG_LEN];

        // Split data into three: nonce, input/output, tag. Copy input.
        let (nonce, in_out) = data.split_at_mut(NONCE_LEN);
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
        let aead = Aes256GcmSiv::new(&self.0);
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
    pub(crate) fn decrypt(&self, name: &[u8], value: &[u8]) -> Result<String, anyhow::Error> {
        let data = BASE64_URL_SAFE_NO_PAD
            .decode(value)
            .context("Failed to decode cookie value using base64 (URL-safe, no padding)")?;
        if data.len() <= NONCE_LEN {
            anyhow::bail!("The cookie value was too short to contain a nonce");
        }

        let (nonce, cipher) = data.split_at(NONCE_LEN);
        let payload = Payload {
            msg: cipher,
            aad: name,
        };

        let aead = Aes256GcmSiv::new(&self.0);
        let s = aead
            .decrypt(GenericArray::from_slice(nonce), payload)
            .map_err(|_| anyhow::anyhow!("Failed to decrypt cookie value using AES-GCM"))?;
        String::from_utf8(s).context("Cookie value was not valid UTF-8")
    }
}
