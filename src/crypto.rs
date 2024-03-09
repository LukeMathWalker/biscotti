use rand::RngCore;
use std::convert::TryFrom;
use std::hash::Hash;

const SIGNING_KEY_LEN: usize = 32;
const ENCRYPTION_KEY_LEN: usize = 32;
const COMBINED_KEY_LENGTH: usize = SIGNING_KEY_LEN + ENCRYPTION_KEY_LEN;

/// A cryptographic master key to sign or encrypt cookies.
#[allow(clippy::derived_hash_with_manual_eq)]
#[derive(Clone, Eq, Hash)]
pub struct Key([u8; COMBINED_KEY_LENGTH]);

mod deser {
    use crate::Key;
    use serde::Deserializer;

    impl<'de> serde::Deserialize<'de> for Key {
        fn deserialize<D>(deserializer: D) -> Result<Key, D::Error>
        where
            D: Deserializer<'de>,
        {
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            let key = Key::try_from(bytes.as_ref()).map_err(serde::de::Error::custom)?;
            Ok(key)
        }
    }
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;

        self.0.ct_eq(&other.0).into()
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key").finish()
    }
}

impl Key {
    // An empty key structure, to be filled.
    const fn zero() -> Self {
        Key([0; COMBINED_KEY_LENGTH])
    }

    /// Creates a new [`Key`] from a 512-bit cryptographically random string.
    ///
    /// The supplied key must be at least 512-bits (64 bytes). For security, the
    /// master key _must_ be cryptographically random.
    ///
    /// # Panics
    ///
    /// Panics if `key` is less than 64 bytes in length.
    ///
    /// For a non-panicking version, use [`Key::try_from()`] or generate a key with
    /// [`Key::generate()`] or [`Key::try_generate()`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::Key;
    ///
    /// # /*
    /// let key = { /* a cryptographically random key >= 64 bytes */ };
    /// # */
    /// # let key: &Vec<u8> = &(0..64).collect();
    ///
    /// let key = Key::from(key);
    /// ```
    #[inline]
    pub fn from(key: &[u8]) -> Key {
        Key::try_from(key).unwrap()
    }

    /// Generates signing/encryption keys from a secure, random source. Keys are
    /// generated nondeterministically.
    ///
    /// # Panics
    ///
    /// Panics if randomness cannot be retrieved from the operating system. See
    /// [`Key::try_generate()`] for a non-panicking version.
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::Key;
    ///
    /// let key = Key::generate();
    /// ```
    pub fn generate() -> Key {
        Self::try_generate().expect("failed to generate `Key` from randomness")
    }

    /// Attempts to generate signing/encryption keys from a secure, random
    /// source. Keys are generated nondeterministically. If randomness cannot be
    /// retrieved from the underlying operating system, returns `None`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::Key;
    ///
    /// let key = Key::try_generate();
    /// ```
    pub fn try_generate() -> Option<Key> {
        let mut rng = rand::thread_rng();
        let mut key = Key::zero();
        rng.try_fill_bytes(&mut key.0).ok()?;
        Some(key)
    }

    /// Returns the raw bytes of a key suitable for signing cookies. Guaranteed
    /// to be at least 32 bytes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::Key;
    ///
    /// let key = Key::generate();
    /// let signing_key = key.signing();
    /// ```
    pub fn signing(&self) -> &[u8] {
        &self.0[..SIGNING_KEY_LEN]
    }

    /// Returns the raw bytes of a key suitable for encrypting cookies.
    /// Guaranteed to be at least 32 bytes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::Key;
    ///
    /// let key = Key::generate();
    /// let encryption_key = key.encryption();
    /// ```
    pub fn encryption(&self) -> &[u8] {
        &self.0[SIGNING_KEY_LEN..]
    }

    /// Returns the raw bytes of the master key. Guaranteed to be at least 64
    /// bytes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::Key;
    ///
    /// let key = Key::generate();
    /// let master_key = key.master();
    /// ```
    pub fn master(&self) -> &[u8] {
        &self.0
    }
}

/// The error returned by [`Key::try_from()`] when trying to create a [`Key`] from raw bytes.
#[derive(Debug)]
#[non_exhaustive]
pub enum KeyError {
    /// Too few bytes were provided to generate a key.
    ///
    /// See [`Key::from()`] for minimum requirements.
    TooShort {
        /// The number of bytes provided.
        length: usize,
    },
}

impl std::error::Error for KeyError {}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::TooShort { length: n } => {
                write!(
                    f,
                    "key material is too short: expected >= {} bytes, got {} bytes",
                    COMBINED_KEY_LENGTH, n
                )
            }
        }
    }
}

impl TryFrom<&[u8]> for Key {
    type Error = KeyError;

    /// A fallible version of [`Key::from()`].
    ///
    /// Succeeds when [`Key::from()`] succeds and returns an error where
    /// [`Key::from()`] panics, namely, if `key` is too short.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use std::convert::TryFrom;
    /// use biscotti::Key;
    ///
    /// # /*
    /// let key = { /* a cryptographically random key >= 64 bytes */ };
    /// # */
    /// # let key: &Vec<u8> = &(0..64).collect();
    /// # let key: &[u8] = &key[..];
    /// assert!(Key::try_from(key).is_ok());
    ///
    /// // A key that's far too short to use.
    /// let key = &[1, 2, 3, 4][..];
    /// assert!(Key::try_from(key).is_err());
    /// ```
    fn try_from(key: &[u8]) -> Result<Self, Self::Error> {
        if key.len() < COMBINED_KEY_LENGTH {
            Err(KeyError::TooShort { length: key.len() })
        } else {
            let mut output = Key::zero();
            output.0.copy_from_slice(&key[..COMBINED_KEY_LENGTH]);
            Ok(output)
        }
    }
}

#[cfg(test)]
mod test {
    use super::Key;

    #[test]
    fn from_works() {
        let key = Key::from(&(0..64).collect::<Vec<_>>());

        let signing: Vec<u8> = (0..32).collect();
        assert_eq!(key.signing(), &*signing);

        let encryption: Vec<u8> = (32..64).collect();
        assert_eq!(key.encryption(), &*encryption);
    }

    #[test]
    fn try_from_works() {
        use core::convert::TryInto;
        let data = (0..64).collect::<Vec<_>>();
        let key_res: Result<Key, _> = data[0..63].try_into();
        assert!(key_res.is_err());

        let key_res: Result<Key, _> = data.as_slice().try_into();
        assert!(key_res.is_ok());
    }

    #[test]
    fn non_deterministic_generate() {
        let key_a = Key::generate();
        let key_b = Key::generate();

        assert_ne!(key_a.signing(), key_b.signing());
        assert_ne!(key_a.encryption(), key_b.encryption());
    }

    #[test]
    fn debug_does_not_leak_key() {
        let key = Key::generate();

        assert_eq!(format!("{:?}", key), "Key");
    }
}

pub(crate) mod encryption {
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
        if data.len() <= NONCE_LEN {
            anyhow::bail!("The cookie value was too short to contain a nonce");
        }

        let (nonce, cipher) = data.split_at(NONCE_LEN);
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
}

pub(crate) mod signing {
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
}
