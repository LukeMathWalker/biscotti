use rand::RngCore;

const MINIMUM_KEY_LENGTH: usize = 32;

/// A cryptographic master key to sign or encrypt cookies.
#[allow(clippy::derived_hash_with_manual_eq)]
#[derive(Clone, Eq, Hash)]
pub struct Key(Vec<u8>);

#[cfg(feature = "serde")]
mod deser {
    use crate::Key;
    use serde::Deserializer;

    impl<'de> serde::Deserialize<'de> for Key {
        fn deserialize<D>(deserializer: D) -> Result<Key, D::Error>
        where
            D: Deserializer<'de>,
        {
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            let key = Key::try_from(bytes).map_err(serde::de::Error::custom)?;
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
        f.debug_tuple("Key").field(&"***").finish()
    }
}

impl Key {
    /// Creates a new [`Key`] from a string that's at least 256-bits (32 bytes) long.  
    /// For security, the master key _must_ be cryptographically random.
    ///
    /// # Panics
    ///
    /// Panics if `key` is less than 32 bytes in length.
    ///
    /// For a non-panicking version, use [`crate::Key::try_from()`] or generate a key with
    /// [`Key::generate()`] or [`Key::try_generate()`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::Key;
    ///
    /// # /*
    /// let key = { /* a cryptographically random key >= 32 bytes */ };
    /// # */
    /// # let key: Vec<u8> = (0..32).collect();
    ///
    /// let key = Key::from(key);
    /// ```
    #[inline]
    pub fn from(key: Vec<u8>) -> Key {
        crate::Key::try_from(key).expect("Invalid key material")
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
        let mut key: Vec<u8> = vec![0; MINIMUM_KEY_LENGTH * 2];
        rng.try_fill_bytes(&mut key).ok()?;
        Some(Key::from(key))
    }

    /// Returns the raw bytes of the master key. Guaranteed to be at least 32
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

/// The error returned by [`crate::Key::try_from()`] when trying to create a [`Key`] from raw bytes.
#[derive(Debug)]
#[non_exhaustive]
pub enum KeyError {
    /// See [`ShortKeyError`].
    TooShort(ShortKeyError),
}

impl std::error::Error for KeyError {}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::TooShort(e) => {
                write!(f, "{e}")
            }
        }
    }
}

#[derive(Debug)]
/// The key generation algorithm requires more bytes than what was provided.
///
/// See [`Key::from()`] for minimum requirements.
pub struct ShortKeyError {
    length: usize,
}

impl std::fmt::Display for ShortKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "key material is too short: expected >= {} bytes, got {} bytes",
            MINIMUM_KEY_LENGTH, self.length
        )
    }
}

impl std::error::Error for ShortKeyError {}

impl TryFrom<&[u8]> for Key {
    type Error = KeyError;

    /// A fallible version of [`Key::from()`].
    ///
    /// Succeeds when [`Key::from()`] succeeds and returns an error where
    /// [`Key::from()`] panics, namely, if `key` is too short.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use std::convert::TryFrom;
    /// use biscotti::Key;
    ///
    /// # /*
    /// let key = { /* a cryptographically random key >= 32 bytes */ };
    /// # */
    /// # let key: &Vec<u8> = &(0..32).collect();
    /// # let key: &[u8] = &key[..];
    /// assert!(Key::try_from(key).is_ok());
    ///
    /// // A key that's far too short to use.
    /// let key = &[1, 2, 3, 4][..];
    /// assert!(Key::try_from(key).is_err());
    /// ```
    fn try_from(key: &[u8]) -> Result<Self, Self::Error> {
        crate::Key::try_from(key.to_vec())
    }
}

impl TryFrom<Vec<u8>> for Key {
    type Error = KeyError;

    /// A fallible version of [`Key::from()`].
    ///
    /// Succeeds when [`Key::from()`] succeeds and returns an error where
    /// [`Key::from()`] panics, namely, if `key` is too short.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use std::convert::TryFrom;
    /// use biscotti::Key;
    ///
    /// # /*
    /// let key = { /* a cryptographically random key >= 32 bytes */ };
    /// # */
    /// # let key: Vec<u8> = (0..32).collect();
    /// assert!(Key::try_from(key).is_ok());
    ///
    /// // A key that's far too short to use.
    /// let key = vec![1, 2, 3, 4];
    /// assert!(Key::try_from(key).is_err());
    /// ```
    fn try_from(key: Vec<u8>) -> Result<Self, Self::Error> {
        if key.len() < MINIMUM_KEY_LENGTH {
            Err(KeyError::TooShort(ShortKeyError { length: key.len() }))
        } else {
            Ok(Key(key))
        }
    }
}

#[cfg(test)]
mod test {
    use super::Key;
    use crate::crypto::encryption::EncryptionKey;
    use crate::crypto::signing::SigningKey;

    #[test]
    fn try_from_works() {
        use core::convert::TryInto;
        let data = (0..32).collect::<Vec<_>>();
        let key_res: Result<Key, _> = data[0..31].try_into();
        assert!(key_res.is_err());

        let key_res: Result<Key, _> = data.as_slice().try_into();
        assert!(key_res.is_ok());
    }

    #[test]
    fn non_deterministic_generate() {
        let key_a = Key::generate();
        let key_b = Key::generate();

        assert_ne!(SigningKey::derive(&key_a), SigningKey::derive(&key_b));
        assert_ne!(EncryptionKey::derive(&key_a), EncryptionKey::derive(&key_b));
    }

    #[test]
    fn debug_does_not_leak_key() {
        let key = Key::generate();

        assert_eq!(format!("{:?}", key), "Key(\"***\")");
    }
}
