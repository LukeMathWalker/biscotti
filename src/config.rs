//! Configuration for a [`Processor`].
//!
//! Check out the [`ProcessorConfig`] struct for more information.
//!
//! [`Processor`]: crate::Processor
//! [`ProcessorConfig`]: crate::ProcessorConfig
pub use inner::{CryptoAlgorithm, CryptoRule, FallbackConfig};

pub(crate) mod inner {
    use crate::Key;

    /// `Config` specifies how the server should handle incoming and outgoing cookies
    /// with respect to security and encoding.
    ///
    /// In particular, it specifies whether cookie values and names should be
    /// percent-encoded, and whether cookie values should be encrypted or signed.
    ///
    /// Check out the documentation for the fields of this struct for more information.
    ///
    /// # [`Processor`]
    ///
    /// To action the rules specified in this struct, you must convert it into a [`Processor`]:
    ///
    /// ```rust
    /// use biscotti::{Processor, ProcessorConfig, Key};
    /// use biscotti::config::{CryptoRule, CryptoAlgorithm};
    ///
    /// let mut config = ProcessorConfig::default();
    /// config.crypto_rules.push(CryptoRule {
    ///     cookie_names: vec!["session".to_string()],
    ///     algorithm: CryptoAlgorithm::Encryption,
    ///     // You'll use a key loaded from *somewhere* in production—e.g.
    ///     // from a file, environment variable, or a secret management service.
    ///     key: Key::generate(),
    ///     fallbacks: vec![],
    /// });
    /// let processor: Processor = config.into();
    /// ```
    ///
    /// [`Processor`]: crate::Processor
    #[derive(Debug, Clone)]
    #[non_exhaustive]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize))]
    pub struct ProcessorConfig {
        /// If `true`, all cookie values and names are automatically:
        ///
        /// - percent-decoded, when parsing request cookies out of the `Cookie` header.
        /// - percent-encoded, when building the `Set-Cookie` header from response cookies.
        ///
        /// If `false`, cookie values and names are used as is.
        ///
        /// By default, this field is `true`.
        #[cfg_attr(feature = "serde", serde(default = "percent_encode_default"))]
        pub percent_encode: bool,
        /// By default:
        ///
        /// - Values for response cookies are sent to the client unencrypted and unsigned
        /// - Values for request cookies are assumed to be unencrypted and unsigned
        ///
        /// You can opt into higher cryptographic guarantees for specific cookies using
        /// one or more [`CryptoRule`]s.
        #[cfg_attr(feature = "serde", serde(default = "crypto_rules_default"))]
        pub crypto_rules: Vec<CryptoRule>,
    }

    fn percent_encode_default() -> bool {
        true
    }

    fn crypto_rules_default() -> Vec<CryptoRule> {
        vec![]
    }

    /// `CryptoRule` specifies whether certain cookies should be encrypted or signed.
    #[derive(Debug, Clone)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize))]
    pub struct CryptoRule {
        /// The names of the cookies to which this rule applies.
        pub cookie_names: Vec<String>,
        /// How the cookies should be secured: either encryption or signing.
        pub algorithm: CryptoAlgorithm,
        /// The key to use for encryption or signing.
        ///
        /// # Requirements
        ///
        /// The key must be at least 64 bytes long and should be generated using a
        /// cryptographically secure random number generator.
        pub key: Key,
        /// Fallbacks are used to decrypt/verify request cookies that failed to
        /// be decrypted/verified using the primary key.  
        /// Fallbacks are never used to encrypt/sign response cookies.
        ///
        /// # Key rotation
        ///
        /// Fallbacks exist to enable **key and algorithm rotation**.  
        /// From time to time, you may want to change the key used to sign or encrypt cookies, or update
        /// the algorithm.  
        /// If you do this naively
        /// (e.g. change [`CryptoRule::key`] or [`CryptoRule::algorithm`] to a new value),
        /// the server will immediately start rejecting all existing cookies
        /// because they were signed/encrypted with the old key/algorithm.
        ///
        /// With fallbacks, you can start using the new configuration _without_ invalidating all existing
        /// cookies.
        /// The process for key rotation goes as follows:
        ///
        /// 1. Generate a new key
        /// 2. Set `key` to the new key,
        ///    and add the old key to the `fallbacks` vector, using the same algorithm
        /// 3. Wait for the expiration of all cookies signed/encrypted with the old key
        /// 4. Remove the old key from the `fallbacks` vector
        #[cfg_attr(feature = "serde", serde(default))]
        pub fallbacks: Vec<FallbackConfig>,
    }

    #[derive(Debug, Clone)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize))]
    /// A fallback configuration for either decrypting or verifying a cookie.
    ///
    /// Check out [`CryptoRule::fallbacks`] for more information.
    pub struct FallbackConfig {
        /// The key to use for encryption or signing.
        pub key: Key,
        /// How the cookies should be secured.
        pub algorithm: CryptoAlgorithm,
    }

    /// The two cryptographic processes that can be applied to a cookie value.
    #[derive(Debug, Clone, Copy)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize))]
    #[non_exhaustive]
    pub enum CryptoAlgorithm {
        /// The cookie value will be encrypted using [AEAD-AES-256-GCM-SIV](https://www.rfc-editor.org/rfc/rfc8452.html).
        ///
        /// Encryption guarantees **confidentiality** of the value as well as its
        /// **integrity**.
        Encryption,
        /// The cookie will be signed using [HMAC-SHA256](https://www.rfc-editor.org/rfc/rfc2104.html).  
        ///
        /// Signing guarantees **integrity** of the value.
        Signing,
    }

    impl Default for ProcessorConfig {
        fn default() -> Self {
            ProcessorConfig {
                percent_encode: percent_encode_default(),
                crypto_rules: crypto_rules_default(),
            }
        }
    }
}
