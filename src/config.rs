//! Configuration for a [`Processor`].
//!
//! Check out the [`Config`] struct for more information.
//!
//! [`Processor`]: crate::Processor
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
/// use biscotti::{Processor, Key};
/// use biscotti::config::{Config, CryptoRule, CryptoType};
///
/// let mut config = Config::default();
/// config.crypto_rules.push(CryptoRule {
///     cookie_names: vec!["session".to_string()],
///     r#type: CryptoType::Encryption,
///     // You'll use a key loaded from *somewhere* in production—e.g.
///     // from a file, environment variable, or a secret management service.
///     key: Key::generate(),
///     secondary_keys: vec![],
/// });
/// let processor: Processor = config.into();
/// ```
///
/// [`Processor`]: crate::Processor
#[derive(Debug, Clone)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Deserialize))]
pub struct Config {
    /// If `true`, all cookie values and names are automatically:
    ///
    /// - percent-decoded, when parsing request cookies out of the `Cookie` header.
    /// - percent-encoded, when building the `Set-Cookie` header from response cookies.
    ///
    /// If `false`, cookie values and names are used as is.
    ///
    /// By default, this field is `true`.
    pub percent_encode: bool,
    /// By default:
    ///
    /// - Values for response cookies are sent to the client unencrypted and unsigned
    /// - Values for request cookies are assumed to be unencrypted and unsigned
    ///
    /// You can opt into higher cryptographic guarantees for specific cookies using
    /// one or more [`CryptoRule`]s.
    pub crypto_rules: Vec<CryptoRule>,
}

/// `CryptoRule` specifies whether certain cookies should be encrypted or signed.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize))]
pub struct CryptoRule {
    /// The names of the cookies to which this rule applies.
    pub cookie_names: Vec<String>,
    /// How the cookies should be secured: either encryption or signing.
    pub r#type: CryptoType,
    /// The key to use for encryption or signing.
    ///
    /// # Requirements
    ///
    /// The key must be at least 64 bytes long and should be generated using a
    /// cryptographically secure random number generator.
    pub key: Key,
    /// Secondary keys are used to decrypt/verify request cookies that failed to
    /// be decrypted/verified using the primary key.  
    /// Secondary keys are never used to encrypt/sign response cookies.
    ///
    /// # Key rotation
    ///
    /// Secondary keys exist to enable **key rotation**.  
    /// From time to time, you may want to change the key used to sign or encrypt cookies.  
    /// If you do this naively (i.e. change [`CryptoRule::key`] to a new value), the server  
    /// will immediately start rejecting all existing cookies
    /// because they were signed/encrypted with the old key.
    ///
    /// Using secondary keys, you can start using the new key _without_ invalidating all existing
    /// cookies.
    /// The process is as follows:
    ///
    /// 1. Generate a new key
    /// 2. Set `key` to the new key, and add the old key to the `secondary_keys` vector
    /// 3. Wait for the expiration of all cookies signed/encrypted with the old key
    /// 4. Remove the old key from the `secondary_keys` vector
    #[cfg_attr(feature = "serde", serde(default))]
    pub secondary_keys: Vec<Key>,
}

/// The two cryptographic processes that can be applied to a cookie value.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize))]
pub enum CryptoType {
    /// The cookie value should be encrypted.  
    /// Encryption guarantees **confidentiality** of the value as well as its
    /// **integrity**.
    Encryption,
    /// The cookie value should be signed using this key.
    /// Signing guarantees **integrity** of the value.
    Signing,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            percent_encode: true,
            crypto_rules: vec![],
        }
    }
}
