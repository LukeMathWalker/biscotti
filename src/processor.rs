use crate::crypto::encryption::EncryptionKey;
use crate::crypto::signing::SigningKey;
use crate::crypto::Key;
use crate::encoding::encode;
use crate::ProcessorConfig;
use crate::{config, RequestCookie, ResponseCookie};
use percent_encoding::percent_decode;
use std::collections::HashMap;
use std::str::Utf8Error;

/// Transforms cookies before they are sent to the client, or after they have been parsed from an incoming request.
///
/// # Creating a `Processor`
///
/// A processor is created from a [`ProcessorConfig`] using the [`From`] trait.
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
/// # Using a `Processor`
///
/// You need a `Processor`
/// to invoke [`ResponseCookies::header_values`] and [`RequestCookies::parse_header`].  
/// You can also use it to transform individual cookies using
/// [`Processor::process_outgoing`] and [`Processor::process_incoming`].
///
/// [`ResponseCookies::header_values`]: crate::ResponseCookies::header_values
/// [`RequestCookies::parse_header`]: crate::RequestCookies::parse_header
#[derive(Debug, Clone)]
pub struct Processor {
    percent_encode: bool,
    rules: HashMap<String, Rule>,
}

impl From<ProcessorConfig> for Processor {
    fn from(value: ProcessorConfig) -> Self {
        let mut processor = Processor {
            percent_encode: value.percent_encode,
            rules: HashMap::new(),
        };

        for rule in value.crypto_rules.into_iter() {
            let primary = CryptoConfig::new(&rule.key, rule.algorithm.into());
            let fallbacks: Vec<_> = rule
                .fallbacks
                .into_iter()
                .map(|config| CryptoConfig::new(&config.key, config.algorithm.into()))
                .collect();
            for name in rule.cookie_names {
                processor.rules.insert(
                    name,
                    Rule {
                        primary,
                        fallbacks: fallbacks.clone(),
                    },
                );
            }
        }
        processor
    }
}

impl Processor {
    /// Transform a [`ResponseCookie`] before it is sent to the client.
    pub fn process_outgoing<'c>(&self, mut cookie: ResponseCookie<'c>) -> ResponseCookie<'c> {
        if self.percent_encode {
            let name = encode(&cookie.name).to_string();
            cookie.name = name.into();
        }
        if let Some(rule) = self.rules.get(cookie.name.as_ref()) {
            let value = rule.primary.process_outgoing(&cookie.name, &cookie.value);
            cookie.value = value.into();
        } else {
            // We don't need to percent-encode the value if we're encrypting or signing it.
            // The signing/encryption process is guaranteed to return a value that is safe to use
            // in a cookie.
            if self.percent_encode {
                let value = encode(&cookie.value).to_string();
                cookie.value = value.into();
            }
        }

        cookie
    }

    /// Transform a [`RequestCookie`] before it is added to [`ResponseCookies`].
    ///
    /// [`ResponseCookies`]: crate::ResponseCookies
    pub fn process_incoming<'c>(
        &self,
        name: &'c str,
        value: &'c str,
    ) -> Result<RequestCookie<'c>, ProcessIncomingError> {
        let mut cookie = RequestCookie {
            name: name.into(),
            value: value.into(),
        };

        let mut decode_value = false;

        if let Some(rule) = self.rules.get(name) {
            let configs = std::iter::once(rule.primary).chain(rule.fallbacks.iter().copied());
            let value = 'outer: {
                let mut error = None;
                for config in configs {
                    let outcome = config.process_incoming(name, value);
                    match outcome {
                        Ok(value) => {
                            break 'outer value;
                        }
                        Err(e) => {
                            if error.is_none() {
                                // We only want to keep the first error.
                                error = Some(e);
                            }
                        }
                    }
                }
                // If we reach this point, we've tried all the keys and none of them worked.
                return Err(error.unwrap().into());
            };
            cookie.value = value.into();
        } else {
            decode_value = true;
        }
        if self.percent_encode {
            cookie.name =
                percent_decode(name.as_bytes())
                    .decode_utf8()
                    .map_err(|e| DecodingError {
                        invalid_part: InvalidCookiePart::Name {
                            raw_value: name.to_string(),
                        },
                        source: e,
                    })?;
        }

        if self.percent_encode && decode_value {
            cookie.value = percent_decode(value.as_bytes())
                .decode_utf8()
                .map_err(|e| DecodingError {
                    invalid_part: InvalidCookiePart::Value {
                        cookie_name: cookie.name.clone().into_owned(),
                        raw_value: value.to_string(),
                    },
                    source: e,
                })?;
        }

        Ok(cookie)
    }
}

#[derive(Debug)]
#[non_exhaustive]
/// The error returned by [`Processor::process_incoming`].
pub enum ProcessIncomingError {
    Crypto(CryptoError),
    Decoding(DecodingError),
}

impl std::fmt::Display for ProcessIncomingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcessIncomingError::Crypto(e) => e.fmt(f),
            ProcessIncomingError::Decoding(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for ProcessIncomingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProcessIncomingError::Crypto(e) => Some(e),
            ProcessIncomingError::Decoding(e) => Some(e),
        }
    }
}

impl From<CryptoError> for ProcessIncomingError {
    fn from(value: CryptoError) -> Self {
        ProcessIncomingError::Crypto(value)
    }
}

impl From<DecodingError> for ProcessIncomingError {
    fn from(value: DecodingError) -> Self {
        ProcessIncomingError::Decoding(value)
    }
}

#[derive(Debug)]
/// An error that occurred while decrypting or verifying an incoming request cookie.
///
/// This error is returned by [`Processor::process_incoming`].
pub struct CryptoError {
    name: String,
    r#type: CryptoAlgorithm,
    source: anyhow::Error,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let t = match self.r#type {
            CryptoAlgorithm::Encryption => "an encrypted",
            CryptoAlgorithm::Signing => "a signed",
        };
        write!(f, "Failed to process `{}` as {t} request cookie", self.name)
    }
}

impl std::error::Error for CryptoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

#[derive(Debug)]
/// An error that occurred while decoding a percent-encoded cookie name or value.
///
/// This error is returned by [`Processor::process_incoming`].
pub struct DecodingError {
    invalid_part: InvalidCookiePart,
    source: Utf8Error,
}

impl std::fmt::Display for DecodingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.invalid_part {
            InvalidCookiePart::Name { raw_value } => {
                write!(
                    f,
                    "Failed to percent-decode the name of a cookie: `{raw_value}`",
                )
            }
            InvalidCookiePart::Value {
                cookie_name,
                raw_value,
            } => {
                write!(
                    f,
                    "Failed to percent-decode the value of the `{cookie_name}` cookie: `{raw_value}`",
                )
            }
        }
    }
}

impl std::error::Error for DecodingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum InvalidCookiePart {
    Name {
        raw_value: String,
    },
    Value {
        cookie_name: String,
        raw_value: String,
    },
}

#[derive(Debug, Clone)]
struct Rule {
    primary: CryptoConfig,
    fallbacks: Vec<CryptoConfig>,
}

#[derive(Debug, Clone, Copy)]
enum CryptoConfig {
    Encryption { key: EncryptionKey },
    Signing { key: SigningKey },
}

impl CryptoConfig {
    pub fn new(master_key: &Key, crypto_algorithm: CryptoAlgorithm) -> Self {
        match crypto_algorithm {
            CryptoAlgorithm::Encryption => {
                let key = EncryptionKey::derive(master_key);
                CryptoConfig::Encryption { key }
            }
            CryptoAlgorithm::Signing => {
                let key = SigningKey::derive(master_key);
                CryptoConfig::Signing { key }
            }
        }
    }

    /// Process a cookie value received from the client, either by verifying it or decrypting it.
    fn process_incoming(&self, name: &str, value: &str) -> Result<String, CryptoError> {
        match self {
            Self::Encryption { key } => {
                key.decrypt(name.as_bytes(), value.as_bytes())
                    .map_err(|e| CryptoError {
                        name: name.to_owned(),
                        r#type: CryptoAlgorithm::Encryption,
                        source: e,
                    })
            }
            Self::Signing { key } => key.verify(name, value).map_err(|e| CryptoError {
                name: name.to_owned(),
                r#type: CryptoAlgorithm::Signing,
                source: e,
            }),
        }
    }

    /// Process a cookie to be sent to the client, either by signing it or encrypting it.
    fn process_outgoing(&self, name: &str, value: &str) -> String {
        match self {
            Self::Encryption { key } => key.encrypt(name.as_bytes(), value.as_bytes()),
            Self::Signing { key } => key.sign(name, value),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum CryptoAlgorithm {
    Encryption,
    Signing,
}

impl std::fmt::Display for CryptoAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoAlgorithm::Encryption => write!(f, "encryption"),
            CryptoAlgorithm::Signing => write!(f, "signing"),
        }
    }
}

impl From<config::CryptoAlgorithm> for CryptoAlgorithm {
    fn from(value: config::CryptoAlgorithm) -> Self {
        match value {
            config::CryptoAlgorithm::Encryption => CryptoAlgorithm::Encryption,
            config::CryptoAlgorithm::Signing => CryptoAlgorithm::Signing,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{CryptoAlgorithm, CryptoRule, FallbackConfig};
    use crate::encoding::encode;
    use crate::{Key, Processor, ProcessorConfig, RequestCookies, ResponseCookie};
    use std::error::Error;

    #[test]
    fn roundtrip_encryption() {
        let name = "encrypted";
        let unencrypted_value = "tamper-proof";
        let processor: Processor = ProcessorConfig {
            crypto_rules: vec![CryptoRule {
                cookie_names: vec![name.to_string()],
                algorithm: CryptoAlgorithm::Encryption,
                key: Key::generate(),
                fallbacks: vec![],
            }],
            ..Default::default()
        }
        .into();

        let cookie = ResponseCookie::new(name, unencrypted_value);
        let encrypted_cookie = processor.process_outgoing(cookie);
        assert_ne!(encrypted_cookie.value(), unencrypted_value);
        // The encrypted value should be safe to use in a cookie.
        assert_eq!(
            encode(encrypted_cookie.value()).to_string(),
            encrypted_cookie.value()
        );

        let header = format!("{}={}", encrypted_cookie.name(), encrypted_cookie.value());
        let request_cookies = RequestCookies::parse_header(&header, &processor)
            .expect("Failed to parse the encrypted cookie");
        let decrypted_cookie = request_cookies
            .get(name)
            .expect("Failed to get the decrypted cookie");

        assert_eq!(decrypted_cookie.name(), name);
        assert_eq!(decrypted_cookie.value(), unencrypted_value);
    }

    #[test]
    fn roundtrip_signing() {
        let name = "signed";
        let value = "tamper-proof";
        let processor: Processor = ProcessorConfig {
            crypto_rules: vec![CryptoRule {
                cookie_names: vec![name.to_string()],
                algorithm: CryptoAlgorithm::Signing,
                key: Key::generate(),
                fallbacks: vec![],
            }],
            ..Default::default()
        }
        .into();

        let cookie = ResponseCookie::new(name, value);
        let signed_cookie = processor.process_outgoing(cookie);
        assert_ne!(signed_cookie.value(), value);

        let header = format!("{}={}", signed_cookie.name(), signed_cookie.value());
        let request_cookies = RequestCookies::parse_header(&header, &processor)
            .expect("Failed to parse the signed cookie");
        let verified_cookie = request_cookies
            .get(name)
            .expect("Failed to get the signed cookie");

        assert_eq!(verified_cookie.name(), name);
        assert_eq!(verified_cookie.value(), value);
    }

    #[test]
    fn roundtrip_encoded() {
        let name = "to be encoded";
        let value = "a bunch of % very special ! # characters ;";
        let processor: Processor = ProcessorConfig::default().into();

        let cookie = ResponseCookie::new(name, value);
        let encoded_cookie = processor.process_outgoing(cookie);
        assert_ne!(encoded_cookie.name(), name);
        assert_ne!(encoded_cookie.value(), value);

        let header = format!("{}={}", encoded_cookie.name(), encoded_cookie.value());
        let request_cookies = RequestCookies::parse_header(&header, &processor)
            .expect("Failed to parse the decoded cookie");
        let decoded_cookie = request_cookies
            .get(name)
            .expect("Failed to get the decoded cookie");

        assert_eq!(decoded_cookie.name(), name);
        assert_eq!(decoded_cookie.value(), value);
    }

    #[test]
    fn unsigned_is_rejected() {
        let name = "session";
        let value = "a-value-that-should-be-signed-but-is-not";
        let header = format!("{name}={value}");

        let processor: Processor = ProcessorConfig {
            crypto_rules: vec![CryptoRule {
                cookie_names: vec![name.to_string()],
                algorithm: CryptoAlgorithm::Signing,
                key: Key::generate(),
                fallbacks: vec![],
            }],
            ..Default::default()
        }
        .into();
        let err = RequestCookies::parse_header(&header, &processor)
            .expect_err("A non-signed cookie passed verification, bad!");
        assert_eq!(
            err.to_string(),
            "Failed to parse cookies out of a header value"
        );
        assert_eq!(
            err.source().unwrap().to_string(),
            "Failed to process `session` as a signed request cookie"
        );
    }

    #[test]
    fn unencrypted_is_rejected() {
        let name = "session";
        let value = "a-value-that-should-be-encrypted-but-is-not";
        let header = format!("{name}={value}");

        let processor: Processor = ProcessorConfig {
            crypto_rules: vec![CryptoRule {
                cookie_names: vec![name.to_string()],
                algorithm: CryptoAlgorithm::Encryption,
                key: Key::generate(),
                fallbacks: vec![],
            }],
            ..Default::default()
        }
        .into();
        let err = RequestCookies::parse_header(&header, &processor)
            .expect_err("A non-encrypted cookie passed, bad!");
        assert_eq!(
            err.to_string(),
            "Failed to parse cookies out of a header value"
        );
        assert_eq!(
            err.source().unwrap().to_string(),
            "Failed to process `session` as an encrypted request cookie"
        );
    }

    #[test]
    fn signed_with_secondary_is_fine() {
        let name = "signed";
        let value = "tamper-proof";
        let primary_key = Key::generate();
        let fallbacks = vec![
            FallbackConfig {
                key: Key::generate(),
                algorithm: CryptoAlgorithm::Signing,
            },
            FallbackConfig {
                key: Key::generate(),
                algorithm: CryptoAlgorithm::Signing,
            },
            FallbackConfig {
                key: Key::generate(),
                algorithm: CryptoAlgorithm::Signing,
            },
        ];
        let fallback = fallbacks[1].clone();

        let processor: Processor = ProcessorConfig {
            crypto_rules: vec![CryptoRule {
                cookie_names: vec![name.to_string()],
                algorithm: fallback.algorithm,
                key: fallback.key.clone(),
                fallbacks: vec![],
            }],
            ..Default::default()
        }
        .into();
        let cookie = ResponseCookie::new(name, value);
        // Signed with the secondary key.
        let secured_cookie = processor.process_outgoing(cookie);
        assert_ne!(secured_cookie.value(), value);

        let header = format!("{}={}", secured_cookie.name(), secured_cookie.value());
        let processor: Processor = ProcessorConfig {
            crypto_rules: vec![CryptoRule {
                cookie_names: vec![name.to_string()],
                algorithm: CryptoAlgorithm::Signing,
                // Primary key has changed!
                key: primary_key.clone(),
                fallbacks,
            }],
            ..Default::default()
        }
        .into();
        let request_cookies = RequestCookies::parse_header(&header, &processor)
            .expect("Failed to parse the signed cookie");
        let verified_cookie = request_cookies
            .get(name)
            .expect("Failed to get the signed cookie");

        assert_eq!(verified_cookie.name(), name);
        assert_eq!(verified_cookie.value(), value);
    }

    #[test]
    fn encrypted_with_secondary_is_fine() {
        let name = "encrypted";
        let value = "tamper-proof";
        let primary_key = Key::generate();
        let fallbacks = vec![
            FallbackConfig {
                key: Key::generate(),
                algorithm: CryptoAlgorithm::Signing,
            },
            FallbackConfig {
                key: Key::generate(),
                algorithm: CryptoAlgorithm::Signing,
            },
            FallbackConfig {
                key: Key::generate(),
                algorithm: CryptoAlgorithm::Signing,
            },
        ];
        let fallback = fallbacks[1].clone();

        let processor: Processor = ProcessorConfig {
            crypto_rules: vec![CryptoRule {
                cookie_names: vec![name.to_string()],
                algorithm: fallback.algorithm,
                key: fallback.key.clone(),
                fallbacks: vec![],
            }],
            ..Default::default()
        }
        .into();
        let cookie = ResponseCookie::new(name, value);
        // Signed with the secondary key.
        let secured_cookie = processor.process_outgoing(cookie);
        assert_ne!(secured_cookie.value(), value);

        let header = format!("{}={}", secured_cookie.name(), secured_cookie.value());
        let processor: Processor = ProcessorConfig {
            crypto_rules: vec![CryptoRule {
                cookie_names: vec![name.to_string()],
                algorithm: CryptoAlgorithm::Encryption,
                // Primary key has changed!
                key: primary_key.clone(),
                fallbacks,
            }],
            ..Default::default()
        }
        .into();
        let request_cookies = RequestCookies::parse_header(&header, &processor)
            .expect("Failed to parse the encrypted cookie");
        let decrypted_cookie = request_cookies
            .get(name)
            .expect("Failed to get the encrypted cookie");

        assert_eq!(decrypted_cookie.name(), name);
        assert_eq!(decrypted_cookie.value(), value);
    }
}
