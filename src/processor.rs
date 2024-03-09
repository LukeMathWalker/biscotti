use crate::config::Config;
use crate::crypto::Key;
use crate::encoding::encode;
use crate::{config, crypto, RequestCookie, ResponseCookie};
use anyhow::Context;
use indexmap::IndexSet;
use percent_encoding::percent_decode;
use std::collections::HashMap;

/// Transforms cookies before they are sent to the client, or after they have been parsed from an incoming request.
///
/// # Creating a `Processor`
///
/// A processor is created from a [`Config`] using the [`From`] trait.
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
/// # Using a `Processor`
///
/// You need a `Processor`
/// to invoke [`ResponseCookies::header_values`] and [`RequestCookies::parse_header`].  
/// You can also use it to transform individual cookies using
/// [`Processor::process_outgoing`] and [`Processor::process_incoming`].
///
/// [`ResponseCookies::header_values`]: crate::ResponseCookies::header_values
/// [`RequestCookies::parse_header`]: crate::RequestCookies::parse_header
pub struct Processor {
    percent_encode: bool,
    keys: IndexSet<Key>,
    rules: HashMap<String, Rule>,
}

impl From<Config> for Processor {
    fn from(value: Config) -> Self {
        let mut keys = IndexSet::with_capacity(value.crypto_rules.len());
        let mut rules = HashMap::new();
        for rule in value.crypto_rules.into_iter() {
            let (key_id, _) = keys.insert_full(rule.key);
            let secondary_key_ids: Vec<_> = rule
                .secondary_keys
                .into_iter()
                .map(|key| keys.insert_full(key).0)
                .collect();
            for name in &rule.cookie_names {
                rules.insert(
                    name.clone(),
                    Rule {
                        r#type: rule.r#type.into(),
                        key_id,
                        secondary_key_ids: secondary_key_ids.clone(),
                    },
                );
            }
        }
        Processor {
            percent_encode: value.percent_encode,
            keys,
            rules,
        }
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
            let key = &self.keys[rule.key_id];
            let value = match rule.r#type {
                CryptoType::Encryption => {
                    let key = key.encryption();
                    crypto::encryption::encrypt(
                        cookie.name.as_bytes(),
                        cookie.value.as_bytes(),
                        key,
                    )
                }
                CryptoType::Signing => {
                    let key = key.signing();
                    crypto::signing::sign(cookie.name.as_bytes(), cookie.value.as_ref(), key)
                }
            };
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
            let key_ids =
                std::iter::once(rule.key_id).chain(rule.secondary_key_ids.iter().copied());
            let value = 'outer: {
                let mut error = None;
                for key_id in key_ids {
                    let key = &self.keys[key_id];
                    let outcome = process_incoming(key, rule.r#type, name, value);
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
            cookie.name = percent_decode(name.as_bytes())
                .decode_utf8()
                .context("Failed to percent-decode the cookie name")
                .map_err(|e| DecodingError {
                    source: e,
                    raw_value: name.to_string(),
                })?;
        }

        if self.percent_encode && decode_value {
            cookie.value = percent_decode(value.as_bytes())
                .decode_utf8()
                .with_context(|| {
                    format!(
                        "Failed to percent-decode the value of the cookie named '{}'",
                        cookie.name
                    )
                })
                .map_err(|e| DecodingError {
                    raw_value: value.to_string(),
                    source: e,
                })?;
        }

        Ok(cookie)
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
/// The error returned by [`Processor::process_incoming`].
pub enum ProcessIncomingError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Decoding(#[from] DecodingError),
}

#[derive(Debug, thiserror::Error)]
/// An error that occurred while decrypting or verifying an incoming request cookie.
///
/// This error is returned by [`Processor::process_incoming`].
pub struct CryptoError {
    r#type: CryptoType,
    #[source]
    source: anyhow::Error,
}

#[derive(Debug, thiserror::Error)]
#[error("{source}")]
/// An error that occurred while decoding a percent-encoded cookie name or value.
///
/// This error is returned by [`Processor::process_incoming`].
pub struct DecodingError {
    pub(crate) raw_value: String,
    #[source]
    pub(crate) source: anyhow::Error,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let t = match self.r#type {
            CryptoType::Encryption => "an encrypted",
            CryptoType::Signing => "a signed",
        };
        write!(f, "Failed to process {t} request cookie")
    }
}

#[derive(Debug, Clone)]
struct Rule {
    r#type: CryptoType,
    key_id: usize,
    secondary_key_ids: Vec<usize>,
}

/// Process a cookie value received from the client, either by verifying it or decrypting it.
fn process_incoming(
    key: &Key,
    ty: CryptoType,
    name: &str,
    value: &str,
) -> Result<String, CryptoError> {
    match ty {
        CryptoType::Encryption => {
            let key = key.encryption();
            crypto::encryption::decrypt(name.as_bytes(), value.as_bytes(), key).map_err(|e| {
                CryptoError {
                    r#type: CryptoType::Encryption,
                    source: e,
                }
            })
        }
        CryptoType::Signing => {
            let key = key.signing();
            crypto::signing::verify(name.as_bytes(), value, key).map_err(|e| CryptoError {
                r#type: CryptoType::Signing,
                source: e,
            })
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum CryptoType {
    Encryption,
    Signing,
}

impl std::fmt::Display for CryptoType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoType::Encryption => write!(f, "encryption"),
            CryptoType::Signing => write!(f, "signing"),
        }
    }
}

impl From<config::CryptoType> for CryptoType {
    fn from(value: config::CryptoType) -> Self {
        match value {
            config::CryptoType::Encryption => CryptoType::Encryption,
            config::CryptoType::Signing => CryptoType::Signing,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{Config, CryptoRule, CryptoType};
    use crate::encoding::encode;
    use crate::{Key, Processor, RequestCookies, ResponseCookie};

    #[test]
    fn roundtrip_encryption() {
        let name = "encrypted";
        let unencrypted_value = "tamper-proof";
        let processor: Processor = Config {
            crypto_rules: vec![CryptoRule {
                cookie_names: vec![name.to_string()],
                r#type: crate::config::CryptoType::Encryption,
                key: Key::generate(),
                secondary_keys: vec![],
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
        let processor: Processor = Config {
            crypto_rules: vec![CryptoRule {
                cookie_names: vec![name.to_string()],
                r#type: crate::config::CryptoType::Signing,
                key: Key::generate(),
                secondary_keys: vec![],
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
        let processor: Processor = Config::default().into();

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
    fn signed_with_secondary_is_fine() {
        let name = "signed";
        let value = "tamper-proof";
        let primary_key = Key::generate();
        let secondary_keys = vec![Key::generate(), Key::generate(), Key::generate()];
        let secondary_key = secondary_keys[1].clone();

        let processor: Processor = Config {
            crypto_rules: vec![CryptoRule {
                cookie_names: vec![name.to_string()],
                r#type: CryptoType::Signing,
                key: secondary_key.clone(),
                secondary_keys: vec![],
            }],
            ..Default::default()
        }
        .into();
        let cookie = ResponseCookie::new(name, value);
        // Signed with the secondary key.
        let secured_cookie = processor.process_outgoing(cookie);
        assert_ne!(secured_cookie.value(), value);

        let header = format!("{}={}", secured_cookie.name(), secured_cookie.value());
        let processor: Processor = Config {
            crypto_rules: vec![CryptoRule {
                cookie_names: vec![name.to_string()],
                r#type: CryptoType::Signing,
                // Primary key has changed!
                key: primary_key.clone(),
                secondary_keys,
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
        let secondary_keys = vec![Key::generate(), Key::generate(), Key::generate()];
        let secondary_key = secondary_keys[1].clone();

        let processor: Processor = Config {
            crypto_rules: vec![CryptoRule {
                cookie_names: vec![name.to_string()],
                r#type: CryptoType::Encryption,
                key: secondary_key.clone(),
                secondary_keys: vec![],
            }],
            ..Default::default()
        }
        .into();
        let cookie = ResponseCookie::new(name, value);
        // Signed with the secondary key.
        let secured_cookie = processor.process_outgoing(cookie);
        assert_ne!(secured_cookie.value(), value);

        let header = format!("{}={}", secured_cookie.name(), secured_cookie.value());
        let processor: Processor = Config {
            crypto_rules: vec![CryptoRule {
                cookie_names: vec![name.to_string()],
                r#type: CryptoType::Encryption,
                // Primary key has changed!
                key: primary_key.clone(),
                secondary_keys,
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
