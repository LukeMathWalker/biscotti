use crate::processor::{ProcessIncomingError, Processor};
use crate::request::CookiesForName;
use crate::RequestCookie;
use std::borrow::Cow;
use std::collections::HashMap;

#[derive(Default, Debug, Clone)]
/// A collection of [`RequestCookie`]s attached to an HTTP request using the `Cookie` header.
pub struct RequestCookies<'c> {
    /// Invariant: the `Vec` for a given `name` is never empty.
    cookies: HashMap<Cow<'c, str>, Vec<Cow<'c, str>>>,
}

impl<'c> RequestCookies<'c> {
    /// Creates a new, empty [`RequestCookies`] map.
    pub fn new() -> RequestCookies<'c> {
        Default::default()
    }

    /// Inserts a new [`RequestCookie`] into `self`.
    ///
    /// If a cookie with the same name already exists, **the new value is appended
    /// to the existing value list**.
    ///
    /// If you want to replace the existing value list for a given name, use the
    /// [`RequestCookies::replace()`] method.
    ///
    /// # Return value
    ///
    /// Returns `true` if [`RequestCookies`] contained one or more cookies with the same name.
    /// `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::{RequestCookie, RequestCookies};
    ///
    /// let mut cookies = RequestCookies::new();
    /// cookies.append(RequestCookie::new("name", "value1"));
    /// assert_eq!(cookies.get("name").unwrap().value(), "value1");
    ///
    /// // A new cookie with the same name: its value is appended to
    /// // the existing value list for `name`.
    /// cookies.append(RequestCookie::new("name", "value2"));
    /// // `get` keeps returning the first value.
    /// assert_eq!(cookies.get("name").unwrap().value(), "value1");
    /// // Use `get_all` to get all values for a given name.
    /// let mut c = cookies.get_all("name").unwrap();
    /// assert_eq!(c.next().unwrap().value(), "value1");
    /// assert_eq!(c.next().unwrap().value(), "value2");
    /// assert_eq!(c.next(), None);
    /// ```
    pub fn append<C>(&mut self, cookie: C) -> bool
    where
        C: Into<RequestCookie<'c>>,
    {
        let cookie = cookie.into();
        let RequestCookie { name, value } = cookie;

        let output = self.cookies.contains_key(&name);

        self.cookies.entry(name).or_default().push(value);

        output
    }

    /// Inserts a new [`RequestCookie`] into `self`.
    ///
    /// If a cookie with the same name already exists, **the existing value
    /// list is discarded and replaced with the new value**.  
    ///
    /// If you want to append a new value to the existing value list, use
    /// [`RequestCookies::append()`].
    ///
    /// # Return value
    ///
    /// Returns `true` if [`RequestCookies`] contained one or more cookies with the same name.
    /// `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::{RequestCookie, RequestCookies};
    ///
    /// let mut cookies = RequestCookies::new();
    /// cookies.replace(RequestCookie::new("name", "value1"));
    ///
    /// assert_eq!(cookies.get("name").unwrap().value(), "value1");
    ///
    /// // A new cookie with the same name: its value replaces
    /// // the existing value list for `name`.
    /// cookies.replace(RequestCookie::new("name", "value2"));
    ///
    /// assert_eq!(cookies.get("name").unwrap().value(), "value2");
    /// let mut values = cookies.get_all("name").unwrap().values();
    /// assert_eq!(values.next(), Some("value2"));
    /// assert_eq!(values.next(), None);
    /// ```
    pub fn replace<C>(&mut self, cookie: C) -> bool
    where
        C: Into<RequestCookie<'c>>,
    {
        let cookie = cookie.into();
        let RequestCookie { name, value } = cookie;
        self.cookies.insert(name, vec![value]).is_some()
    }

    /// Get a cookie by name.
    ///
    /// If there are multiple cookie values associated to the name, this method returns the
    /// first one.
    /// If you want to get all cookie values for a given name, use [`RequestCookies::get_all()`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::{RequestCookie, RequestCookies};
    ///
    /// let mut cookies = RequestCookies::new();
    /// cookies.append(RequestCookie::new("name", "value1"));
    /// assert_eq!(cookies.get("name").unwrap().value(), "value1");
    ///
    /// // A new cookie with the same name: its value is appended to
    /// // the existing value list for `name`.
    /// cookies.append(RequestCookie::new("name", "value2"));
    ///
    /// // `get` keeps returning the first value.
    /// assert_eq!(cookies.get("name").unwrap().value(), "value1");
    /// // `get_all` returns all values.
    /// let mut values = cookies.get_all("name").unwrap().values();
    /// assert_eq!(values.next(), Some("value1"));
    /// assert_eq!(values.next(), Some("value2"));
    /// assert_eq!(values.next(), None);
    /// ```
    pub fn get(&self, name: &str) -> Option<RequestCookie<'c>> {
        self.cookies.get_key_value(name).map(|(name, v)| {
            let first = v.first().unwrap();
            RequestCookie::new(name.clone(), first.clone())
        })
    }

    /// Get all cookie values for a given cookie name.  
    /// If there are no cookies with the given name, the method returns `None`.
    ///
    /// If you want to get the first cookie value for a given name, use the
    /// [`RequestCookies::get()`] method.
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::{RequestCookie, RequestCookies};
    ///
    /// let mut cookies = RequestCookies::new();
    /// cookies.append(RequestCookie::new("name", "value1"));
    /// assert_eq!(cookies.get("name").unwrap().value(), "value1");
    ///
    /// // A new cookie with the same name: its value is appended to
    /// // the existing value list for `name`.
    /// cookies.append(RequestCookie::new("name", "value2"));
    ///
    /// // `get` keeps returning the first value.
    /// assert_eq!(cookies.get("name").unwrap().value(), "value1");
    /// // `get_all` returns all values.
    /// let mut values = cookies.get_all("name").unwrap().values();
    /// assert_eq!(values.next(), Some("value1"));
    /// assert_eq!(values.next(), Some("value2"));
    /// assert_eq!(values.next(), None);
    /// ```
    pub fn get_all(&self, name: &str) -> Option<CookiesForName<'_, 'c>> {
        self.cookies.get_key_value(name).map(|(name, v)| {
            let iter = v.iter();
            CookiesForName {
                iter,
                name: name.clone(),
            }
        })
    }

    /// Parse a `Cookie` header value into a [`RequestCookies`] map.
    pub fn parse_header(
        header: &'c str,
        policy: &Processor,
    ) -> Result<RequestCookies<'c>, ParseError> {
        let mut cookies = RequestCookies::new();
        for cookie in header.split(';') {
            if cookie.chars().all(char::is_whitespace) {
                continue;
            }

            let (name, value) = match cookie.split_once('=') {
                Some((name, value)) => (name.trim(), value.trim()),
                None => return Err(ParseError::MissingPair),
            };

            if name.is_empty() {
                return Err(ParseError::EmptyName);
            }

            let cookie = policy.process_incoming(name, value)?;

            cookies.append(cookie);
        }
        Ok(cookies)
    }
}

#[derive(Debug, thiserror::Error)]
/// The error returned by [`RequestCookies::parse_header()`].
pub enum ParseError {
    #[error("Expected a name-value pair, but no `=` was found")]
    MissingPair,
    #[error("Cookie name is empty")]
    EmptyName,
    #[error(transparent)]
    ProcessingError(#[from] ProcessIncomingError),
}

#[cfg(test)]
mod tests {
    use crate::config::Config;
    use crate::errors::ParseError::{EmptyName, MissingPair};
    use crate::processor::DecodingError;
    use crate::{
        errors::{ParseError, ProcessIncomingError},
        Processor, RequestCookies,
    };

    /// A helper macro for our testing purposes.
    ///
    /// E.g. `cookies!("name" => "value", "other" => "key")` expands to:
    ///
    /// ```rust
    /// use biscotti::{RequestCookie, RequestCookies};
    ///
    /// {
    ///     let mut cookies = RequestCookies::new();
    ///     cookies.append(RequestCookie::new("name", "value"));
    ///     cookies.append(RequestCookie::new("other", "key"));
    ///     Ok(cookies)
    /// }
    /// ```
    macro_rules! cookies {
        ($($name:expr => $value:expr),* $(,)?) => {
            {
                use crate::RequestCookies;
                #[allow(unused_imports)]
                use crate::RequestCookie;

                #[allow(unused_mut)]
                let mut cookies = RequestCookies::new();
                $(
                    cookies.append(RequestCookie::new($name, $value));
                )*
                Ok(cookies)
            }
        };
    }

    #[track_caller]
    fn check_case(
        string: &str,
        processor: &Processor,
        expected: Result<RequestCookies, ParseError>,
    ) {
        match RequestCookies::parse_header(string, processor) {
            Ok(actual) => {
                let expected =
                    expected.unwrap_or_else(|_| panic!("Expected a success for {string}"));
                for (name, value) in expected.cookies {
                    let values: Vec<_> = actual
                        .get_all(&name)
                        .unwrap_or_else(|| panic!("No entry for {name} and raw string {string}"))
                        .values()
                        .collect();
                    assert_eq!(values, value, "Failed for string: {string}");
                }
            }
            Err(e) => {
                let expected = expected.expect_err(&format!("Expected an error for {string}"));
                use ParseError::*;
                match (e, expected) {
                    (EmptyName, EmptyName)
                    | (MissingPair, MissingPair)
                    | (ProcessingError(_), ProcessingError(_)) => {}
                    (actual, expected) => {
                        panic!(
                            "Expected {:?}, but got {:?} for {}",
                            expected, actual, string
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn parse_unencoded() {
        let cases = [
            ("", cookies![]),
            (";;", cookies![]),
            ("name=value", cookies!["name" => "value"]),
            ("a=%20", cookies!["a" => "%20"]),
            ("a=d#$%^&*()_", cookies!["a" => "d#$%^&*()_"]),
            ("  name=value  ", cookies!["name" => "value"]),
            ("name=value  ", cookies!["name" => "value"]),
            (
                "name=value;;other=key",
                cookies!["name" => "value", "other" => "key"],
            ),
            (
                "name=value;  ;other=key",
                cookies!["name" => "value", "other" => "key"],
            ),
            (
                "name=value ;  ;other=key",
                cookies!["name" => "value", "other" => "key"],
            ),
            (
                "name=value ;  ; other=key",
                cookies!["name" => "value", "other" => "key"],
            ),
            (
                "name=value ;  ; other=key ",
                cookies!["name" => "value", "other" => "key"],
            ),
            (
                "name=value ;  ; other=key;; ",
                cookies!["name" => "value", "other" => "key"],
            ),
            (
                ";name=value ;  ; other=key ",
                cookies!["name" => "value", "other" => "key"],
            ),
            (";a=1 ;  ; b=2 ", cookies!["a" => "1", "b" => "2"]),
            (";a=1 ;  ; b= ", cookies!["a" => "1", "b" => ""]),
            (" ;   a=1 ;  ; ;;c===  ", cookies!["a" => "1", "c" => "=="]),
            (";a=1 ;  ; =v ; c=", Err(EmptyName)),
            (" ;   a=1 ;  ; =v ; ;;c=", Err(EmptyName)),
            (" ;   a=1 ;  ; =v ; ;;c===  ", Err(EmptyName)),
            ("yo", Err(MissingPair)),
        ];

        let processor: Processor = Config {
            percent_encode: false,
            crypto_rules: vec![],
            ..Default::default()
        }
        .into();

        for (string, expected) in cases {
            check_case(string, &processor, expected)
        }
    }

    #[test]
    fn parse_encoded() {
        let cases = [
            ("", cookies![]),
            (";;", cookies![]),
            ("name=value", cookies!["name" => "value"]),
            ("a=%20", cookies!["a" => " "]),
            ("a%20or%20b=1", cookies!["a or b" => "1"]),
            ("  name=value  ", cookies!["name" => "value"]),
            ("name=value  ", cookies!["name" => "value"]),
            (
                "name=value;;other=key",
                cookies!["name" => "value", "other" => "key"],
            ),
            (
                "name=value;  ;other=key",
                cookies!["name" => "value", "other" => "key"],
            ),
            (
                "name=value ;  ;other=key",
                cookies!["name" => "value", "other" => "key"],
            ),
            (
                "name=value ;  ; other=key",
                cookies!["name" => "value", "other" => "key"],
            ),
            (
                "name=value ;  ; other=key ",
                cookies!["name" => "value", "other" => "key"],
            ),
            (
                "name=value ;  ; other=key;; ",
                cookies!["name" => "value", "other" => "key"],
            ),
            (
                ";name=value ;  ; other=key ",
                cookies!["name" => "value", "other" => "key"],
            ),
            (";a=1 ;  ; b=2 ", cookies!["a" => "1", "b" => "2"]),
            (";a=1 ;  ; b= ", cookies!["a" => "1", "b" => ""]),
            (" ;   a=1 ;  ; ;;c===  ", cookies!["a" => "1", "c" => "=="]),
            (";a=1 ;  ; =v ; c=", Err(EmptyName)),
            (" ;   a=1 ;  ; =v ; ;;c=", Err(EmptyName)),
            (" ;   a=1 ;  ; =v ; ;;c===  ", Err(EmptyName)),
            ("yo", Err(MissingPair)),
            ("a=d#$%^&*()_", cookies!["a" => "d#$%^&*()_"]),
            (
                "a=%F1%F2%F3%C0%C1%C2",
                Err(ParseError::ProcessingError(ProcessIncomingError::Decoding(
                    DecodingError {
                        raw_value: "d#$%^&*()_".to_string(),
                        source: anyhow::anyhow!("invalid percent encoding"),
                    },
                ))),
            ),
        ];

        let processor: Processor = Config {
            percent_encode: true,
            crypto_rules: vec![],
            ..Default::default()
        }
        .into();

        for (string, expected) in cases {
            check_case(string, &processor, expected)
        }
    }
}
