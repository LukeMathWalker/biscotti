use std::borrow::Cow;
use std::collections::HashMap;

use crate::errors::{CryptoError, DecodingError};
use crate::processor::{ProcessIncomingError, Processor};
use crate::request::CookiesForName;
use crate::RequestCookie;

#[derive(Default, Debug, Clone)]
/// A collection of [`RequestCookie`]s attached to an HTTP request using the `Cookie` header.
pub struct RequestCookies<'cookie> {
    /// Invariant: the `Vec` for a given `name` is never empty.
    cookies: HashMap<Cow<'cookie, str>, Vec<Cow<'cookie, str>>>,
}

impl<'cookie> RequestCookies<'cookie> {
    /// Creates a new, empty [`RequestCookies`] map.
    pub fn new() -> RequestCookies<'cookie> {
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
        C: Into<RequestCookie<'cookie>>,
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
        C: Into<RequestCookie<'cookie>>,
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
    pub fn get<'map, 'key>(&'map self, name: &'key str) -> Option<RequestCookie<'cookie>> {
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
    pub fn get_all<'map, 'key>(
        &'map self,
        name: &'key str,
    ) -> Option<CookiesForName<'map, 'cookie>> {
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
        header: &'cookie str,
        processor: &Processor,
    ) -> Result<RequestCookies<'cookie>, ParseError> {
        Self::parse_headers(std::iter::once(header), processor)
    }

    /// Parse a `Cookie` header value and append its value to the existing [`RequestCookies`] map.
    pub fn extend_from_header(
        &mut self,
        header: &'cookie str,
        processor: &Processor,
    ) -> Result<(), ParseError> {
        for cookie in header.split(';') {
            if cookie.chars().all(char::is_whitespace) {
                continue;
            }

            let (name, value) = match cookie.split_once('=') {
                Some((name, value)) => (name.trim(), value.trim()),
                None => {
                    let e = MissingPairError {
                        fragment: cookie.to_string(),
                    };
                    return Err(ParseError::MissingPair(e));
                }
            };

            if name.is_empty() {
                let e = EmptyNameError {
                    value: value.to_string(),
                };
                return Err(ParseError::EmptyName(e));
            }

            let cookie = match processor.process_incoming(name, value) {
                Ok(c) => c,
                Err(e) => {
                    return match e {
                        ProcessIncomingError::Crypto(e) => Err(ParseError::Crypto(e)),
                        ProcessIncomingError::Decoding(e) => Err(ParseError::Decoding(e)),
                    }
                }
            };

            self.append(cookie);
        }
        Ok(())
    }

    /// Parse multiple `Cookie` header values into a [`RequestCookies`] map.
    pub fn parse_headers<I>(
        headers: I,
        processor: &Processor,
    ) -> Result<RequestCookies<'cookie>, ParseError>
    where
        I: IntoIterator<Item = &'cookie str>,
    {
        let mut cookies = RequestCookies::new();
        for header in headers {
            cookies.extend_from_header(header, processor)?;
        }
        Ok(cookies)
    }
}

#[derive(Debug)]
#[non_exhaustive]
/// The error returned by [`RequestCookies::parse_header()`].
pub enum ParseError {
    MissingPair(MissingPairError),
    EmptyName(EmptyNameError),
    Crypto(CryptoError),
    Decoding(DecodingError),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Failed to parse cookies out of a header value")
    }
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParseError::MissingPair(e) => Some(e),
            ParseError::EmptyName(e) => Some(e),
            ParseError::Crypto(e) => Some(e),
            ParseError::Decoding(e) => Some(e),
        }
    }
}

#[derive(Debug)]
/// An error that occurs when parsing a fragment of a `Cookie` header value
/// that doesn't contain a name-value separator (`=`).
pub struct MissingPairError {
    fragment: String,
}

impl std::fmt::Display for MissingPairError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Expected a name-value pair, but no `=` was found in `{}`",
            self.fragment
        )
    }
}

impl std::error::Error for MissingPairError {}

#[derive(Debug)]
/// An error that occurs when parsing a fragment of a `Cookie` header value
/// that contains an empty name (e.g. `=value`).
pub struct EmptyNameError {
    value: String,
}

impl std::fmt::Display for EmptyNameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "The name of a cookie cannot be empty, but found an empty name with `{}` as value",
            self.value
        )
    }
}

impl std::error::Error for EmptyNameError {}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use googletest::matcher::{Matcher, MatcherResult};
    use googletest::prelude::{displays_as, eq};

    use crate::ProcessorConfig;
    use crate::{Processor, RequestCookie, RequestCookies};

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
    fn check_case<'a>(
        string: &'a str,
        processor: &Processor,
        expected: Result<RequestCookies<'a>, Box<dyn Matcher<ActualT = String>>>,
    ) {
        let actual = RequestCookies::parse_header(string, processor);
        match &actual {
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
            Err(err) => {
                let source = err.source().unwrap().to_string();
                let matcher = expected.expect_err(&format!("Expected an error for {string}"));
                let error = format!(
                    "Expected: {}\n\
                    Actual: {err},\n\
                    {}\n",
                    matcher.describe(MatcherResult::Match),
                    matcher.explain_match(&source)
                );
                assert!(matcher.matches(&source).is_match(), "{error}");
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
            (";a=1 ;  ; =v ; c=", Err(err_str("The name of a cookie cannot be empty, but found an empty name with `v` as value"))),
            (" ;   a=1 ;  ; =v ; ;;c=", Err(err_str("The name of a cookie cannot be empty, but found an empty name with `v` as value"))),
            (" ;   a=1 ;  ; =v ; ;;c===  ", Err(err_str("The name of a cookie cannot be empty, but found an empty name with `v` as value"))),
            ("yo", Err(err_str("Expected a name-value pair, but no `=` was found in `yo`"))),
        ];

        let processor: Processor = ProcessorConfig {
            percent_encode: false,
            crypto_rules: vec![],
            ..Default::default()
        }
        .into();

        for (string, expected) in cases {
            check_case(string, &processor, expected)
        }
    }

    fn boxed<T>(matcher: impl Matcher<ActualT = T> + 'static) -> Box<dyn Matcher<ActualT = T>> {
        Box::new(matcher)
    }

    fn err_str(s: &'static str) -> Box<dyn Matcher<ActualT = String>> {
        boxed(displays_as(eq(s)))
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
            (";a=1 ;  ; =v ; c=", Err(err_str("The name of a cookie cannot be empty, but found an empty name with `v` as value"))),
            (" ;   a=1 ;  ; =v ; ;;c=", Err(err_str("The name of a cookie cannot be empty, but found an empty name with `v` as value"))),
            (" ;   a=1 ;  ; =v ; ;;c===  ", Err(err_str("The name of a cookie cannot be empty, but found an empty name with `v` as value"))),
            ("yo", Err(err_str("Expected a name-value pair, but no `=` was found in `yo`"))),
            ("a=d#$%^&*()_", cookies!["a" => "d#$%^&*()_"]),
            (
                "a=%F1%F2%F3%C0%C1%C2",
                Err(err_str(
                    "Failed to percent-decode the value of the `a` cookie: `%F1%F2%F3%C0%C1%C2`",
                )),
            ),
        ];

        let processor: Processor = ProcessorConfig {
            percent_encode: true,
            crypto_rules: vec![],
            ..Default::default()
        }
        .into();

        for (string, expected) in cases {
            check_case(string, &processor, expected)
        }
    }

    #[test]
    fn get_lifetime() {
        let mut cookies: RequestCookies<'static> = RequestCookies::new();
        cookies.append(RequestCookie::new("name", "value"));

        // This is a compile-time test to ensure that we can retrieve
        // cookies using a key with a shorter lifetime than the cookies themselves.
        let key = "name".to_string();
        cookies.get(key.as_str());
    }
}
