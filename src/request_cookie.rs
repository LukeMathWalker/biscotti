use std::borrow::Cow;

/// A cookie set by a client in an HTTP request using the `Cookie` header.
///
/// ## Constructing a `RequestCookie`
///
/// To construct a cookie with only a name/value, use [`RequestCookie::new()`]:
///
/// ```rust
/// use biscotti::RequestCookie;
///
/// let cookie = RequestCookie::new("name", "value");
/// assert_eq!(cookie.to_string(), "name=value");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RequestCookie<'c> {
    /// The cookie's name.
    pub(crate) name: Cow<'c, str>,
    /// The cookie's value.
    pub(crate) value: Cow<'c, str>,
}

impl<'c> RequestCookie<'c> {
    /// Creates a new [`RequestCookie`] with the given `name` and `value`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::RequestCookie;
    ///
    /// let cookie = RequestCookie::new("name", "value");
    /// assert_eq!(cookie.to_string(), "name=value");
    /// ```
    pub fn new<N, V>(name: N, value: V) -> RequestCookie<'c>
    where
        N: Into<Cow<'c, str>>,
        V: Into<Cow<'c, str>>,
    {
        RequestCookie {
            name: name.into(),
            value: value.into(),
        }
    }

    /// Returns the name of this cookie.
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::RequestCookie;
    ///
    /// let cookie = RequestCookie::new("name", "value");
    /// assert_eq!(cookie.name(), "name");
    /// ```
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the value of this cookie.
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::RequestCookie;
    ///
    /// let cookie = RequestCookie::new("name", "value");
    /// assert_eq!(cookie.value(), "value");
    /// ```
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl std::fmt::Display for RequestCookie<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}={}", self.name, self.value)
    }
}
