use std::borrow::Cow;

/// A unique identifier for a [`ResponseCookie`].
///
/// It takes into account the name, domain, and path of the cookie.
///
/// # Example
///
/// ```
/// use biscotti::ResponseCookieId;
///
/// let id = ResponseCookieId::new("name");
/// assert_eq!(id.name(), "name");
/// assert_eq!(id.domain(), None);
/// assert_eq!(id.path(), None);
///
/// let id = ResponseCookieId::new("name").set_domain("rust-lang.org").set_path("/");
/// assert_eq!(id.name(), "name");
/// assert_eq!(id.domain(), Some("rust-lang.org"));
/// assert_eq!(id.path(), Some("/"));
/// ```
///
/// [`ResponseCookie`]: crate::ResponseCookie
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct ResponseCookieId<'c> {
    pub(crate) name: Cow<'c, str>,
    pub(crate) domain: Option<Cow<'c, str>>,
    pub(crate) path: Option<Cow<'c, str>>,
}

impl<'c> ResponseCookieId<'c> {
    /// Creates a new [`ResponseCookieId`] with the given name.
    pub fn new<N: Into<Cow<'c, str>>>(name: N) -> ResponseCookieId<'c> {
        ResponseCookieId {
            name: name.into(),
            domain: None,
            path: None,
        }
    }

    /// Sets the domain of the cookie.
    pub fn set_domain<P: Into<Cow<'c, str>>>(mut self, domain: P) -> ResponseCookieId<'c> {
        self.domain = Some(domain.into());
        self
    }

    /// Unsets the domain of the cookie.
    pub fn unset_domain(mut self) -> ResponseCookieId<'c> {
        self.domain = None;
        self
    }

    /// Sets the path of the cookie.
    pub fn set_path<P: Into<Cow<'c, str>>>(mut self, path: P) -> ResponseCookieId<'c> {
        self.path = Some(path.into());
        self
    }

    /// Unsets the path of the cookie.
    pub fn unset_path(mut self) -> ResponseCookieId<'c> {
        self.path = None;
        self
    }

    /// Returns the name of the cookie.
    #[inline]
    pub fn name(&self) -> &str {
        self.name.as_ref()
    }

    /// Returns the domain of the cookie, if any.
    #[inline]
    pub fn domain(&self) -> Option<&str> {
        self.domain.as_ref().map(|d| d.as_ref())
    }

    /// Returns the path of the cookie, if any.
    #[inline]
    pub fn path(&self) -> Option<&str> {
        self.path.as_ref().map(|p| p.as_ref())
    }
}

impl<'a> From<&'a str> for ResponseCookieId<'a> {
    fn from(value: &'a str) -> ResponseCookieId<'a> {
        ResponseCookieId {
            name: Cow::Borrowed(value),
            domain: None,
            path: None,
        }
    }
}
