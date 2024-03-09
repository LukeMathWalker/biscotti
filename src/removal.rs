use crate::{ResponseCookie, ResponseCookieId};
use std::borrow::Cow;
use std::fmt::Debug;

#[derive(Debug, Clone)]
/// A [`ResponseCookie`] that, when sent to the client,
/// removes a cookie with the same [`ResponseCookieId`] from the client's machine, if it exists.
///
/// See [`ResponseCookies`]'s documentation for more details on cookie deletion.
///
/// [`ResponseCookies`]: crate::ResponseCookies
pub struct RemovalCookie<'c> {
    /// The cookie's name.
    pub(crate) name: Cow<'c, str>,
    /// The cookie's domain, if any.
    pub(crate) domain: Option<Cow<'c, str>>,
    /// The cookie's path domain, if any.
    pub(crate) path: Option<Cow<'c, str>>,
}

impl<'c> RemovalCookie<'c> {
    /// Creates a new [`RemovalCookie`] with the given name.
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::RemovalCookie;
    ///
    /// let removal = RemovalCookie::new("name")
    ///     .set_path("/");
    /// assert_eq!(removal.name(), "name");
    /// assert_eq!(removal.path(), Some("/"));
    /// assert_eq!(removal.domain(), None);
    /// ```
    pub fn new<N>(name: N) -> Self
    where
        N: Into<Cow<'c, str>>,
    {
        Self {
            name: name.into(),
            domain: None,
            path: None,
        }
    }

    /// Returns the name of `self`.
    ///
    /// # Example
    ///
    /// ```
    /// use biscotti::RemovalCookie;
    ///
    /// let c = RemovalCookie::new("name");
    /// assert_eq!(c.name(), "name");
    /// ```
    #[inline]
    pub fn name(&self) -> &str {
        self.name.as_ref()
    }

    /// Returns the `Path` of the [`RemovalCookie`] if one was specified.
    ///
    /// # Example
    ///
    /// ```
    /// use biscotti::RemovalCookie;
    ///
    /// let c = RemovalCookie::new("name");
    /// assert_eq!(c.path(), None);
    ///
    /// let c = RemovalCookie::new("name").set_path("/");
    /// assert_eq!(c.path(), Some("/"));
    ///
    /// let c = RemovalCookie::new("name").set_path("/sub");
    /// assert_eq!(c.path(), Some("/sub"));
    /// ```
    #[inline]
    pub fn path(&self) -> Option<&str> {
        match self.path {
            Some(ref c) => Some(c.as_ref()),
            None => None,
        }
    }

    /// Returns the `Domain` of the [`RemovalCookie`] if one was specified.
    ///
    /// This does not consider whether the `Domain` is valid; validation is left
    /// to higher-level libraries, as needed. However, if the `Domain` starts
    /// with a leading `.`, the leading `.` is stripped.
    ///
    /// # Example
    ///
    /// ```
    /// use biscotti::RemovalCookie;
    ///
    /// let c = RemovalCookie::new("name");
    /// assert_eq!(c.domain(), None);
    ///
    /// let c = RemovalCookie::new("name").set_domain("crates.io");
    /// assert_eq!(c.domain(), Some("crates.io"));
    ///
    /// let c = RemovalCookie::new("name").set_domain(".crates.io");
    /// assert_eq!(c.domain(), Some("crates.io"));
    ///
    /// // Note that `..crates.io` is not a valid domain.
    /// let c = RemovalCookie::new("name").set_domain("..crates.io");
    /// assert_eq!(c.domain(), Some(".crates.io"));
    /// ```
    #[inline]
    pub fn domain(&self) -> Option<&str> {
        match self.domain {
            Some(ref c) => {
                let domain = c.as_ref();
                domain.strip_prefix('.').or(Some(domain))
            }
            None => None,
        }
    }

    /// Converts `self` into a `RemovalCookie` with a `'static` lifetime with as few
    /// allocations as possible.
    pub fn into_owned(self) -> RemovalCookie<'static> {
        let to_owned = |s: Cow<'c, str>| match s {
            Cow::Borrowed(s) => Cow::Owned(s.to_owned()),
            Cow::Owned(s) => Cow::Owned(s),
        };
        RemovalCookie {
            name: to_owned(self.name),
            domain: self.domain.map(to_owned),
            path: self.path.map(to_owned),
        }
    }
}

/// Methods to set fields in a [`RemovalCookie`].
impl<'c> RemovalCookie<'c> {
    /// Sets the name of this removal cookie, replacing the current name.
    /// It returns the modified removal cookie.
    ///
    /// # Example
    ///
    /// ```
    /// use biscotti::RemovalCookie;
    ///
    /// let mut c = RemovalCookie::new("name");
    /// assert_eq!(c.name(), "name");
    ///
    /// c = c.set_name("foo");
    /// assert_eq!(c.name(), "foo");
    /// ```
    pub fn set_name<N: Into<Cow<'c, str>>>(mut self, name: N) -> Self {
        self.name = name.into();
        self
    }

    /// Sets the path property of the removal cookie to `path`.
    /// It returns the modified removal cookie.
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::RemovalCookie;
    ///
    /// let mut c = RemovalCookie::new("name");
    /// assert_eq!(c.path(), None);
    ///
    /// c = c.set_path("/");
    /// assert_eq!(c.path(), Some("/"));
    /// ```
    pub fn set_path<P: Into<Cow<'c, str>>>(mut self, path: P) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Unsets the `path` property of the removal cookie.
    /// It returns the modified removal cookie.
    ///
    /// # Example
    ///
    /// ```
    /// use biscotti::RemovalCookie;
    ///
    /// let mut c = RemovalCookie::new("name");
    /// assert_eq!(c.path(), None);
    ///
    /// c = c.set_path("/");
    /// assert_eq!(c.path(), Some("/"));
    ///
    /// c = c.unset_path();
    /// assert_eq!(c.path(), None);
    /// ```
    pub fn unset_path(mut self) -> Self {
        self.path = None;
        self
    }

    /// Sets the `domain` of `self` to `domain`.
    ///
    /// # Example
    ///
    /// ```
    /// use biscotti::RemovalCookie;
    ///
    /// let mut c = RemovalCookie::new("name");
    /// assert_eq!(c.domain(), None);
    ///
    /// c = c.set_domain("rust-lang.org");
    /// assert_eq!(c.domain(), Some("rust-lang.org"));
    /// ```
    pub fn set_domain<D: Into<Cow<'c, str>>>(mut self, domain: D) -> Self {
        self.domain = Some(domain.into());
        self
    }

    /// Unsets the `domain` of `self`.
    ///
    /// # Example
    ///
    /// ```
    /// use biscotti::RemovalCookie;
    ///
    /// let mut c = RemovalCookie::new("name");
    /// assert_eq!(c.domain(), None);
    ///
    /// c = c.set_domain("rust-lang.org");
    /// assert_eq!(c.domain(), Some("rust-lang.org"));
    ///
    /// c = c.unset_domain();
    /// assert_eq!(c.domain(), None);
    /// ```
    pub fn unset_domain(mut self) -> Self {
        self.domain = None;
        self
    }
}

impl<'c> From<RemovalCookie<'c>> for ResponseCookie<'c> {
    fn from(value: RemovalCookie<'c>) -> Self {
        let mut c = ResponseCookie::new(value.name, "");
        if let Some(domain) = value.domain {
            c = c.set_domain(domain);
        }
        if let Some(path) = value.path {
            c = c.set_path(path);
        }
        // A date in the past to ensure the client removes the cookie.
        c = c.set_expires(time::OffsetDateTime::from_unix_timestamp(0).unwrap());
        c
    }
}

impl<'c> From<ResponseCookieId<'c>> for RemovalCookie<'c> {
    fn from(value: ResponseCookieId<'c>) -> Self {
        RemovalCookie {
            name: value.name,
            domain: value.domain,
            path: value.path,
        }
    }
}
