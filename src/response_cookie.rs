use crate::{Expiration, RemovalCookie, ResponseCookieId, SameSite};
use std::borrow::Cow;
use std::fmt;
use time::format_description::FormatItem;
use time::macros::{datetime, format_description};
use time::{Duration, OffsetDateTime, UtcOffset};

/// A cookie set by a server in an HTTP response using the `Set-Cookie` header.
///
/// ## Constructing a `ResponseCookie`
///
/// To construct a cookie with only a name/value, use [`ResponseCookie::new()`]:
///
/// ```rust
/// use biscotti::ResponseCookie;
///
/// let cookie = ResponseCookie::new("name", "value");
/// assert_eq!(cookie.to_string(), "name=value");
/// ```
///
/// ## Building a `ResponseCookie`
///
/// To construct more elaborate cookies, use `ResponseCookie`'s `set_*` methods.
///
/// ```rust
/// use biscotti::ResponseCookie;
///
/// let cookie = ResponseCookie::new("name", "value")
///     .set_domain("www.rust-lang.org")
///     .set_path("/")
///     .set_secure(true)
///     .set_http_only(true);
/// ```
#[derive(Debug, Clone)]
pub struct ResponseCookie<'c> {
    /// The cookie's name.
    pub(crate) name: Cow<'c, str>,
    /// The cookie's value.
    pub(crate) value: Cow<'c, str>,
    /// The cookie's expiration, if any.
    pub(crate) expires: Option<Expiration>,
    /// The cookie's maximum age, if any.
    pub(crate) max_age: Option<Duration>,
    /// The cookie's domain, if any.
    pub(crate) domain: Option<Cow<'c, str>>,
    /// The cookie's path domain, if any.
    pub(crate) path: Option<Cow<'c, str>>,
    /// Whether this cookie was marked Secure.
    pub(crate) secure: Option<bool>,
    /// Whether this cookie was marked HttpOnly.
    pub(crate) http_only: Option<bool>,
    /// The draft `SameSite` attribute.
    pub(crate) same_site: Option<SameSite>,
    /// The draft `Partitioned` attribute.
    pub(crate) partitioned: Option<bool>,
}

impl<'c> ResponseCookie<'c> {
    /// Creates a new [`ResponseCookie`] with the given name and value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::ResponseCookie;
    ///
    /// let cookie = ResponseCookie::new("name", "value");
    /// assert_eq!(cookie.name_value(), ("name", "value"));
    ///
    /// // This is equivalent to `from` with a `(name, value)` tuple:
    /// let cookie = ResponseCookie::from(("name", "value"));
    /// assert_eq!(cookie.name_value(), ("name", "value"));
    /// ```
    pub fn new<N, V>(name: N, value: V) -> Self
    where
        N: Into<Cow<'c, str>>,
        V: Into<Cow<'c, str>>,
    {
        ResponseCookie {
            name: name.into(),
            value: value.into(),
            expires: None,
            max_age: None,
            domain: None,
            path: None,
            secure: None,
            http_only: None,
            same_site: None,
            partitioned: None,
        }
    }

    /// Converts `self` into a [`ResponseCookie`] with a static lifetime with as few
    /// allocations as possible.
    ///
    /// # Example
    ///
    /// ```
    /// use biscotti::ResponseCookie;
    ///
    /// let c = ResponseCookie::new("a", "b");
    /// let owned_cookie = c.into_owned();
    /// assert_eq!(owned_cookie.name_value(), ("a", "b"));
    /// ```
    pub fn into_owned(self) -> ResponseCookie<'static> {
        let to_owned = |s: Cow<'c, str>| match s {
            Cow::Borrowed(s) => Cow::Owned(s.to_owned()),
            Cow::Owned(s) => Cow::Owned(s),
        };
        ResponseCookie {
            name: to_owned(self.name),
            value: to_owned(self.value),
            expires: self.expires,
            max_age: self.max_age,
            domain: self.domain.map(to_owned),
            path: self.path.map(to_owned),
            secure: self.secure,
            http_only: self.http_only,
            same_site: self.same_site,
            partitioned: self.partitioned,
        }
    }

    /// Returns the name of `self`.
    ///
    /// # Example
    ///
    /// ```
    /// use biscotti::ResponseCookie;
    ///
    /// let c = ResponseCookie::new("name", "value");
    /// assert_eq!(c.name(), "name");
    /// ```
    #[inline]
    pub fn name(&self) -> &str {
        self.name.as_ref()
    }

    /// Returns the value of `self`.
    ///
    /// Does not strip surrounding quotes. See [`ResponseCookie::value_trimmed()`] for a
    /// version that does.
    ///
    /// # Example
    ///
    /// ```
    /// use biscotti::ResponseCookie;
    ///
    /// let c = ResponseCookie::new("name", "value");
    /// assert_eq!(c.value(), "value");
    ///
    /// let c = ResponseCookie::new("name", "\"value\"");
    /// assert_eq!(c.value(), "\"value\"");
    /// ```
    #[inline]
    pub fn value(&self) -> &str {
        self.value.as_ref()
    }

    /// Returns the value of `self` with surrounding double-quotes trimmed.
    ///
    /// This is _not_ the value of the cookie (_that_ is [`ResponseCookie::value()`]).
    /// Instead, this is the value with a surrounding pair of double-quotes, if
    /// any, trimmed away. Quotes are only trimmed when they form a pair and
    /// never otherwise. The trimmed value is never used for other operations,
    /// such as equality checking, on `self`.
    ///
    /// # Example
    ///
    /// ```
    /// use biscotti::ResponseCookie;
    /// let c0 = ResponseCookie::new("name", "value");
    /// assert_eq!(c0.value_trimmed(), "value");
    ///
    /// let c = ResponseCookie::new("name", "\"value\"");
    /// assert_eq!(c.value_trimmed(), "value");
    /// assert!(c != c0);
    ///
    /// let c = ResponseCookie::new("name", "\"value");
    /// assert_eq!(c.value(), "\"value");
    /// assert_eq!(c.value_trimmed(), "\"value");
    /// assert!(c != c0);
    ///
    /// let c = ResponseCookie::new("name", "\"value\"\"");
    /// assert_eq!(c.value(), "\"value\"\"");
    /// assert_eq!(c.value_trimmed(), "value\"");
    /// assert!(c != c0);
    /// ```
    #[inline]
    pub fn value_trimmed(&self) -> &str {
        #[inline(always)]
        fn trim_quotes(s: &str) -> &str {
            if s.len() < 2 {
                return s;
            }

            let bytes = s.as_bytes();
            match (bytes.first(), bytes.last()) {
                (Some(b'"'), Some(b'"')) => &s[1..(s.len() - 1)],
                _ => s,
            }
        }

        trim_quotes(self.value())
    }

    /// Returns the name and value of `self` as a tuple of `(name, value)`.
    ///
    /// # Example
    ///
    /// ```
    /// use biscotti::ResponseCookie;
    ///
    /// let c = ResponseCookie::new("name", "value");
    /// assert_eq!(c.name_value(), ("name", "value"));
    /// ```
    #[inline]
    pub fn name_value(&self) -> (&str, &str) {
        (self.name(), self.value())
    }

    /// Returns the name and [trimmed value](ResponseCookie::value_trimmed()) of `self`
    /// as a tuple of `(name, trimmed_value)`.
    ///
    /// # Example
    ///
    /// ```
    /// use biscotti::ResponseCookie;
    ///
    /// let c = ResponseCookie::new("name", "\"value\"");
    /// assert_eq!(c.name_value_trimmed(), ("name", "value"));
    /// ```
    #[inline]
    pub fn name_value_trimmed(&self) -> (&str, &str) {
        (self.name(), self.value_trimmed())
    }

    /// Returns whether this cookie was marked `HttpOnly` or not. Returns
    /// `Some(true)` when the cookie was explicitly set (manually or parsed) as
    /// `HttpOnly`, `Some(false)` when `http_only` was manually set to `false`,
    /// and `None` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use biscotti::ResponseCookie;
    ///
    /// let mut c = ResponseCookie::new("name", "value");
    /// assert_eq!(c.http_only(), None);
    ///
    /// // An explicitly set "false" value.
    /// c = c.set_http_only(false);
    /// assert_eq!(c.http_only(), Some(false));
    ///
    /// // An explicitly set "true" value.
    /// c = c.set_http_only(true);
    /// assert_eq!(c.http_only(), Some(true));
    /// ```
    #[inline]
    pub fn http_only(&self) -> Option<bool> {
        self.http_only
    }

    /// Returns whether this cookie was marked `Secure` or not. Returns
    /// `Some(true)` when the cookie was explicitly set (manually or parsed) as
    /// `Secure`, `Some(false)` when `secure` was manually set to `false`, and
    /// `None` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use biscotti::ResponseCookie;
    ///
    /// let mut c = ResponseCookie::new("name", "value");
    /// assert_eq!(c.secure(), None);
    ///
    /// // An explicitly set "false" value.
    /// c = c.set_secure(false);
    /// assert_eq!(c.secure(), Some(false));
    ///
    /// // An explicitly set "true" value.
    /// c = c.set_secure(true);
    /// assert_eq!(c.secure(), Some(true));
    /// ```
    #[inline]
    pub fn secure(&self) -> Option<bool> {
        self.secure
    }

    /// Returns the `SameSite` attribute of this cookie if one was specified.
    ///
    /// # Example
    ///
    /// ```
    /// use biscotti::{ResponseCookie, SameSite};
    ///
    /// let mut c = ResponseCookie::new("name", "value");
    /// assert_eq!(c.same_site(), None);
    ///
    /// c = c.set_same_site(SameSite::Lax);
    /// assert_eq!(c.same_site(), Some(SameSite::Lax));
    ///
    /// c = c.set_same_site(None);
    /// assert_eq!(c.same_site(), None);
    /// ```
    #[inline]
    pub fn same_site(&self) -> Option<SameSite> {
        self.same_site
    }

    /// Returns whether this cookie was marked `Partitioned` or not. Returns
    /// `Some(true)` when the cookie was explicitly set (manually or parsed) as
    /// `Partitioned`, `Some(false)` when `partitioned` was manually set to `false`,
    /// and `None` otherwise.
    ///
    /// **Note:** This cookie attribute is experimental! Its meaning and
    /// definition are not standardized and therefore subject to change.
    ///
    /// [HTTP draft]: https://github.com/privacycg/CHIPS
    ///
    /// # Example
    ///
    /// ```
    /// use biscotti::ResponseCookie;
    ///
    /// let mut c = ResponseCookie::new("name", "value");
    /// assert_eq!(c.partitioned(), None);
    ///
    /// // An explicitly set "false" value.
    /// c = c.set_partitioned(false);
    /// assert_eq!(c.partitioned(), Some(false));
    ///
    /// // An explicitly set "true" value.
    /// c = c.set_partitioned(true);
    /// assert_eq!(c.partitioned(), Some(true));
    /// ```
    #[inline]
    pub fn partitioned(&self) -> Option<bool> {
        self.partitioned
    }

    /// Returns the specified max-age of the cookie if one was specified.
    ///
    /// # Example
    ///
    /// ```
    /// use biscotti::{ResponseCookie, time::Duration};
    ///
    /// let mut c = ResponseCookie::new("name", "value");
    /// assert_eq!(c.max_age(), None);
    ///
    /// c = c.set_max_age(Duration::hours(1));
    /// assert_eq!(c.max_age().map(|age| age.whole_hours()), Some(1));
    /// ```
    #[inline]
    pub fn max_age(&self) -> Option<Duration> {
        self.max_age
    }

    /// Returns the `Path` of the cookie if one was specified.
    ///
    /// # Example
    ///
    /// ```
    /// use biscotti::ResponseCookie;
    ///
    /// let mut c = ResponseCookie::new("name", "value");
    /// assert_eq!(c.path(), None);
    ///
    /// c = c.set_path("/");
    /// assert_eq!(c.path(), Some("/"));
    ///
    /// c = c.unset_path();
    /// assert_eq!(c.path(), None);
    /// ```
    #[inline]
    pub fn path(&self) -> Option<&str> {
        match self.path {
            Some(ref c) => Some(c.as_ref()),
            None => None,
        }
    }

    /// Returns the `Domain` of the cookie if one was specified.
    ///
    /// This does not consider whether the `Domain` is valid; validation is left
    /// to higher-level libraries, as needed. However, if the `Domain` starts
    /// with a leading `.`, the leading `.` is stripped.
    ///
    /// # Example
    ///
    /// ```
    /// use biscotti::ResponseCookie;
    ///
    /// let mut c = ResponseCookie::new("name", "value");
    /// assert_eq!(c.domain(), None);
    ///
    /// c = c.set_domain("crates.io");
    /// assert_eq!(c.domain(), Some("crates.io"));
    ///
    /// c = c.set_domain(".crates.io");
    /// assert_eq!(c.domain(), Some("crates.io"));
    ///
    /// // Note that `..crates.io` is not a valid domain.
    /// c = c.set_domain("..crates.io");
    /// assert_eq!(c.domain(), Some(".crates.io"));
    ///
    /// c = c.unset_domain();
    /// assert_eq!(c.domain(), None);
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

    /// Returns the [`Expiration`] of the cookie if one was specified.
    ///
    /// # Example
    ///
    /// ```
    /// use biscotti::{ResponseCookie, Expiration};
    /// use time::{OffsetDateTime, macros::{date, time}};
    ///
    /// let mut c = ResponseCookie::new("name", "value");
    /// assert_eq!(c.expires(), None);
    ///
    /// c = c.set_expires(None);
    /// assert_eq!(c.expires(), Some(Expiration::Session));
    ///
    /// let expire_time = OffsetDateTime::new_utc(date!(2017-10-21), time!(07:28:00));
    /// c = c.set_expires(Some(expire_time));
    /// assert_eq!(c.expires().and_then(|e| e.datetime()).map(|t| t.year()), Some(2017));
    /// ```
    #[inline]
    pub fn expires(&self) -> Option<Expiration> {
        self.expires
    }

    /// Returns the expiration date-time of the cookie if one was specified.
    ///
    /// It returns `None` if the cookie is a session cookie or if the expiration
    /// was not specified.
    ///
    /// # Example
    ///
    /// ```
    /// use biscotti::{Expiration, ResponseCookie};
    /// use time::{OffsetDateTime, macros::{date, time}};
    ///
    /// let mut c = ResponseCookie::new("name", "value");
    /// assert_eq!(c.expires_datetime(), None);
    ///
    /// // Here, `cookie.expires()` returns `Some(Expiration::Session)`.
    /// c = c.set_expires(Expiration::Session);
    /// assert_eq!(c.expires_datetime(), None);
    ///
    /// let expire_time = OffsetDateTime::new_utc(date!(2017-10-21), time!(07:28:00));
    /// c = c.set_expires(Some(expire_time));
    /// assert_eq!(c.expires_datetime().map(|t| t.year()), Some(2017));
    /// ```
    #[inline]
    pub fn expires_datetime(&self) -> Option<OffsetDateTime> {
        self.expires.and_then(|e| e.datetime())
    }

    /// Sets the name of `self` to `name`.
    ///
    /// # Example
    ///
    /// ```
    /// use biscotti::ResponseCookie;
    ///
    /// let mut c = ResponseCookie::new("name", "value");
    /// assert_eq!(c.name(), "name");
    ///
    /// c = c.set_name("foo");
    /// assert_eq!(c.name(), "foo");
    /// ```
    pub fn set_name<N: Into<Cow<'c, str>>>(mut self, name: N) -> Self {
        self.name = name.into();
        self
    }

    /// Sets the value of `self` to `value`.
    ///
    /// # Example
    ///
    /// ```
    /// use biscotti::ResponseCookie;
    ///
    /// let mut c = ResponseCookie::new("name", "value");
    /// assert_eq!(c.value(), "value");
    ///
    /// c = c.set_value("bar");
    /// assert_eq!(c.value(), "bar");
    /// ```
    pub fn set_value<V: Into<Cow<'c, str>>>(mut self, value: V) -> Self {
        self.value = value.into();
        self
    }

    /// Sets the value of `http_only` in `self` to `value`.  If `value` is
    /// `None`, the field is unset.
    ///
    /// # Example
    ///
    /// ```
    /// use biscotti::ResponseCookie;
    ///
    /// let mut c = ResponseCookie::new("name", "value");
    /// assert_eq!(c.http_only(), None);
    ///
    /// c = c.set_http_only(true);
    /// assert_eq!(c.http_only(), Some(true));
    ///
    /// c = c.set_http_only(false);
    /// assert_eq!(c.http_only(), Some(false));
    ///
    /// c = c.set_http_only(None);
    /// assert_eq!(c.http_only(), None);
    /// ```
    #[inline]
    pub fn set_http_only<T: Into<Option<bool>>>(mut self, value: T) -> Self {
        self.http_only = value.into();
        self
    }

    /// Sets the value of `secure` in `self` to `value`. If `value` is `None`,
    /// the field is unset.
    ///
    /// # Example
    ///
    /// ```
    /// use biscotti::ResponseCookie;
    ///
    /// let mut c = ResponseCookie::new("name", "value");
    /// assert_eq!(c.secure(), None);
    ///
    /// c = c.set_secure(true);
    /// assert_eq!(c.secure(), Some(true));
    ///
    /// c = c.set_secure(false);
    /// assert_eq!(c.secure(), Some(false));
    ///
    /// c = c.set_secure(None);
    /// assert_eq!(c.secure(), None);
    /// ```
    #[inline]
    pub fn set_secure<T: Into<Option<bool>>>(mut self, value: T) -> Self {
        self.secure = value.into();
        self
    }

    /// Sets the value of `same_site` in `self` to `value`. If `value` is
    /// `None`, the field is unset.
    ///
    /// # Example
    ///
    /// ```
    /// use biscotti::{ResponseCookie, SameSite};
    ///
    /// let mut c = ResponseCookie::new("name", "value");
    /// assert_eq!(c.same_site(), None);
    ///
    /// c = c.set_same_site(SameSite::Strict);
    /// assert_eq!(c.same_site(), Some(SameSite::Strict));
    /// assert_eq!(c.to_string(), "name=value; SameSite=Strict");
    ///
    /// c = c.set_same_site(None);
    /// assert_eq!(c.same_site(), None);
    /// assert_eq!(c.to_string(), "name=value");
    /// ```
    ///
    /// # Example: `SameSite::None`
    ///
    /// If `value` is `SameSite::None`, the "Secure"
    /// flag will be set when the cookie is written out unless `secure` is
    /// explicitly set to `false` via [`ResponseCookie::set_secure()`] or the equivalent
    /// builder method.
    ///
    /// ```
    /// use biscotti::{ResponseCookie, SameSite};
    ///
    /// let mut c = ResponseCookie::new("name", "value");
    /// assert_eq!(c.same_site(), None);
    ///
    /// c = c.set_same_site(SameSite::None);
    /// assert_eq!(c.same_site(), Some(SameSite::None));
    /// assert_eq!(c.to_string(), "name=value; SameSite=None; Secure");
    ///
    /// c = c.set_secure(false);
    /// assert_eq!(c.to_string(), "name=value; SameSite=None");
    /// ```
    #[inline]
    pub fn set_same_site<T: Into<Option<SameSite>>>(mut self, value: T) -> Self {
        self.same_site = value.into();
        self
    }

    /// Sets the value of `partitioned` in `self` to `value`. If `value` is
    /// `None`, the field is unset.
    ///
    /// **Note:** _Partitioned_ cookies require the `Secure` attribute to be
    /// set. As such, `Partitioned` cookies are always rendered with the
    /// `Secure` attribute, irrespective of the `Secure` attribute's setting.
    ///
    /// **Note:** This cookie attribute is an [HTTP draft]! Its meaning and
    /// definition are not standardized and therefore subject to change.
    ///
    /// [HTTP draft]: https://datatracker.ietf.org/doc/draft-cutler-httpbis-partitioned-cookies/
    ///
    /// # Example
    ///
    /// ```
    /// use biscotti::ResponseCookie;
    ///
    /// let mut c = ResponseCookie::new("name", "value");
    /// assert_eq!(c.partitioned(), None);
    ///
    /// c = c.set_partitioned(true);
    /// assert_eq!(c.partitioned(), Some(true));
    /// assert!(c.to_string().contains("Secure"));
    ///
    /// c = c.set_partitioned(false);
    /// assert_eq!(c.partitioned(), Some(false));
    /// assert!(!c.to_string().contains("Secure"));
    ///
    /// c = c.set_partitioned(None);
    /// assert_eq!(c.partitioned(), None);
    /// assert!(!c.to_string().contains("Secure"));
    /// ```
    #[inline]
    pub fn set_partitioned<T: Into<Option<bool>>>(mut self, value: T) -> Self {
        self.partitioned = value.into();
        self
    }

    /// Sets the value of `max_age` in `self` to `value`. If `value` is `None`,
    /// the field is unset.
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::ResponseCookie;
    /// use biscotti::time::Duration;
    ///
    /// # fn main() {
    /// let mut c = ResponseCookie::new("name", "value");
    /// assert_eq!(c.max_age(), None);
    ///
    /// c = c.set_max_age(Duration::hours(10));
    /// assert_eq!(c.max_age(), Some(Duration::hours(10)));
    ///
    /// c = c.set_max_age(None);
    /// assert!(c.max_age().is_none());
    /// # }
    /// ```
    #[inline]
    pub fn set_max_age<D: Into<Option<Duration>>>(mut self, value: D) -> Self {
        self.max_age = value.into();
        self
    }

    /// Sets the `path` of `self` to `path`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::ResponseCookie;
    ///
    /// let mut c = ResponseCookie::new("name", "value");
    /// assert_eq!(c.path(), None);
    ///
    /// c = c.set_path("/");
    /// assert_eq!(c.path(), Some("/"));
    /// ```
    pub fn set_path<P: Into<Cow<'c, str>>>(mut self, path: P) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Unsets the `path` of `self`.
    ///
    /// # Example
    ///
    /// ```
    /// use biscotti::ResponseCookie;
    ///
    /// let mut c = ResponseCookie::new("name", "value");
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
    /// use biscotti::ResponseCookie;
    ///
    /// let mut c = ResponseCookie::new("name", "value");
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
    /// use biscotti::ResponseCookie;
    ///
    /// let mut c = ResponseCookie::new("name", "value");
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

    /// Sets the expires field of `self` to `time`. If `time` is `None`, an
    /// expiration of [`Session`](Expiration::Session) is set.
    ///
    /// # Example
    ///
    /// ```
    /// use biscotti::{ResponseCookie, Expiration};
    /// use biscotti::time::{Duration, OffsetDateTime};
    ///
    /// let mut c = ResponseCookie::new("name", "value");
    /// assert_eq!(c.expires(), None);
    ///
    /// let mut now = OffsetDateTime::now_utc();
    /// now += Duration::weeks(52);
    ///
    /// c = c.set_expires(now);
    /// assert!(c.expires().is_some());
    ///
    /// c = c.set_expires(None);
    /// assert_eq!(c.expires(), Some(Expiration::Session));
    /// ```
    pub fn set_expires<T: Into<Expiration>>(mut self, time: T) -> Self {
        static MAX_DATETIME: OffsetDateTime = datetime!(9999-12-31 23:59:59.999_999 UTC);

        // RFC 6265 requires dates not to exceed 9999 years.
        self.expires = Some(time.into().map(|time| std::cmp::min(time, MAX_DATETIME)));
        self
    }

    /// Unsets the `expires` of `self`.
    ///
    /// # Example
    ///
    /// ```
    /// use biscotti::{ResponseCookie, Expiration};
    ///
    /// let mut c = ResponseCookie::new("name", "value");
    /// assert_eq!(c.expires(), None);
    ///
    /// c = c.set_expires(None);
    /// assert_eq!(c.expires(), Some(Expiration::Session));
    ///
    /// c = c.unset_expires();
    /// assert_eq!(c.expires(), None);
    /// ```
    pub fn unset_expires(mut self) -> Self {
        self.expires = None;
        self
    }

    /// Makes `self` a "permanent" cookie by extending its expiration and max
    /// age 20 years into the future.
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::ResponseCookie;
    /// use biscotti::time::Duration;
    ///
    /// # fn main() {
    /// let mut c = ResponseCookie::new("foo", "bar");
    /// assert!(c.expires().is_none());
    /// assert!(c.max_age().is_none());
    ///
    /// c = c.make_permanent();
    /// assert!(c.expires().is_some());
    /// assert_eq!(c.max_age(), Some(Duration::days(365 * 20)));
    /// # }
    /// ```
    pub fn make_permanent(self) -> Self {
        let twenty_years = Duration::days(365 * 20);
        self.set_max_age(twenty_years)
            .set_expires(OffsetDateTime::now_utc() + twenty_years)
    }

    /// Make `self` a "removal" cookie by clearing its value and
    /// setting an expiration date far in the past.
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::ResponseCookie;
    /// use biscotti::time::{Duration, OffsetDateTime};
    ///
    /// # fn main() {
    /// let c = ResponseCookie::new("foo", "bar");
    /// let removal = c.into_removal();
    ///
    /// // You can convert a `RemovalCookie` back into a "raw" `ResponseCookie`
    /// // to inspect its properties.
    /// let raw: ResponseCookie = removal.into();
    /// assert_eq!(raw.value(), "");
    /// let expiration = raw.expires_datetime().unwrap();
    /// assert!(expiration < OffsetDateTime::now_utc());
    /// # }
    /// ```
    pub fn into_removal(self) -> RemovalCookie<'c> {
        let mut c = RemovalCookie::new(self.name);
        if let Some(path) = self.path {
            c = c.set_path(path);
        }
        if let Some(domain) = self.domain {
            c = c.set_domain(domain);
        }
        c
    }

    /// Returns a [`ResponseCookieId`] that can be used to identify `self` in a
    /// collection of response cookies.
    ///
    /// It takes into account the `name`, `domain`, and `path` of `self`.
    pub fn id(&self) -> ResponseCookieId<'c> {
        let mut id = ResponseCookieId::new(self.name.clone());
        if let Some(path) = self.path.as_ref() {
            id = id.set_path(path.clone());
        }
        if let Some(domain) = self.domain.as_ref() {
            id = id.set_domain(domain.clone());
        }
        id
    }

    fn fmt_parameters(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(true) = self.http_only() {
            write!(f, "; HttpOnly")?;
        }

        if let Some(same_site) = self.same_site() {
            write!(f, "; SameSite={}", same_site)?;
        }

        if let Some(true) = self.partitioned() {
            write!(f, "; Partitioned")?;
        }

        if self.secure() == Some(true)
            || self.partitioned() == Some(true)
            || self.secure().is_none() && self.same_site() == Some(SameSite::None)
        {
            write!(f, "; Secure")?;
        }

        if let Some(path) = self.path() {
            write!(f, "; Path={}", path)?;
        }

        if let Some(domain) = self.domain() {
            write!(f, "; Domain={}", domain)?;
        }

        if let Some(max_age) = self.max_age() {
            write!(f, "; Max-Age={}", max_age.whole_seconds())?;
        }

        if let Some(time) = self.expires_datetime() {
            let time = time.to_offset(UtcOffset::UTC);

            // From http://tools.ietf.org/html/rfc2616#section-3.3.1.
            static FMT1: &[FormatItem<'_>] = format_description!("[weekday repr:short], [day] [month repr:short] [year padding:none] [hour]:[minute]:[second] GMT");
            write!(
                f,
                "; Expires={}",
                time.format(&FMT1).map_err(|_| fmt::Error)?
            )?;
        }

        Ok(())
    }
}

impl<'c> fmt::Display for ResponseCookie<'c> {
    /// Formats the cookie `self` as a `Set-Cookie` header value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::ResponseCookie;
    ///
    /// let cookie = ResponseCookie::new("foo", "bar").set_path("/");
    /// assert_eq!(cookie.to_string(), "foo=bar; Path=/");
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}={}", self.name(), self.value())?;
        self.fmt_parameters(f)
    }
}

impl<'a, 'b> PartialEq<ResponseCookie<'b>> for ResponseCookie<'a> {
    fn eq(&self, other: &ResponseCookie<'b>) -> bool {
        let so_far_so_good = self.name() == other.name()
            && self.value() == other.value()
            && self.http_only() == other.http_only()
            && self.secure() == other.secure()
            && self.partitioned() == other.partitioned()
            && self.max_age() == other.max_age()
            && self.expires() == other.expires();

        if !so_far_so_good {
            return false;
        }

        match (self.path(), other.path()) {
            (Some(a), Some(b)) if a.eq_ignore_ascii_case(b) => {}
            (None, None) => {}
            _ => return false,
        };

        match (self.domain(), other.domain()) {
            (Some(a), Some(b)) if a.eq_ignore_ascii_case(b) => {}
            (None, None) => {}
            _ => return false,
        };

        true
    }
}

impl<'a, N, V> From<(N, V)> for ResponseCookie<'a>
where
    N: Into<Cow<'a, str>>,
    V: Into<Cow<'a, str>>,
{
    fn from((name, value): (N, V)) -> Self {
        ResponseCookie::new(name, value)
    }
}

impl<'a> AsRef<ResponseCookie<'a>> for ResponseCookie<'a> {
    fn as_ref(&self) -> &ResponseCookie<'a> {
        self
    }
}

impl<'a> AsMut<ResponseCookie<'a>> for ResponseCookie<'a> {
    fn as_mut(&mut self) -> &mut ResponseCookie<'a> {
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::{ResponseCookie, SameSite};
    use time::{Date, Duration, Month, OffsetDateTime};

    #[test]
    fn format() {
        let cookie = ResponseCookie::new("foo", "bar");
        assert_eq!(&cookie.to_string(), "foo=bar");

        let cookie = ResponseCookie::new("foo", "bar").set_http_only(true);
        assert_eq!(&cookie.to_string(), "foo=bar; HttpOnly");

        let cookie = ResponseCookie::new("foo", "bar").set_max_age(Duration::seconds(10));
        assert_eq!(&cookie.to_string(), "foo=bar; Max-Age=10");

        let cookie = ResponseCookie::new("foo", "bar").set_secure(true);
        assert_eq!(&cookie.to_string(), "foo=bar; Secure");

        let cookie = ResponseCookie::new("foo", "bar").set_path("/");
        assert_eq!(&cookie.to_string(), "foo=bar; Path=/");

        let cookie = ResponseCookie::new("foo", "bar").set_domain("www.rust-lang.org");
        assert_eq!(&cookie.to_string(), "foo=bar; Domain=www.rust-lang.org");

        let cookie = ResponseCookie::new("foo", "bar").set_domain(".rust-lang.org");
        assert_eq!(&cookie.to_string(), "foo=bar; Domain=rust-lang.org");

        let cookie = ResponseCookie::new("foo", "bar").set_domain("rust-lang.org");
        assert_eq!(&cookie.to_string(), "foo=bar; Domain=rust-lang.org");

        let expires = OffsetDateTime::new_in_offset(
            Date::from_calendar_date(2015, Month::October, 21).unwrap(),
            time::macros::time!(07:28:00),
            time::UtcOffset::UTC,
        );
        let cookie = ResponseCookie::new("foo", "bar").set_expires(expires);
        assert_eq!(
            &cookie.to_string(),
            "foo=bar; Expires=Wed, 21 Oct 2015 07:28:00 GMT"
        );

        let cookie = ResponseCookie::new("foo", "bar").set_same_site(SameSite::Strict);
        assert_eq!(&cookie.to_string(), "foo=bar; SameSite=Strict");

        let cookie = ResponseCookie::new("foo", "bar").set_same_site(SameSite::Lax);
        assert_eq!(&cookie.to_string(), "foo=bar; SameSite=Lax");

        let mut cookie = ResponseCookie::new("foo", "bar").set_same_site(SameSite::None);
        assert_eq!(&cookie.to_string(), "foo=bar; SameSite=None; Secure");

        cookie = cookie.set_partitioned(true);
        assert_eq!(
            &cookie.to_string(),
            "foo=bar; SameSite=None; Partitioned; Secure"
        );

        cookie = cookie.set_same_site(None);
        assert_eq!(&cookie.to_string(), "foo=bar; Partitioned; Secure");

        cookie = cookie.set_secure(false);
        assert_eq!(&cookie.to_string(), "foo=bar; Partitioned; Secure");

        cookie = cookie.set_secure(None);
        assert_eq!(&cookie.to_string(), "foo=bar; Partitioned; Secure");

        cookie = cookie.set_partitioned(None);
        assert_eq!(&cookie.to_string(), "foo=bar");

        let mut c = ResponseCookie::new("foo", "bar")
            .set_same_site(SameSite::None)
            .set_secure(false);
        assert_eq!(&c.to_string(), "foo=bar; SameSite=None");
        c = c.set_secure(true);
        assert_eq!(&c.to_string(), "foo=bar; SameSite=None; Secure");
    }

    #[test]
    #[ignore]
    fn format_date_wraps() {
        let expires = OffsetDateTime::UNIX_EPOCH + Duration::MAX;
        let cookie = ResponseCookie::new("foo", "bar").set_expires(expires);
        assert_eq!(
            &cookie.to_string(),
            "foo=bar; Expires=Fri, 31 Dec 9999 23:59:59 GMT"
        );

        let expires = time::macros::datetime!(9999-01-01 0:00 UTC) + Duration::days(1000);
        let cookie = ResponseCookie::new("foo", "bar").set_expires(expires);
        assert_eq!(
            &cookie.to_string(),
            "foo=bar; Expires=Fri, 31 Dec 9999 23:59:59 GMT"
        );
    }
}
