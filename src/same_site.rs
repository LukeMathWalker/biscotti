//! This module contains types that represent cookie properties that are not yet
//! standardized. That is, _draft_ features.

use std::fmt;

/// The `SameSite` cookie attribute.
///
/// A cookie with a `SameSite` attribute is imposed restrictions on when it is
/// sent to the origin server in a cross-site request. If the `SameSite`
/// attribute is "Strict", then the cookie is never sent in cross-site requests.
/// If the `SameSite` attribute is "Lax", the cookie is only sent in cross-site
/// requests with "safe" HTTP methods, i.e, `GET`, `HEAD`, `OPTIONS`, `TRACE`.
/// If the `SameSite` attribute is "None", the cookie is sent in all cross-site
/// requests if the "Secure" flag is also set, otherwise the cookie is ignored.
/// This library automatically sets the "Secure" flag on cookies when
/// `same_site` is set to `SameSite::None` as long as `secure` is not explicitly
/// set to `false`.
///
/// If the `SameSite` attribute is not present (by not setting `SameSite`
/// initally or passing `None` to [`Cookie::set_same_site()`]), then the cookie
/// will be sent as normal.
///
/// **Note:** This cookie attribute is an [HTTP draft]! Its meaning and
/// definition are subject to change.
///
/// [`Cookie::set_same_site()`]: crate::ResponseCookie::set_same_site()
/// [HTTP draft]: https://tools.ietf.org/html/draft-west-cookie-incrementalism-00
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum SameSite {
    /// The "Strict" `SameSite` attribute.
    #[cfg_attr(feature = "serde", serde(alias = "strict"))]
    Strict,
    /// The "Lax" `SameSite` attribute.
    #[cfg_attr(feature = "serde", serde(alias = "lax"))]
    Lax,
    /// The "None" `SameSite` attribute.
    #[cfg_attr(feature = "serde", serde(alias = "none"))]
    None,
}

impl SameSite {
    /// Returns `true` if `self` is `SameSite::Strict` and `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::SameSite;
    ///
    /// let strict = SameSite::Strict;
    /// assert!(strict.is_strict());
    /// assert!(!strict.is_lax());
    /// assert!(!strict.is_none());
    /// ```
    #[inline]
    pub fn is_strict(&self) -> bool {
        match *self {
            SameSite::Strict => true,
            SameSite::Lax | SameSite::None => false,
        }
    }

    /// Returns `true` if `self` is `SameSite::Lax` and `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::SameSite;
    ///
    /// let lax = SameSite::Lax;
    /// assert!(lax.is_lax());
    /// assert!(!lax.is_strict());
    /// assert!(!lax.is_none());
    /// ```
    #[inline]
    pub fn is_lax(&self) -> bool {
        match *self {
            SameSite::Lax => true,
            SameSite::Strict | SameSite::None => false,
        }
    }

    /// Returns `true` if `self` is `SameSite::None` and `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::SameSite;
    ///
    /// let none = SameSite::None;
    /// assert!(none.is_none());
    /// assert!(!none.is_lax());
    /// assert!(!none.is_strict());
    /// ```
    #[inline]
    pub fn is_none(&self) -> bool {
        match *self {
            SameSite::None => true,
            SameSite::Lax | SameSite::Strict => false,
        }
    }

    /// Returns the `SameSite` attribute as a string slice.
    pub fn as_str(&self) -> &'static str {
        match *self {
            SameSite::Strict => "Strict",
            SameSite::Lax => "Lax",
            SameSite::None => "None",
        }
    }
}

impl fmt::Display for SameSite {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
