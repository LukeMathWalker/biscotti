use jiff::Zoned;

/// A cookie's expiration: either a date-time or session.
///
/// An `Expiration` is constructible with `Expiration::from()` via any of:
///
///   * `None` -> `Expiration::Session`
///   * `Some(OffsetDateTime)` -> `Expiration::DateTime`
///   * `OffsetDateTime` -> `Expiration::DateTime`
///
/// ```rust
/// use biscotti::{Expiration, time::Zoned};
///
/// let expires = Expiration::from(None);
/// assert_eq!(expires, Expiration::Session);
///
/// let now = Zoned::now();
/// let expires = Expiration::from(now.clone());
/// assert_eq!(expires, Expiration::DateTime(now.clone()));
///
/// let expires = Expiration::from(Some(now.clone()));
/// assert_eq!(expires, Expiration::DateTime(now));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Expiration {
    /// Expiration for a "permanent" cookie at a specific date-time.
    DateTime(Zoned),
    /// Expiration for a "session" cookie. Browsers define the notion of a
    /// "session" and will automatically expire session cookies when they deem
    /// the "session" to be over. This is typically, but need not be, when the
    /// browser is closed.
    Session,
}

impl Expiration {
    /// Returns `true` if `self` is an `Expiration::DateTime`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::{Expiration, time::Zoned};
    ///
    /// let expires = Expiration::from(None);
    /// assert!(!expires.is_datetime());
    ///
    /// let expires = Expiration::from(Zoned::now());
    /// assert!(expires.is_datetime());
    /// ```
    pub fn is_datetime(&self) -> bool {
        match self {
            Expiration::DateTime(_) => true,
            Expiration::Session => false,
        }
    }

    /// Returns `true` if `self` is an `Expiration::Session`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::{Expiration, time::Zoned};
    ///
    /// let expires = Expiration::from(None);
    /// assert!(expires.is_session());
    ///
    /// let expires = Expiration::from(Zoned::now());
    /// assert!(!expires.is_session());
    /// ```
    pub fn is_session(&self) -> bool {
        match self {
            Expiration::DateTime(_) => false,
            Expiration::Session => true,
        }
    }

    /// Returns a reference to the inner [`Zoned`] value if `self` is a `DateTime`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::{Expiration, time::Zoned};
    ///
    /// let expires = Expiration::from(None);
    /// assert!(expires.datetime().is_none());
    ///
    /// let now = Zoned::now();
    /// let expires = Expiration::from(now.clone());
    /// assert_eq!(expires.datetime(), Some(&now));
    /// ```
    ///
    /// [`Zoned`]: crate::time::Zoned
    pub fn datetime(&self) -> Option<&Zoned> {
        match self {
            Expiration::Session => None,
            Expiration::DateTime(v) => Some(v),
        }
    }

    /// Applied `f` to the inner `OffsetDateTime` if `self` is a `DateTime` and
    /// returns the mapped `Expiration`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::Expiration;
    /// use biscotti::time::{Zoned, ToSpan};
    ///
    /// let now = Zoned::now();
    /// let one_week = 1.weeks();
    ///
    /// let expires = Expiration::from(now.clone());
    /// assert_eq!(
    ///     expires.map(|t| &t + one_week).datetime(),
    ///     Some(&now + one_week).as_ref()
    /// );
    ///
    /// let expires = Expiration::from(None);
    /// assert_eq!(expires.map(|t| &t + one_week).datetime(), None);
    /// ```
    pub fn map<F>(self, f: F) -> Self
    where
        F: FnOnce(Zoned) -> Zoned,
    {
        match self {
            Expiration::Session => Expiration::Session,
            Expiration::DateTime(v) => Expiration::DateTime(f(v)),
        }
    }
}

impl<T: Into<Option<Zoned>>> From<T> for Expiration {
    fn from(option: T) -> Self {
        match option.into() {
            Some(value) => Expiration::DateTime(value),
            None => Expiration::Session,
        }
    }
}
