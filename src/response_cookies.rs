use std::collections::hash_map::Values;
use std::collections::HashMap;

use crate::{Processor, ResponseCookie, ResponseCookieId};

/// A collection of [`ResponseCookie`]s to be attached to an HTTP response
/// using the `Set-Cookie` header.
///
/// # Adding a cookie
///
/// A set's life begins via [`ResponseCookies::new()`] and calls to
/// [`ResponseCookies::insert()`]:
///
/// ```rust
/// use biscotti::{ResponseCookie, ResponseCookies};
///
/// let mut set = ResponseCookies::new();
/// set.insert(("name", "value"));
/// set.insert(("second", "another"));
/// set.insert(ResponseCookie::new("third", "again").set_path("/"));
/// ```
///
/// # Removing a cookie
///
/// If you want to tell the client to remove a cookie, you need to
/// insert a [`RemovalCookie`] into the set.  
/// Note that any `T: Into<ResponseCookie>` can be passed into
/// these methods.
///
/// ```rust
/// use biscotti::{ResponseCookie, ResponseCookies, RemovalCookie, ResponseCookieId};
///
/// let mut set = ResponseCookies::new();
/// let removal = RemovalCookie::new("name").set_path("/");
/// // This will tell the client to remove the cookie with name "name"
/// // and path "/".
/// set.insert(removal);
///
/// // If you insert a cookie with the same name and path, it will replace
/// // the removal cookie.
/// let cookie = ResponseCookie::new("name", "value").set_path("/");
/// set.insert(cookie);
///
/// let retrieved = set.get(ResponseCookieId::new("name").set_path("/")).unwrap();
/// assert_eq!(retrieved.value(), "value");
/// ```
///
/// If you want to remove a cookie from the set without telling the client to remove it,
/// you can use [`ResponseCookies::discard()`].
///
/// # Retrieving a cookie
///
/// Cookies can be retrieved with [`ResponseCookies::get()`].  
/// Check the method's documentation for more information.
///
/// [`RemovalCookie`]: crate::RemovalCookie
#[derive(Default, Debug, Clone)]
pub struct ResponseCookies<'c> {
    cookies: HashMap<ResponseCookieId<'c>, ResponseCookie<'c>>,
}

impl<'c> ResponseCookies<'c> {
    /// Creates an empty cookie set.
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::ResponseCookies;
    ///
    /// let set = ResponseCookies::new();
    /// assert_eq!(set.iter().count(), 0);
    /// ```
    pub fn new() -> ResponseCookies<'c> {
        ResponseCookies::default()
    }

    /// Returns a reference to the [`ResponseCookie`] inside this set with the specified `id`.
    ///
    /// # Via id
    ///
    /// ```rust
    /// use biscotti::{ResponseCookies, ResponseCookie, ResponseCookieId};
    ///
    /// let mut set = ResponseCookies::new();
    /// assert!(set.get("name").is_none());
    ///
    /// let cookie = ResponseCookie::new("name", "value").set_path("/");
    /// set.insert(cookie);
    ///
    /// // By specifying just the name, the domain and path are assumed to be None.
    /// let id = ResponseCookieId::new("name");
    /// // `name` has a path of `/`, so it doesn't match the empty path.
    /// assert!(set.get(id).is_none());
    ///
    /// let id = ResponseCookieId::new("name").set_path("/");
    /// // You need to specify a matching path to get the cookie we inserted above.
    /// assert_eq!(set.get(id).map(|c| c.value()), Some("value"));
    /// ```
    ///
    /// # Via name
    ///
    /// ```rust
    /// use biscotti::{ResponseCookies, ResponseCookie, ResponseCookieId};
    ///
    /// let mut set = ResponseCookies::new();
    /// assert!(set.get("name").is_none());
    ///
    /// let cookie = ResponseCookie::new("name", "value");
    /// set.insert(cookie);
    ///
    /// // By specifying just the name, the domain and path are assumed to be None.
    /// assert_eq!(set.get("name").map(|c| c.value()), Some("value"));
    /// ```
    pub fn get<I: Into<ResponseCookieId<'c>>>(&self, id: I) -> Option<&ResponseCookie<'c>> {
        let id = id.into();
        self.cookies.get(&id)
    }

    /// Inserts `cookie` into this set.  
    /// If a cookie with the same [`ResponseCookieId`] already
    /// exists, it is replaced with `cookie` and the old cookie is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::{ResponseCookies, ResponseCookie, ResponseCookieId};
    ///
    /// let mut set = ResponseCookies::new();
    /// set.insert(("name", "value"));
    /// set.insert(("second", "two"));
    /// // Replaces the "second" cookie with a new one.
    /// assert!(set.insert(("second", "three")).is_some());
    ///
    /// assert_eq!(set.get("name").map(|c| c.value()), Some("value"));
    /// assert_eq!(set.get("second").map(|c| c.value()), Some("three"));
    /// assert_eq!(set.iter().count(), 2);
    ///
    /// // If we insert another cookie with name "second", but different domain and path,
    /// // it won't replace the existing one.
    /// let cookie = ResponseCookie::new("second", "four").set_domain("rust-lang.org");
    /// set.insert(cookie);
    ///
    /// assert_eq!(set.get("second").map(|c| c.value()), Some("three"));
    /// let id = ResponseCookieId::new("second").set_domain("rust-lang.org");
    /// assert_eq!(set.get(id).map(|c| c.value()), Some("four"));
    /// assert_eq!(set.iter().count(), 3);
    /// ```
    pub fn insert<C: Into<ResponseCookie<'c>>>(&mut self, cookie: C) -> Option<ResponseCookie<'c>> {
        let cookie = cookie.into();
        self.cookies.insert(cookie.id(), cookie)
    }

    /// Discard `cookie` from this set.  
    ///
    /// **`discard` does not instruct the client to remove the cookie**.  
    /// You need to insert a [`RemovalCookie`] into [`ResponseCookies`] to do that.
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::{ResponseCookies, ResponseCookie};
    ///
    /// let mut set = ResponseCookies::new();
    /// set.insert(("second", "two"));
    /// set.discard("second");
    ///
    /// assert!(set.get("second").is_none());
    /// assert_eq!(set.iter().count(), 0);
    /// ```
    ///
    /// # Example with path and domain
    ///
    /// A cookie is identified by its name, domain, and path.
    /// If you want to discard a cookie with a non-empty domain and/or path, you need to specify them.
    ///
    /// ```rust
    /// use biscotti::{ResponseCookies, ResponseCookie, ResponseCookieId};
    ///
    /// let mut set = ResponseCookies::new();
    /// let cookie = ResponseCookie::new("name", "value").set_domain("rust-lang.org").set_path("/");
    /// let id = cookie.id();
    /// set.insert((cookie));
    ///
    /// // This won't discard the cookie because the path and the domain don't match.
    /// set.discard("second");
    /// assert_eq!(set.iter().count(), 1);
    /// assert!(set.get(id).is_some());
    ///
    /// // This will discard the cookie because the name, the path and the domain match.
    /// let id = ResponseCookieId::new("name").set_domain("rust-lang.org").set_path("/");
    /// set.discard(id);
    /// assert_eq!(set.iter().count(), 0);
    /// ```
    ///
    /// [`RemovalCookie`]: crate::RemovalCookie
    pub fn discard<I: Into<ResponseCookieId<'c>>>(&mut self, id: I) {
        self.cookies.remove(&id.into());
    }

    /// Returns an iterator over all the cookies present in this set.
    ///
    /// # Example
    ///
    /// ```rust
    /// use biscotti::{ResponseCookies, ResponseCookie};
    ///
    /// let mut set = ResponseCookies::new();
    ///
    /// set.insert(("name", "value"));
    /// set.insert(("second", "two"));
    /// set.insert(("new", "third"));
    /// set.insert(("another", "fourth"));
    /// set.insert(("yac", "fifth"));
    ///
    /// set.discard("name");
    /// set.discard("another");
    ///
    /// // There are three cookies in the set: "second", "new", and "yac".
    /// # assert_eq!(set.iter().count(), 3);
    /// for cookie in set.iter() {
    ///     match cookie.name() {
    ///         "second" => assert_eq!(cookie.value(), "two"),
    ///         "new" => assert_eq!(cookie.value(), "third"),
    ///         "yac" => assert_eq!(cookie.value(), "fifth"),
    ///         _ => unreachable!("there are only three cookies in the set")
    ///     }
    /// }
    /// ```
    pub fn iter(&self) -> Iter {
        Iter {
            cookies: self.cookies.values(),
        }
    }
}

impl<'a, 'c: 'a> ResponseCookies<'c> {
    /// Returns the values that should be sent to the client as `Set-Cookie` headers.
    pub fn header_values(self, processor: &'a Processor) -> impl Iterator<Item = String> + 'a {
        self.cookies
            .into_values()
            .map(|cookie| processor.process_outgoing(cookie).to_string())
    }
}

/// Iterator over all the cookies in a [`ResponseCookies`].
pub struct Iter<'a, 'c> {
    cookies: Values<'a, ResponseCookieId<'c>, ResponseCookie<'c>>,
}

impl<'a, 'c> Iterator for Iter<'a, 'c> {
    type Item = &'a ResponseCookie<'c>;

    fn next(&mut self) -> Option<&'a ResponseCookie<'c>> {
        self.cookies.next()
    }
}

#[cfg(test)]
mod test {
    use super::ResponseCookies;

    #[test]
    #[allow(deprecated)]
    fn simple() {
        let mut c = ResponseCookies::new();

        c.insert(("test", ""));
        c.insert(("test2", ""));
        c.discard("test");

        assert!(c.get("test").is_none());
        assert!(c.get("test2").is_some());

        c.insert(("test3", ""));
        c.discard("test2");
        c.discard("test3");

        assert!(c.get("test").is_none());
        assert!(c.get("test2").is_none());
        assert!(c.get("test3").is_none());
    }

    #[test]
    fn set_is_send() {
        fn is_send<T: Send>(_: T) -> bool {
            true
        }

        assert!(is_send(ResponseCookies::new()))
    }
}
