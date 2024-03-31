//! Low-level types related to [`ResponseCookies`].
use crate::response_cookies::ResponseCookieKey;
use crate::{ResponseCookie, ResponseCookies};
use std::collections::hash_map::Values;

/// Iterator over all the cookies in a [`ResponseCookies`].
pub struct ResponseCookiesIter<'map, 'cookie> {
    pub(crate) cookies: Values<'map, ResponseCookieKey<'cookie>, ResponseCookie<'cookie>>,
}

impl<'map, 'cookie> Iterator for ResponseCookiesIter<'map, 'cookie> {
    type Item = &'map ResponseCookie<'cookie>;

    fn next(&mut self) -> Option<&'map ResponseCookie<'cookie>> {
        self.cookies.next()
    }
}
