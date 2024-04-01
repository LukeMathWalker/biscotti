//! Low-level types related to [`RequestCookies`].
//!
//! [`RequestCookies`]: crate::RequestCookies
use crate::RequestCookie;
use std::borrow::Cow;
use std::slice::Iter;

/// An iterator over all [`RequestCookie`]s with a given name.
///
/// This struct is created by the [`RequestCookies::get_all()`] method.
///
/// [`RequestCookies::get_all()`]: crate::RequestCookies::get_all
pub struct CookiesForName<'map, 'cookie> {
    pub(crate) iter: Iter<'map, Cow<'cookie, str>>,
    pub(crate) name: Cow<'cookie, str>,
}

impl<'map, 'cookie> CookiesForName<'map, 'cookie> {
    pub fn values(&self) -> CookieValuesForName<'map, 'cookie> {
        CookieValuesForName {
            iter: self.iter.clone(),
        }
    }
}

impl<'map, 'cookie> Iterator for CookiesForName<'map, 'cookie> {
    type Item = RequestCookie<'cookie>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter
            .next()
            .map(|value| RequestCookie::new(self.name.clone(), value.clone()))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

/// An iterator over all cookie values for a given cookie name.
///
/// This struct is created by the [`CookiesForName::values()`] method.
pub struct CookieValuesForName<'map, 'cookie> {
    pub(crate) iter: Iter<'map, Cow<'cookie, str>>,
}

impl<'map, 'cookie> Iterator for CookieValuesForName<'map, 'cookie> {
    type Item = &'map str;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|value| value.as_ref())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<'map, 'cookie> ExactSizeIterator for CookiesForName<'map, 'cookie> {}

impl<'map, 'cookie> ExactSizeIterator for CookieValuesForName<'map, 'cookie> {}

impl<'map, 'cookie> DoubleEndedIterator for CookiesForName<'map, 'cookie> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.iter
            .next_back()
            .map(|value| RequestCookie::new(self.name.clone(), value.clone()))
    }
}

impl<'map, 'cookie> DoubleEndedIterator for CookieValuesForName<'map, 'cookie> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.iter.next_back().map(|value| value.as_ref())
    }
}

impl<'map, 'cookie> std::iter::FusedIterator for CookiesForName<'map, 'cookie> {}

impl<'map, 'cookie> std::iter::FusedIterator for CookieValuesForName<'map, 'cookie> {}
