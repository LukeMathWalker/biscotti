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
pub struct CookiesForName<'a, 'c> {
    pub(crate) iter: Iter<'a, Cow<'c, str>>,
    pub(crate) name: Cow<'c, str>,
}

impl<'a, 'c> CookiesForName<'a, 'c> {
    pub fn values(&self) -> CookieValuesForName<'a, 'c> {
        CookieValuesForName {
            iter: self.iter.clone(),
        }
    }
}

impl<'a, 'c> Iterator for CookiesForName<'a, 'c> {
    type Item = RequestCookie<'c>;

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
pub struct CookieValuesForName<'a, 'c> {
    pub(crate) iter: Iter<'a, Cow<'c, str>>,
}

impl<'a, 'c> Iterator for CookieValuesForName<'a, 'c> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|value| value.as_ref())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<'a, 'c> ExactSizeIterator for CookiesForName<'a, 'c> {}

impl<'a, 'c> ExactSizeIterator for CookieValuesForName<'a, 'c> {}

impl<'a, 'c> DoubleEndedIterator for CookiesForName<'a, 'c> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.iter
            .next_back()
            .map(|value| RequestCookie::new(self.name.clone(), value.clone()))
    }
}

impl<'a, 'c> DoubleEndedIterator for CookieValuesForName<'a, 'c> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.iter.next_back().map(|value| value.as_ref())
    }
}

impl<'a, 'c> std::iter::FusedIterator for CookiesForName<'a, 'c> {}

impl<'a, 'c> std::iter::FusedIterator for CookieValuesForName<'a, 'c> {}
