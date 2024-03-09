use percent_encoding::{AsciiSet, CONTROLS};

/// https://url.spec.whatwg.org/#fragment-percent-encode-set
const FRAGMENT: &AsciiSet = &CONTROLS.add(b' ').add(b'"').add(b'<').add(b'>').add(b'`');

/// https://url.spec.whatwg.org/#path-percent-encode-set
const PATH: &AsciiSet = &FRAGMENT.add(b'#').add(b'?').add(b'{').add(b'}');

/// https://url.spec.whatwg.org/#userinfo-percent-encode-set
const USERINFO: &AsciiSet = &PATH
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'=')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'|')
    .add(b'%');

/// https://www.rfc-editor.org/rfc/rfc6265#section-4.1.1 + '(', ')'
const COOKIE: &AsciiSet = &USERINFO.add(b'(').add(b')').add(b',');

/// Percent-encode a cookie name or value with the proper encoding set.
pub(crate) fn encode(string: &str) -> impl std::fmt::Display + '_ {
    percent_encoding::percent_encode(string.as_bytes(), COOKIE)
}
