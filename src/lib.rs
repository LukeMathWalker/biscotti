//! A crate to handle HTTP cookies in a Rust server.
//!
//! # Overview
//!
//! You can use `biscotti` to handle cookies in your server.  
//!
//! It has support for:
//!
//! - Handling cookies attached to incoming requests, via [`RequestCookies`]
//! - Building cookies for outgoing responses, via [`ResponseCookies`]
//! - Encrypting, signing or encoding cookies, via [`Processor`]
//!
//! In particular:
//!
//! - It can handle multiple request cookies with the same name
//! - It lets you add multiple cookies with the same name but different paths or domains
//! - Cookies are percent-encoded/decoded by default (but you can opt out)
//! - It has built-in support for rotating signing/encryption keys over time
//!
//! # Non-goals
//!
//! `biscotti` is not designed to handle cookies on the client side.  
//! It doesn't provide any logic to parse the `Set-Cookie` headers returned in a server response.
//!
//! # Quickstart
//!
//! ## Incoming cookies
//!
//! ```rust
//! use biscotti::{Processor, ProcessorConfig, RequestCookies};
//!
//! // Start by creating a `Processor` instance from a `Config`.
//! // It determines if (and which) cookies should be decrypted, verified or percent-decoded.
//! let processor: Processor = ProcessorConfig::default().into();
//! // You can then use `RequestCookies::parse_header` to parse the `Cookie` header
//! // you received from the client.
//! let cookies = RequestCookies::parse_header(
//!     "name=first%20value; name2=val; name=another%20value",
//!     &processor
//! ).unwrap();
//!
//! // You can now access the cookies!
//!
//! // You can access the first cookie with a given name...
//! assert_eq!(cookies.get("name").unwrap().value(), "first value");
//! // ...or opt to retrieve all values associated with that cookie name.
//! assert_eq!(cookies.get_all("name").unwrap().len(), 2);
//!
//! assert_eq!(cookies.get("name2").unwrap().value(), "val");
//! assert_eq!(cookies.get_all("name2").unwrap().len(), 1);
//! ```
//!
//! ## Outgoing cookies
//!
//! ```rust
//! use std::collections::HashSet;
//! use biscotti::{Processor, ProcessorConfig, ResponseCookies, RemovalCookie, ResponseCookie};
//! use biscotti::SameSite;
//!
//! // Start by creating a `ResponseCookies` instance to hold the cookies you want to send.
//! let mut cookies = ResponseCookies::new();
//!
//! // You can add cookies to the `ResponseCookies` instance via the `insert` method.
//! cookies.insert(ResponseCookie::new("name", "a value"));
//! cookies.insert(ResponseCookie::new("name", "a value").set_path("/"));
//! // If you want to remove a cookie from the client's machine, you can use a `RemovalCookie`.
//! cookies.insert(RemovalCookie::new("another name"));
//!
//! // You then convert obtain the respective `Set-Cookie` header values.
//! // A processor is required: it determines if (and which) cookies should be encrypted,
//! // signed or percent-encoded.
//! let processor: Processor = ProcessorConfig::default().into();
//! let header_values: HashSet<_> = cookies.header_values(&processor).collect();
//! assert_eq!(header_values, HashSet::from([
//!     "name=a%20value".to_string(),
//!     // Both `name` cookies are kept since they have different path attributes.
//!     "name=a%20value; Path=/".to_string(),
//!     // A removal cookie is a cookie with an empty value and an expiry in the past.
//!     "another%20name=; Expires=Thu, 01 Jan 1970 00:00:00 GMT".to_string(),
//! ]));
//! ```
//!
//! ## Credits
//!
//! `biscotti` is heavily inspired by the [`cookie` crate](https://crates.io/crates/cookie) [Copyright (c) 2017 Sergio Benitez,
//! Copyright (c) 2014 Alex Crichton].  
//! `biscotti` started as a `cookie` fork and it includes non-negligible portions of its
//! code.
//!
//! [`Processor`]: crate::Processor
//! [`RequestCookies`]: crate::RequestCookies
//! [`ResponseCookies`]: crate::ResponseCookies

pub mod config;
mod crypto;
mod encoding;
mod expiration;
mod processor;
mod removal;
mod request_cookie;
mod request_cookies;
mod response_cookie;
mod response_cookie_id;
mod response_cookies;
mod same_site;

pub mod request;
pub mod response;

pub use crate::expiration::*;
pub use crate::same_site::*;
pub use config::inner::ProcessorConfig;
pub use crypto::Key;
pub use processor::Processor;
pub use removal::RemovalCookie;
pub use request_cookie::RequestCookie;
pub use request_cookies::RequestCookies;
pub use response_cookie::ResponseCookie;
pub use response_cookie_id::ResponseCookieId;
pub use response_cookies::ResponseCookies;
pub use time;

/// Errors that can occur when using `biscotti`.
pub mod errors {
    pub use crate::crypto::{KeyError, ShortKeyError};
    pub use crate::processor::{CryptoError, DecodingError, ProcessIncomingError};
    pub use crate::request_cookies::{EmptyNameError, MissingPairError, ParseError};
}
