//! Signed, encrypted session cookies for Iron.
//!
//! A more complete reference implementation can be found on
//! [github](https://github.com/heartsucker/iron-reference).
//!
//! # Hello, Secure Session!
//!
//! ```
//! extern crate iron;
//! extern crate secure_session;
//! extern crate typemap;
//!
//! use serde::{Deserialize, Serialize};
//! use iron::AroundMiddleware;
//! use iron::prelude::*;
//! use iron::status;
//!
//! use secure_session::middleware::{SessionMiddleware, SessionConfig};
//! use secure_session::session::ChaCha20Poly1305SessionManager;
//!
//! fn main() {
//!     let key = *b"01234567012345670123456701234567";
//!     let manager = ChaCha20Poly1305SessionManager::<Session>::from_key(key);
//!     let config = SessionConfig::default();
//!     let middleware =
//!         SessionMiddleware::<Session, SessionKey, ChaCha20Poly1305SessionManager<Session>>::new(
//!             manager, config);
//!
//!     let handler = middleware.around(Box::new(index));
//!
//!     Iron::new(handler); //.http("localhost:8080").unwrap();
//! }
//!
//! fn index(request: &mut Request) -> IronResult<Response> {
//!     let message = request.extensions.get::<SessionKey>()
//!         .map(|s| s.message.clone())
//!         .unwrap_or("secure session".to_string());
//!     Ok(Response::with((status::Ok, format!("Hello, {}!", message))))
//! }
//!
//! #[derive(Serialize, Deserialize)]
//! struct Session {
//!     message: String,
//! }
//!
//! struct SessionKey {}
//!
//! impl typemap::Key for SessionKey {
//!     type Value = Session;
//! }
//! ```

#![deny(missing_docs)]

#[macro_use]
extern crate log;

/// The name of the cookie that stores the session.
pub const SESSION_COOKIE_NAME: &'static str = "ss";

pub mod error;
pub mod middleware;
pub mod session;
