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
//! extern crate serde;
//! #[macro_use]
//! extern crate serde_derive;
//! extern crate typemap;
//! 
//! use iron::AroundMiddleware;
//! use iron::prelude::*;
//! use iron::status;
//! 
//! use secure_session::middleware::{SessionMiddleware, SessionConfig};
//! use secure_session::session::{SessionManager, ChaCha20Poly1305SessionManager};
//! 
//! fn main() {
//!     let password = b"very-very-secret";
//!     let manager = ChaCha20Poly1305SessionManager::<Session>::from_password(password);
//!     let config = SessionConfig::default();
//!     let middleware =
//!         SessionMiddleware::<Session, SessionKey, ChaCha20Poly1305SessionManager<Session>>::new(manager, config);
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

extern crate bincode;
extern crate chrono;
extern crate cookie;
extern crate crypto;
extern crate data_encoding;
#[cfg(test)]
extern crate hyper;
extern crate iron;
#[cfg(test)]
extern crate iron_test;
#[macro_use]
extern crate log;
extern crate rand;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate typemap;

/// The name of the cookie that stores the session.
pub const SESSION_COOKIE_NAME: &'static str = "ss";

pub mod error;
pub mod session;
pub mod middleware;
