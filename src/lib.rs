//! Signed, encrypted session cookies for Iron.
//!
//! # Hello, Secure Session!
//!
//! ```
//! extern crate iron;
//! extern crate secure_session;
//!
//! use iron::AroundMiddleware;
//! use iron::prelude::*;
//! use iron::status;
//! use std::str;
//!
//! use secure_session::middleware::{SessionMiddleware, SessionConfig};
//! use secure_session::session::{Session, SessionManager, ChaCha20Poly1305SessionManager};
//!
//! fn main() {
//!     // Set up the session manager with the default config
//!     let password = b"very-very-secret";
//!     let manager = ChaCha20Poly1305SessionManager::from_password(password);
//!     let config = SessionConfig::default();
//!     let middleware = SessionMiddleware::new(manager, config);
//!
//!     // Set up the routes
//!     let handler = middleware.around(Box::new(index));
//!
//!     // Make and start the server
//!     Iron::new(handler); //.http("localhost:8080").unwrap();
//! }
//!
//! fn index(request: &mut Request) -> IronResult<Response> {
//!     let session = request.extensions.get::<Session>().unwrap();
//!     let who = session.get_bytes("who").and_then(|b| str::from_utf8(b).ok())
//!         .unwrap_or("secure session");
//!     Ok(Response::with((status::Ok, format!("Hello, {}!", who))))
//! }
//! ```

#![deny(missing_docs)]

extern crate bincode;
extern crate chrono;
extern crate cookie;
extern crate crypto;
#[cfg(test)]
extern crate hyper;
extern crate iron;
#[cfg(test)]
extern crate iron_test;
#[macro_use]
extern crate log;
extern crate ring;
extern crate rustc_serialize;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate typemap;

/// The name of the cookie that stores the session.
pub const SESSION_COOKIE_NAME: &'static str = "ss";

pub mod error;
pub mod session;
pub mod middleware;
