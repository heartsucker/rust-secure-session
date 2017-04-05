//! Signed, encrypted session cookies for Iron

// TODO change to deny once this is more stable

extern crate bincode;
extern crate chrono;
extern crate cookie;
extern crate crypto;
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
