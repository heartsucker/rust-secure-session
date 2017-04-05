//! Iron specific middleware and handlers

use chrono::Duration;
use cookie::Cookie;
use iron::headers::{SetCookie, Cookie as IronCookie};
use iron::middleware::{AroundMiddleware, Handler};
use iron::prelude::*;
use rustc_serialize::base64::{self, ToBase64, FromBase64};

use super::SESSION_COOKIE_NAME;
use session::{SessionManager, Session};

struct SessionHandler<S: SessionManager, H: Handler> {
    manager: S,
    config: SessionConfig,
    handler: H,
}

impl<S: SessionManager, H: Handler> SessionHandler<S, H> {
    fn new(manager: S, config: SessionConfig, handler: H) -> Self {
        SessionHandler {
            manager: manager,
            config: config,
            handler: handler,
        }
    }

    fn extract_session_cookie(&self, request: &Request) -> Option<Vec<u8>> {
        request.headers
            .get::<IronCookie>()
            .and_then(|raw_cookie| {
                raw_cookie.0
                    .iter()
                    .filter_map(|c| {
                        Cookie::parse_encoded(c.clone())
                            .ok()
                            .and_then(|cookie| match cookie.name_value() {
                                (SESSION_COOKIE_NAME, value) => Some(value.to_string()),
                                _ => None,
                            })
                            .and_then(|c| c.from_base64().ok())
                    })
                    .collect::<Vec<Vec<u8>>>()
                    .first()
                    .map(|c| c.clone())
            })
    }
}

impl<S: SessionManager + 'static, H: Handler> Handler for SessionHandler<S, H> {
    fn handle(&self, mut request: &mut Request) -> IronResult<Response> {
        // before
        let session_opt = self.extract_session_cookie(&request)
            // TODO error out on deserialization failure
            .and_then(|c| self.manager.deserialize(&c).ok());

        match session_opt {
            Some(session) => {
                let _ = request.extensions.insert::<Session>(session);
            }
            None => {}
        }

        // main
        let mut response = self.handler.handle(&mut request)?;

        // after
        let session_opt = request.extensions.get::<Session>();

        match session_opt {
            Some(session) => {
                // TODO unwrap
                let session_str =
                    self.manager.serialize(&session).unwrap().to_base64(base64::STANDARD);

                let cookie = Cookie::build(SESSION_COOKIE_NAME, session_str)
                    // TODO config for path
                    .path("/")
                    .http_only(true);
                    // TODO .secure(self.config.secure_cookie)
                    // TODO config flag for SameSite

                let cookie = (match self.config.ttl_seconds {
                    Some(ttl) => {
                        cookie.max_age(Duration::seconds(ttl))
                    },
                    None => cookie
                }).finish();

                let mut cookies = vec![format!("{}", cookie.encoded())]; // TODO is this formatting dumb?

                {
                    if let Some(set_cookie) = response.headers.get::<SetCookie>() {
                        cookies.extend(set_cookie.0.clone())
                    }
                }
                response.headers.set(SetCookie(cookies));
            }
            None => {}
        }

        Ok(response)
    }
}

/// Middleware for automatic session management
pub struct SessionMiddleware<S: SessionManager> {
    manager: S,
    config: SessionConfig,
}

impl<S: SessionManager> SessionMiddleware<S> {
    /// Create a new `SessionMiddleware` given a `SessionManager`
    pub fn new(manager: S, config: SessionConfig) -> Self {
        SessionMiddleware {
            manager: manager,
            config: config,
        }
    }
}

impl<S: SessionManager + 'static> AroundMiddleware for SessionMiddleware<S> {
    fn around(self, handler: Box<Handler>) -> Box<Handler> {
        Box::new(SessionHandler::new(self.manager, self.config, handler))
    }
}


/// Configuration of how sessions and session cookies are created and validated
pub struct SessionConfig {
    ttl_seconds: Option<i64>,
}

impl SessionConfig {
    /// Create a new builder that is initialized with the default configuration.
    pub fn build() -> SessionConfigBuilder {
        SessionConfigBuilder::new()
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig {
            ttl_seconds: None,
        }
    }
}


pub struct SessionConfigBuilder {
    config: SessionConfig,
}

impl SessionConfigBuilder {
    fn new() -> Self {
        SessionConfigBuilder { config: SessionConfig::default() }
    }

    /// Set the session time to live (TTL) in seconds. Default: `None`
    pub fn ttl_seconds(mut self, ttl_seconds: Option<i64>) -> Self {
        self.config.ttl_seconds = ttl_seconds;
        self
    }
}

