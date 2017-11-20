//! Iron specific middleware and handlers.

use chrono::{Duration, Utc};
use cookie::Cookie;
use data_encoding::BASE64;
use iron::headers::{SetCookie, Cookie as IronCookie};
use iron::middleware::{AroundMiddleware, Handler};
use iron::prelude::*;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use std::marker::PhantomData;
use typemap;

use error::SessionConfigError;
use super::SESSION_COOKIE_NAME;
use session::{SessionManager, Session};


/// Uses a `SessionManager` to serialize and deserialize cookies during the request/response cycle.
pub struct SessionHandler<V, K, S>
where
    V: Serialize + DeserializeOwned + 'static,
    K: typemap::Key<Value = V>,
    S: SessionManager<V>,
{
    manager: S,
    config: SessionConfig,
    handler: Box<Handler>,
    _key: PhantomData<K>,
}

impl<V: Serialize + DeserializeOwned + 'static, K: typemap::Key<Value = V>, S: SessionManager<V>>
    SessionHandler<V, K, S> {
    fn new(manager: S, config: SessionConfig, handler: Box<Handler>) -> Self {
        SessionHandler {
            manager: manager,
            config: config,
            handler: handler,
            _key: PhantomData,
        }
    }

    fn extract_session_cookie(&self, request: &Request) -> Option<Vec<u8>> {
        request.headers.get::<IronCookie>().and_then(|raw_cookie| {
            raw_cookie
                .0
                .iter()
                .filter_map(|c| {
                    Cookie::parse_encoded(c.clone())
                        .ok()
                        .and_then(|cookie| match cookie.name_value() {
                            (SESSION_COOKIE_NAME, value) => Some(value.to_string()),
                            _ => None,
                        })
                        .and_then(|c| BASE64.decode(c.as_bytes()).ok())
                })
                .collect::<Vec<Vec<u8>>>()
                .first()
                .map(|c| c.clone())
        })
    }
}

impl<
    V: Serialize + DeserializeOwned + 'static,
    K: typemap::Key<Value = V> + Send + Sync,
    S: SessionManager<V> + 'static,
> Handler for SessionHandler<V, K, S> {
    fn handle(&self, mut request: &mut Request) -> IronResult<Response> {
        // before
        match self.extract_session_cookie(&request)
            // TODO ? error out on deserialization failure and remove cookie since it is invalid
            .and_then(|c| self.manager.deserialize(&c).ok())
            .and_then(|s| {
                match s.expires {
                    Some(expires) if expires > Utc::now() => s.value,
                    None => s.value,
                    _ => None,
                }
            }).take() {
            Some(value) => {
                let _ = request.extensions.insert::<K>(value);
            }
            None => (),
        }

        // main
        let mut response = self.handler.handle(&mut request)?;

        // after
        let expires = self.config.ttl_seconds.map(|ttl| {
            Utc::now() + Duration::seconds(ttl)
        });
        let session = Session {
            expires: expires,
            value: request.extensions.remove::<K>(),
        };

        let session_str = BASE64.encode(&self.manager.serialize(&session).unwrap());

        let cookie = Cookie::build(SESSION_COOKIE_NAME, session_str)
            // TODO config for path
            .path("/")
            .http_only(true);
        // TODO .secure(self.config.secure_cookie)
        // TODO config flag for SameSite

        let cookie = (match self.config.ttl_seconds {
                          Some(ttl) => cookie.max_age(Duration::seconds(ttl)),
                          None => cookie,
                      }).finish();

        let mut cookies = vec![cookie.encoded().to_string()];

        {
            if let Some(set_cookie) = response.headers.get::<SetCookie>() {
                cookies.extend(set_cookie.0.clone())
            }
        }
        response.headers.set(SetCookie(cookies));

        Ok(response)
    }
}

/// Middleware for automatic session management.
pub struct SessionMiddleware<V, K, S>
where
    V: Serialize + DeserializeOwned + 'static,
    K: typemap::Key<Value = V>,
    S: SessionManager<V>,
{
    manager: S,
    config: SessionConfig,
    _key: PhantomData<K>,
    _value: PhantomData<V>,
}

impl<V: Serialize + DeserializeOwned + 'static, K: typemap::Key<Value = V>, S: SessionManager<V>>
    SessionMiddleware<V, K, S> {
    /// Create a new `SessionMiddleware` for the given `SessionManager` and `SessionConfig`.
    pub fn new(manager: S, config: SessionConfig) -> Self {
        SessionMiddleware {
            manager: manager,
            config: config,
            _key: PhantomData,
            _value: PhantomData,
        }
    }
}

impl<
    V: Serialize + DeserializeOwned + 'static,
    K: typemap::Key<Value = V>,
    S: SessionManager<V> + 'static,
> AroundMiddleware for SessionMiddleware<V, K, S>
where
    SessionHandler<V, K, S>: Handler,
{
    fn around(self, handler: Box<Handler>) -> Box<Handler> {
        Box::new(SessionHandler::<V, K, S>::new(
            self.manager,
            self.config,
            handler,
        ))
    }
}


/// Configuration of how sessions and session cookies are created and validated.
#[derive(Clone)]
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
        SessionConfig { ttl_seconds: None }
    }
}


/// A utility to help build a `SessionConfig` in an API backwards compatible way.
#[derive(Clone)]
pub struct SessionConfigBuilder {
    config: SessionConfig,
}

impl SessionConfigBuilder {
    /// Create a new builder that is initialized with the default configuration.
    pub fn new() -> Self {
        SessionConfigBuilder { config: SessionConfig::default() }
    }

    /// Set the session time to live (TTL) in seconds. Default: `None`
    pub fn ttl_seconds(mut self, ttl_seconds: Option<i64>) -> Self {
        self.config.ttl_seconds = ttl_seconds;
        self
    }

    /// Consume the builder and return a config.
    pub fn finish(self) -> Result<SessionConfig, SessionConfigError> {
        Ok(SessionConfig { ttl_seconds: self.config.ttl_seconds })
    }
}

#[cfg(test)]
mod tests {
    use hyper::header::Headers;
    use iron::headers::{SetCookie, Cookie as IronCookie};
    use iron::prelude::*;
    use iron::status;
    use iron_test::request as mock_request;
    use typemap;
    use session::{MultiSessionManager, ChaCha20Poly1305SessionManager, AesGcmSessionManager};
    use super::*;

    const KEY_32: [u8; 32] = *b"01234567012345670123456701234567";

    #[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug)]
    struct Data {
        string: String,
    }

    struct DataKey {}

    impl typemap::Key for DataKey {
        type Value = Data;
    }

    fn mock_handler(request: &mut Request) -> IronResult<Response> {
        let stat = match request.extensions.get::<DataKey>() {
            Some(_) => status::Ok,
            None => status::NoContent,
        };

        request.extensions.insert::<DataKey>(Data { string: "wat".to_string() });

        Ok(Response::with((stat, "")))
    }

    macro_rules! test_cases {
        ($strct: ident, $md: ident) => {
            mod $md  {
                use cookie::Cookie;
                use hyper::header::Headers;
                use iron::headers::{SetCookie, Cookie as IronCookie};
                use iron::status;
                use iron_test::request as mock_request;

                use $crate::session::$strct;
                use $crate::middleware::{SessionConfig, SessionHandler, SessionConfigBuilder};
                use super::{KEY_32, Data, DataKey, mock_handler};

                #[test]
                fn no_expiry() {
                    let config = SessionConfig::default();
                    let manager = $strct::<Data>::from_key(KEY_32);
                    let middleware =
                        SessionHandler::<Data, DataKey, $strct<Data>>::new(
                            manager, config, Box::new(mock_handler));

                    let path = "http://localhost/";

                    let response = mock_request::get(path, Headers::new(), &middleware)
                        .expect("request failed");
                    assert_eq!(response.status, Some(status::NoContent));

                    // get the cookies out
                    let set_cookie = response.headers.get::<SetCookie>()
                        .expect("no SetCookie header");
                    let cookie = Cookie::parse(set_cookie.0[0].clone()).expect("cookie not parsed");
                    let mut headers = Headers::new();
                    headers.set(IronCookie(vec![cookie.to_string()]));

                    // resend the request and get a different code back
                    let response = mock_request::get(path, headers, &middleware)
                        .expect("request failed");
                    assert_eq!(response.status, Some(status::Ok));
                }

                #[test]
                fn sessions_expire() {
                    let config = SessionConfigBuilder::new().ttl_seconds(Some(-1)).finish()
                        .unwrap();
                    let manager = $strct::<Data>::from_key(KEY_32);
                    let middleware =
                        SessionHandler::<Data, DataKey, $strct<Data>>::new(
                            manager, config, Box::new(mock_handler));

                    let path = "http://localhost/";

                    let response = mock_request::get(path, Headers::new(), &middleware)
                        .expect("request failed");
                    assert_eq!(response.status, Some(status::NoContent));

                    // get the cookies out
                    let set_cookie = response.headers.get::<SetCookie>()
                        .expect("no SetCookie header");
                    let cookie = Cookie::parse(set_cookie.0[0].clone()).expect("cookie not parsed");
                    let mut headers = Headers::new();
                    headers.set(IronCookie(vec![cookie.to_string()]));

                    // resend the request and get a different code back
                    let response = mock_request::get(path, headers, &middleware)
                        .expect("request failed");
                    assert_eq!(response.status, Some(status::NoContent));
                }
            }
        }
    }

    test_cases!(AesGcmSessionManager, aesgcm);
    test_cases!(ChaCha20Poly1305SessionManager, chacha20poly1305);

    #[test]
    fn multisession_and_rotation() {
        let config = SessionConfig::default();

        let manager_1 = AesGcmSessionManager::<Data>::from_key(KEY_32);
        let manager_1_clone = AesGcmSessionManager::<Data>::from_key(KEY_32);
        let middle_1 = SessionMiddleware::<Data, DataKey, AesGcmSessionManager<Data>>::new(
            manager_1, config.clone());
        let handler_1 = middle_1.around(Box::new(mock_handler));

        let manager_2 = ChaCha20Poly1305SessionManager::<Data>::from_key(KEY_32);
        let manager_2_clone = ChaCha20Poly1305SessionManager::<Data>::from_key(KEY_32);
        let middle_2 = SessionMiddleware::<Data, DataKey, ChaCha20Poly1305SessionManager<Data>>::new(
            manager_2, config.clone());
        let handler_2 = middle_2.around(Box::new(mock_handler));

        let multi = MultiSessionManager::<Data>::new(
            Box::new(manager_2_clone), vec![Box::new(manager_1_clone)]);
        let multi_middle = SessionMiddleware::<Data, DataKey, MultiSessionManager<Data>>::new(
            multi, config);
        let multi_handler = multi_middle.around(Box::new(mock_handler));

        // make a request to the first handler and get the initial session
        let resp = mock_request::get("http://localhost/", Headers::new(), &handler_1).unwrap();
        let set_cookie = resp.headers.get::<SetCookie>().expect("no SetCookie header");
        let cookie = Cookie::parse(set_cookie.0[0].clone()).expect("cookie not parsed");

        // make a request to the multi handler
        let mut headers = Headers::new();
        headers.set(IronCookie(vec![cookie.to_string()]));
        let resp = mock_request::get("http://localhost/", headers, &multi_handler).unwrap();
        assert_eq!(resp.status, Some(status::Ok));

        // get the cookie back out
        let set_cookie = resp.headers.get::<SetCookie>().expect("no SetCookie header");
        let cookie = Cookie::parse(set_cookie.0[0].clone()).expect("cookie not parsed");

        // make a request to the second handler
        let mut headers = Headers::new();
        headers.set(IronCookie(vec![cookie.to_string()]));
        let resp = mock_request::get("http://localhost/", headers, &handler_2).unwrap();
        assert_eq!(resp.status, Some(status::Ok));
    }
}
