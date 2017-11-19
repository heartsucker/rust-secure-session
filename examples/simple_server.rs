extern crate iron;
extern crate secure_session;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate typemap;

use iron::AroundMiddleware;
use iron::headers::ContentType;
use iron::method::Method;
use iron::prelude::*;
use iron::status;
use std::io::Read;
use std::str;

use secure_session::middleware::{SessionMiddleware, SessionConfig};
use secure_session::session::{SessionManager, ChaCha20Poly1305SessionManager};

fn main() {
    // initialize the session manager
    let password = b"very-very-secret";
    let manager = ChaCha20Poly1305SessionManager::<Session>::from_password(password);
    let config = SessionConfig::default();
    let middleware = SessionMiddleware::<
        Session,
        SessionKey,
        ChaCha20Poly1305SessionManager<Session>,
    >::new(manager, config);

    // wrap the routes
    let handler = middleware.around(Box::new(index));

    // awwwww yissssssss
    Iron::new(handler).http("localhost:8080").unwrap();
}

fn index(request: &mut Request) -> IronResult<Response> {
    let message = match request.method {
        Method::Post => {
            let (message, insert) = match request.extensions.remove::<SessionKey>() {
                Some(data) => (data.message, false),
                None => {
                    let mut body = String::new();
                    let _ = request.body.read_to_string(&mut body).unwrap();
                    // do the laziest parsing ever because I don't want to pull in another crate
                    if body.len() > 8 {
                        // return (msg, true) because we only update if the message wasn't there
                        (body[8..body.len()].to_string(), true)
                    } else {
                        ("message too short!".to_string(), false)
                    }
                }
            };

            // only update if the message was never seen before
            if insert {
                let _ = request.extensions.insert::<SessionKey>(
                    Session { message: message.clone() },
                );
            }

            message
        }
        _ => {
            match request.extensions.get::<SessionKey>() {
                Some(ref data) => data.message.clone(),
                None => "no session message yet".to_string(),
            }
        }
    };

    // in the real world, one would use something like handlebars instead of this hackiness
    let html = include_str!("./index.html").replace("SESSION_MESSAGE", &message);
    let mut response = Response::with((status::Ok, html));
    response.headers.set(ContentType::html());

    Ok(response)
}

#[derive(Serialize, Deserialize)]
struct Session {
    message: String,
}

struct SessionKey {}

impl typemap::Key for SessionKey {
    type Value = Session;
}
