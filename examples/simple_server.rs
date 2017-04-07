extern crate iron;
extern crate secure_session;

use iron::AroundMiddleware;
use iron::headers::ContentType;
use iron::method::Method;
use iron::prelude::*;
use iron::status;
use std::io::Read;
use std::str;

use secure_session::middleware::{SessionMiddleware, SessionConfig};
use secure_session::session::{Session, SessionManager, ChaCha20Poly1305SessionManager};

fn main() {
    // initialize the session manager
    let password = b"very-very-secret";
    let manager = ChaCha20Poly1305SessionManager::from_password(password);
    let config = SessionConfig::default();
    let middleware = SessionMiddleware::new(manager, config);

    // wrap the routes
    let handler = middleware.around(Box::new(index));

    // awwwww yissssssss
    Iron::new(handler).http("localhost:8080").unwrap();
}

fn index(request: &mut Request) -> IronResult<Response> {
    let message = match request.method {
        Method::Post => {
            let session = request.extensions.get_mut::<Session>().unwrap();
            let (message, insert) = match session.get_bytes("message").and_then(|b| str::from_utf8(b).ok()) {
                Some(message) => (message.to_string(), false),
                None => {
                    let mut body = String::new();
                    let _ = request.body.read_to_string(&mut body).unwrap();
                    if body.len() > 8 {
                        (body[8..body.len()].to_string(), true)
                    } else {
                        ("message too short!".to_string(), false)
                    }
                }
            };

            if insert {
                session.insert_bytes("message", message.as_bytes().to_vec());
            }

            message
        },
        _ => {
            let session = request.extensions.get_mut::<Session>().unwrap();
            match session.get_bytes("message").and_then(|b| str::from_utf8(b).ok()) {
                Some(message) => message.to_string(),
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
