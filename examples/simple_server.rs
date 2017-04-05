extern crate iron;
extern crate secure_session;

use iron::AroundMiddleware;
use iron::headers::ContentType;
use iron::prelude::*;
use iron::status;
use std::io::Read;
use std::str;

use secure_session::middleware::SessionMiddleware;
use secure_session::session::{Session, SessionManager, ChaCha20Poly1305SessionManager};

fn main() {
    // initialize the session manager
    let password = b"very-very-secret";
    let manager = ChaCha20Poly1305SessionManager::from_password(password);
    let middleware = SessionMiddleware::new(manager);

    // wrap the routes
    let handler = middleware.around(Box::new(index));

    // awwwww yissssssss
    Iron::new(handler).http("localhost:8080").unwrap();
}

// This is a stupid, mess of a function, but that's what happens when you just try to cram
// everything in to make the example work
fn index(request: &mut Request) -> IronResult<Response> {
    let msg = match request.extensions.get_mut::<Session>() {
        Some(mut session) => {
            let message = match session.get_bytes("message".to_string()).and_then(|b| str::from_utf8(b).ok()) {
                Some(message) => {
                    message.to_string()
                }
                None => {
                    let mut body = String::new();
                    let _ = request.body.read_to_string(&mut body).unwrap();
                    if body.len() > 8 {
                        body[8..body.len()].to_string()
                    } else {
                        "message to short!".to_string()
                    }
                }
            };
            session.set_bytes("message".to_string(), message.clone().into_bytes());
            message
        },
        None => {
            let mut body = String::new();
            let _ = request.body.read_to_string(&mut body).unwrap();
            if body.len() > 8 {
                let message = body[8..body.len()].to_string();
                message
            } else {
                "no session yet!".to_string()
            }
        }
    };

    if msg != "no session yet!" {
        let mut session = Session::new();
        session.set_bytes("message".to_string(), msg.clone().into_bytes());
        request.extensions.insert::<Session>(session);
    }

    // in the real world, one would use something like handlebars instead of this hackiness
    let html = include_str!("./index.html").replace("SESSION_MESSAGE", &msg);

    let mut response = Response::with((status::Ok, html));
    response.headers.set(ContentType::html());

    Ok(response)
}
