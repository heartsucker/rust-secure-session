#![feature(test)]

extern crate bincode;
extern crate chrono;
extern crate secure_session;
#[cfg(test)]
extern crate test;

use bincode::Infinite;
use chrono::prelude::*;
use secure_session::session::{Session, SessionTransport};
use test::Bencher;

const STRINGS: &str = include_str!("./strings.txt");
const KEY_32: [u8; 32] = *b"01234567012345670123456701234567";

fn session_transport(x: usize) -> SessionTransport {
    assert!(x <= 1000);

    let mut session = Session::new();

    for s in STRINGS.split("\n").take(x) {
        let _ = session.insert_bytes(s, vec![0; 64]);
    }

    let expires = Some(UTC.ymd(2017, 1, 1).and_hms(0, 0, 0));
    SessionTransport { expires: expires, session: session }
}

#[bench]
fn session_transport_serialize_0_items(b: &mut Bencher) {
    let transport = session_transport(0);
    b.iter(|| {
        let _ = bincode::serialize(&transport, Infinite).expect("failed to serialize");
    });
}

#[bench]
fn session_transport_deserialize_0_items(b: &mut Bencher) {
    let transport = session_transport(0);
    let bytes = bincode::serialize(&transport, Infinite).expect("failed to serialize");
    b.iter(|| {
        let _: SessionTransport = bincode::deserialize(&bytes).expect("failed to deserialize");
    });
}

#[bench]
fn session_transport_serialize_10_items(b: &mut Bencher) {
    let transport = session_transport(10);
    b.iter(|| {
        let _ = bincode::serialize(&transport, Infinite).expect("failed to serialize");
    });
}

#[bench]
fn session_transport_deserialize_10_items(b: &mut Bencher) {
    let transport = session_transport(10);
    let bytes = bincode::serialize(&transport, Infinite).expect("failed to serialize");
    b.iter(|| {
        let _: SessionTransport = bincode::deserialize(&bytes).expect("failed to deserialize");
    });
}

#[bench]
fn session_transport_serialize_100_items(b: &mut Bencher) {
    let transport = session_transport(100);
    b.iter(|| {
        let _ = bincode::serialize(&transport, Infinite).expect("failed to serialize");
    });
}

#[bench]
fn session_transport_deserialize_100_items(b: &mut Bencher) {
    let transport = session_transport(100);
    let bytes = bincode::serialize(&transport, Infinite).expect("failed to serialize");
    b.iter(|| {
        let _: SessionTransport = bincode::deserialize(&bytes).expect("failed to deserialize");
    });
}

#[bench]
fn session_transport_serialize_1000_items(b: &mut Bencher) {
    let transport = session_transport(1000);
    b.iter(|| {
        let _ = bincode::serialize(&transport, Infinite).expect("failed to serialize");
    });
}

#[bench]
fn session_transport_deserialize_1000_items(b: &mut Bencher) {
    let transport = session_transport(1000);
    let bytes = bincode::serialize(&transport, Infinite).expect("failed to serialize");
    b.iter(|| {
        let _: SessionTransport = bincode::deserialize(&bytes).expect("failed to deserialize");
    });
}

macro_rules! benchmark {
    ($strct: ident, $md: ident) => {
        mod $md {
            use secure_session::session::{$strct, SessionManager};
            use super::{session_transport, KEY_32};
            use test::Bencher;

            #[bench]
            fn session_transport_serialize_0_items(b: &mut Bencher) {
                let transport = session_transport(0);
                let manager = $strct::from_key(KEY_32);
                b.iter(|| {
                    let _ = manager.serialize(&transport).expect("failed to serialize");
                });
            }

            #[bench]
            fn session_transport_deserialize_0_items(b: &mut Bencher) {
                let transport = session_transport(0);
                let manager = $strct::from_key(KEY_32);
                let bytes = manager.serialize(&transport).expect("failed to serialize");
                b.iter(|| {
                    let _ = manager.deserialize(&bytes).expect("failed to deserialize");
                });
            }

            #[bench]
            fn session_transport_serialize_10_items(b: &mut Bencher) {
                let transport = session_transport(10);
                let manager = $strct::from_key(KEY_32);
                b.iter(|| {
                    let _ = manager.serialize(&transport).expect("failed to serialize");
                });
            }

            #[bench]
            fn session_transport_deserialize_10_items(b: &mut Bencher) {
                let transport = session_transport(10);
                let manager = $strct::from_key(KEY_32);
                let bytes = manager.serialize(&transport).expect("failed to serialize");
                b.iter(|| {
                    let _ = manager.deserialize(&bytes).expect("failed to deserialize");
                });
            }

            #[bench]
            fn session_transport_serialize_100_items(b: &mut Bencher) {
                let transport = session_transport(100);
                let manager = $strct::from_key(KEY_32);
                b.iter(|| {
                    let _ = manager.serialize(&transport).expect("failed to serialize");
                });
            }

            #[bench]
            fn session_transport_deserialize_100_items(b: &mut Bencher) {
                let transport = session_transport(100);
                let manager = $strct::from_key(KEY_32);
                let bytes = manager.serialize(&transport).expect("failed to serialize");
                b.iter(|| {
                    let _ = manager.deserialize(&bytes).expect("failed to deserialize");
                });
            }

            #[bench]
            fn session_transport_serialize_1000_items(b: &mut Bencher) {
                let transport = session_transport(1000);
                let manager = $strct::from_key(KEY_32);
                b.iter(|| {
                    let _ = manager.serialize(&transport).expect("failed to serialize");
                });
            }

            #[bench]
            fn session_transport_deserialize_1000_items(b: &mut Bencher) {
                let transport = session_transport(1000);
                let manager = $strct::from_key(KEY_32);
                let bytes = manager.serialize(&transport).expect("failed to serialize");
                b.iter(|| {
                    let _ = manager.deserialize(&bytes).expect("failed to deserialize");
                });
            }

        }
    }
}

benchmark!(AesGcmSessionManager, aesgcm);
benchmark!(ChaCha20Poly1305SessionManager, chacha20poly1305);
