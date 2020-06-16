#![feature(test)]

extern crate bincode;
extern crate chrono;
extern crate secure_session;
#[cfg(test)]
extern crate test;

use bincode::Infinite;
use chrono::prelude::*;
use secure_session::session::Session;
use std::collections::HashMap;
use std::str;
use test::Bencher;

const STRINGS: &str = include_str!("./strings.txt");
const KEY_32: [u8; 32] = *b"01234567012345670123456701234567";

fn session_data(x: usize) -> Session<HashMap<String, String>> {
    assert!(x <= 1000); // there are only 1000 lines in the file
    let mut map = HashMap::new();

    for s in STRINGS.split("\n").take(x) {
        let _ = map.insert(s.to_string(), str::from_utf8(&[0; 64]).unwrap().to_string());
    }

    let expires = Some(Utc.ymd(2017, 1, 1).and_hms(0, 0, 0));
    Session {
        expires: expires,
        value: Some(map),
    }
}

#[bench]
fn session_data_serialize_0_items(b: &mut Bencher) {
    let session = session_data(0);
    b.iter(|| {
        let _ = bincode::serialize(&session, Infinite).expect("failed to serialize");
    });
}

#[bench]
fn session_data_deserialize_0_items(b: &mut Bencher) {
    let session = session_data(0);
    let bytes = bincode::serialize(&session, Infinite).expect("failed to serialize");
    b.iter(|| {
        let _: Session<HashMap<String, String>> =
            bincode::deserialize(&bytes).expect("failed to deserialize");
    });
}

#[bench]
fn session_data_serialize_10_items(b: &mut Bencher) {
    let session = session_data(10);
    b.iter(|| {
        let _ = bincode::serialize(&session, Infinite).expect("failed to serialize");
    });
}

#[bench]
fn session_data_deserialize_10_items(b: &mut Bencher) {
    let session = session_data(10);
    let bytes = bincode::serialize(&session, Infinite).expect("failed to serialize");
    b.iter(|| {
        let _: Session<HashMap<String, String>> =
            bincode::deserialize(&bytes).expect("failed to deserialize");
    });
}

#[bench]
fn session_data_serialize_100_items(b: &mut Bencher) {
    let session = session_data(100);
    b.iter(|| {
        let _ = bincode::serialize(&session, Infinite).expect("failed to serialize");
    });
}

#[bench]
fn session_data_deserialize_100_items(b: &mut Bencher) {
    let session = session_data(100);
    let bytes = bincode::serialize(&session, Infinite).expect("failed to serialize");
    b.iter(|| {
        let _: Session<HashMap<String, String>> =
            bincode::deserialize(&bytes).expect("failed to deserialize");
    });
}

#[bench]
fn session_data_serialize_1000_items(b: &mut Bencher) {
    let session = session_data(1000);
    b.iter(|| {
        let _ = bincode::serialize(&session, Infinite).expect("failed to serialize");
    });
}

#[bench]
fn session_data_deserialize_1000_items(b: &mut Bencher) {
    let session = session_data(1000);
    let bytes = bincode::serialize(&session, Infinite).expect("failed to serialize");
    b.iter(|| {
        let _: Session<HashMap<String, String>> =
            bincode::deserialize(&bytes).expect("failed to deserialize");
    });
}

macro_rules! benchmark {
    ($strct: ident, $md: ident) => {
        mod $md {
            use super::{session_data, KEY_32};
            use secure_session::session::{$strct, SessionManager};
            use test::Bencher;

            #[bench]
            fn session_data_serialize_0_items(b: &mut Bencher) {
                let session = session_data(0);
                let manager = $strct::from_key(KEY_32);
                b.iter(|| {
                    let _ = manager.serialize(&session).expect("failed to serialize");
                });
            }

            #[bench]
            fn session_data_deserialize_0_items(b: &mut Bencher) {
                let session = session_data(0);
                let manager = $strct::from_key(KEY_32);
                let bytes = manager.serialize(&session).expect("failed to serialize");
                b.iter(|| {
                    let _ = manager.deserialize(&bytes).expect("failed to deserialize");
                });
            }

            #[bench]
            fn session_data_serialize_10_items(b: &mut Bencher) {
                let session = session_data(10);
                let manager = $strct::from_key(KEY_32);
                b.iter(|| {
                    let _ = manager.serialize(&session).expect("failed to serialize");
                });
            }

            #[bench]
            fn session_data_deserialize_10_items(b: &mut Bencher) {
                let session = session_data(10);
                let manager = $strct::from_key(KEY_32);
                let bytes = manager.serialize(&session).expect("failed to serialize");
                b.iter(|| {
                    let _ = manager.deserialize(&bytes).expect("failed to deserialize");
                });
            }

            #[bench]
            fn session_data_serialize_100_items(b: &mut Bencher) {
                let session = session_data(100);
                let manager = $strct::from_key(KEY_32);
                b.iter(|| {
                    let _ = manager.serialize(&session).expect("failed to serialize");
                });
            }

            #[bench]
            fn session_data_deserialize_100_items(b: &mut Bencher) {
                let session = session_data(100);
                let manager = $strct::from_key(KEY_32);
                let bytes = manager.serialize(&session).expect("failed to serialize");
                b.iter(|| {
                    let _ = manager.deserialize(&bytes).expect("failed to deserialize");
                });
            }

            #[bench]
            fn session_data_serialize_1000_items(b: &mut Bencher) {
                let session = session_data(1000);
                let manager = $strct::from_key(KEY_32);
                b.iter(|| {
                    let _ = manager.serialize(&session).expect("failed to serialize");
                });
            }

            #[bench]
            fn session_data_deserialize_1000_items(b: &mut Bencher) {
                let session = session_data(1000);
                let manager = $strct::from_key(KEY_32);
                let bytes = manager.serialize(&session).expect("failed to serialize");
                b.iter(|| {
                    let _ = manager.deserialize(&bytes).expect("failed to deserialize");
                });
            }
        }
    };
}

benchmark!(AesGcmSessionManager, aesgcm);
benchmark!(ChaCha20Poly1305SessionManager, chacha20poly1305);
