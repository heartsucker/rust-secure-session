//! Sessions and session management utilities.

use crate::error::SessionError;
use crypto::aead::{AeadDecryptor, AeadEncryptor};
use crypto::aes::KeySize;
use crypto::aes_gcm::AesGcm;
use crypto::chacha20poly1305::ChaCha20Poly1305;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use time::OffsetDateTime;

/// A session with an exipiration date and optional value.
#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct Session<V> {
    /// The Utc timestamp when the session expires.
    pub expires: Option<OffsetDateTime>,
    /// The value of the session.
    pub value: Option<V>,
}

/// Base trait that provides session management.
pub trait SessionManager<V: Serialize + DeserializeOwned>: Send + Sync {
    /// Given a slice of bytes perform the following options to convert it into a `Session`:
    ///
    ///   * Decrypt (optional)
    ///   * Verify signature / MAC
    ///   * Parse / deserialize into a `Session` struct
    fn deserialize(&self, bytes: &[u8]) -> Result<Session<V>, SessionError>;

    /// Given a session perform the following options to convert a `Session` into bytes:
    ///
    ///   * Encode / serialize into bytes
    ///   * Encrypt (optional)
    ///   * Sign / MAC
    fn serialize(&self, session: &Session<V>) -> Result<Vec<u8>, SessionError>;

    /// Whether or not the sessions are encrypted.
    fn is_encrypted(&self) -> bool;
}

/// Uses the ChaCha20Poly1305 AEAD to provide signed, encrypted sessions.
pub struct ChaCha20Poly1305SessionManager<V: Serialize + DeserializeOwned> {
    aead_key: [u8; 32],
    _value: PhantomData<V>,
}

impl<V: Serialize + DeserializeOwned> ChaCha20Poly1305SessionManager<V> {
    /// Using a saved key, generate a `ChaCha20Poly1305SessionManager`.
    pub fn from_key(aead_key: [u8; 32]) -> Self {
        ChaCha20Poly1305SessionManager {
            aead_key: aead_key,
            _value: PhantomData,
        }
    }

    fn random_bytes(&self, buf: &mut [u8]) {
        OsRng.fill_bytes(buf);
    }

    fn aead(&self, nonce: &[u8; 8]) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(&self.aead_key, nonce, &[])
    }
}

impl<V: Serialize + DeserializeOwned + Send + Sync> SessionManager<V>
    for ChaCha20Poly1305SessionManager<V>
{
    fn deserialize(&self, bytes: &[u8]) -> Result<Session<V>, SessionError> {
        if bytes.len() <= 40 {
            return Err(SessionError::ValidationError);
        }

        let mut ciphertext = vec![0; bytes.len() - 24];
        let mut plaintext = vec![0; bytes.len() - 24];
        let mut tag = [0; 16];
        let mut nonce = [0; 8];

        for i in 0..8 {
            nonce[i] = bytes[i];
        }
        for i in 0..16 {
            tag[i] = bytes[i + 8];
        }
        for i in 0..(bytes.len() - 24) {
            ciphertext[i] = bytes[i + 24];
        }

        let mut aead = self.aead(&nonce);
        if !aead.decrypt(&ciphertext, &mut plaintext, &tag) {
            info!("Failed to decrypt session");
            return Err(SessionError::ValidationError);
        }

        serde_cbor::from_slice(&plaintext[16..plaintext.len()]).map_err(|err| {
            warn!("Failed to deserialize session: {}", err);
            SessionError::InternalError
        })
    }

    fn serialize(&self, session: &Session<V>) -> Result<Vec<u8>, SessionError> {
        let mut nonce = [0; 8];
        self.random_bytes(&mut nonce);

        let session_bytes = serde_cbor::to_vec(&session).map_err(|err| {
            warn!("Failed to serialize session: {}", err);
            SessionError::InternalError
        })?;

        let mut padding = [0; 16];
        self.random_bytes(&mut padding);

        let mut plaintext = vec![0; session_bytes.len() + 16];

        for i in 0..16 {
            plaintext[i] = padding[i];
        }
        for i in 0..session_bytes.len() {
            plaintext[i + 16] = session_bytes[i];
        }

        let mut ciphertext = vec![0; plaintext.len()];
        let mut tag = [0; 16];
        let mut aead = self.aead(&nonce);

        aead.encrypt(&plaintext, &mut ciphertext, &mut tag);

        let mut transport = vec![0; ciphertext.len() + 24];

        for i in 0..8 {
            transport[i] = nonce[i];
        }
        for i in 0..16 {
            transport[i + 8] = tag[i];
        }
        for i in 0..ciphertext.len() {
            transport[i + 24] = ciphertext[i];
        }

        Ok(transport)
    }

    /// Whether or not the sessions are encrypted: `true`
    fn is_encrypted(&self) -> bool {
        true
    }
}

/// Uses the AES-GCM AEAD to provide signed, encrypted sessions.
pub struct AesGcmSessionManager<V: Serialize + DeserializeOwned> {
    aead_key: [u8; 32],
    _value: PhantomData<V>,
}

impl<V: Serialize + DeserializeOwned> AesGcmSessionManager<V> {
    /// Using a saved key, generate a `AesGcmSessionManager`.
    pub fn from_key(aead_key: [u8; 32]) -> Self {
        AesGcmSessionManager {
            aead_key: aead_key,
            _value: PhantomData,
        }
    }

    fn random_bytes(&self, buf: &mut [u8]) {
        OsRng.fill_bytes(buf);
    }

    fn aead<'a>(&self, nonce: &[u8; 12]) -> AesGcm<'a> {
        AesGcm::new(KeySize::KeySize256, &self.aead_key, nonce, &[])
    }
}

impl<V: Serialize + DeserializeOwned + Send + Sync> SessionManager<V> for AesGcmSessionManager<V> {
    fn deserialize(&self, bytes: &[u8]) -> Result<Session<V>, SessionError> {
        if bytes.len() <= 44 {
            return Err(SessionError::ValidationError);
        }

        let mut ciphertext = vec![0; bytes.len() - 28];
        let mut plaintext = vec![0; bytes.len() - 28];
        let mut tag = [0; 16];
        let mut nonce = [0; 12];

        for i in 0..12 {
            nonce[i] = bytes[i];
        }
        for i in 0..16 {
            tag[i] = bytes[i + 12];
        }
        for i in 0..(bytes.len() - 28) {
            ciphertext[i] = bytes[i + 28];
        }

        let mut aead = self.aead(&nonce);
        if !aead.decrypt(&ciphertext, &mut plaintext, &tag) {
            info!("Failed to decrypt session");
            return Err(SessionError::ValidationError);
        }

        serde_cbor::from_slice(&plaintext[16..plaintext.len()]).map_err(|err| {
            warn!("Failed to deserialize session: {}", err);
            SessionError::InternalError
        })
    }

    fn serialize(&self, session: &Session<V>) -> Result<Vec<u8>, SessionError> {
        let mut nonce = [0; 12];
        self.random_bytes(&mut nonce);

        let session_bytes = serde_cbor::to_vec(&session).map_err(|err| {
            warn!("Failed to serialize session: {}", err);
            SessionError::InternalError
        })?;

        let mut padding = [0; 16];
        self.random_bytes(&mut padding);

        let mut plaintext = vec![0; session_bytes.len() + 16];

        for i in 0..16 {
            plaintext[i] = padding[i];
        }
        for i in 0..session_bytes.len() {
            plaintext[i + 16] = session_bytes[i];
        }

        let mut ciphertext = vec![0; plaintext.len()];
        let mut tag = [0; 16];
        let mut aead = self.aead(&nonce);

        aead.encrypt(&plaintext, &mut ciphertext, &mut tag);

        let mut transport = vec![0; ciphertext.len() + 28];

        for i in 0..12 {
            transport[i] = nonce[i];
        }
        for i in 0..16 {
            transport[i + 12] = tag[i];
        }
        for i in 0..ciphertext.len() {
            transport[i + 28] = ciphertext[i];
        }

        Ok(transport)
    }

    /// Whether or not the sessions are encrypted: `true`
    fn is_encrypted(&self) -> bool {
        true
    }
}

/// This is used when one wants to rotate keys or switch from implementation to another. It accepts
/// `1 + N` instances of `SessionManager<V>` and uses only the first to generate sessions.
/// All instances are used only for parsing in the order they are passed in to the
/// `MultiSessionManager`.
pub struct MultiSessionManager<V: Serialize + DeserializeOwned + Send + Sync> {
    current: Box<dyn SessionManager<V>>,
    previous: Vec<Box<dyn SessionManager<V>>>,
}

impl<V: Serialize + DeserializeOwned + Send + Sync> MultiSessionManager<V> {
    /// Create a new `MultiSessionManager` from one current `SessionManager` and some `N` previous
    /// instances of `SessionManager`.
    pub fn new(
        current: Box<dyn SessionManager<V>>,
        previous: Vec<Box<dyn SessionManager<V>>>,
    ) -> Self {
        Self { current, previous }
    }
}

impl<V: Serialize + DeserializeOwned + Send + Sync> SessionManager<V> for MultiSessionManager<V> {
    fn deserialize(&self, bytes: &[u8]) -> Result<Session<V>, SessionError> {
        match self.current.deserialize(bytes) {
            ok @ Ok(_) => return ok,
            Err(_) => {
                for manager in self.previous.iter() {
                    match manager.deserialize(bytes) {
                        ok @ Ok(_) => return ok,
                        Err(_) => (),
                    }
                }
            }
        }
        Err(SessionError::ValidationError)
    }

    fn serialize(&self, session: &Session<V>) -> Result<Vec<u8>, SessionError> {
        self.current.serialize(session)
    }

    fn is_encrypted(&self) -> bool {
        self.current.is_encrypted()
    }
}

#[cfg(test)]
mod tests {
    const KEY_1: [u8; 32] = *b"01234567012345670123456701234567";
    const KEY_2: [u8; 32] = *b"76543210765432107654321076543210";

    macro_rules! test_cases {
        ($strct: ident, $md: ident) => {
            mod $md {
                use super::KEY_1;
                use serde::{Deserialize, Serialize};
                use $crate::error::SessionError;
                use $crate::session::{$strct, Session, SessionManager};

                #[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug)]
                struct Data {
                    string: String,
                }

                #[test]
                fn serde_happy_path() {
                    let manager = $strct::from_key(KEY_1);
                    let data = Data {
                        string: "boots and cats".to_string(),
                    };
                    let session = Session {
                        expires: None,
                        value: Some(data.clone()),
                    };
                    let bytes = manager.serialize(&session).expect("couldn't serialize");
                    let parsed_session = manager.deserialize(&bytes).expect("couldn't deserialize");
                    assert_eq!(parsed_session.value, Some(data));
                }

                #[test]
                fn serde_bad_data_end() {
                    let manager = $strct::from_key(KEY_1);
                    let data = Data {
                        string: "boots and cats".to_string(),
                    };
                    let session = Session {
                        expires: None,
                        value: Some(data.clone()),
                    };
                    let mut bytes = manager.serialize(&session).expect("couldn't serialize");
                    let len = bytes.len();
                    bytes[len - 1] ^= 0x01;

                    let deserialized: Result<Session<Data>, SessionError> =
                        manager.deserialize(&bytes);
                    assert!(deserialized.is_err());
                }

                #[test]
                fn serde_bad_data_start() {
                    let manager = $strct::from_key(KEY_1);
                    let data = Data {
                        string: "boots and cats".to_string(),
                    };
                    let session = Session {
                        expires: None,
                        value: Some(data.clone()),
                    };

                    let mut bytes = manager.serialize(&session).expect("couldn't serialize");
                    bytes[0] ^= 0x01;

                    let deserialized: Result<Session<Data>, SessionError> =
                        manager.deserialize(&bytes);
                    assert!(deserialized.is_err());
                }
            }
        };
    }

    test_cases!(AesGcmSessionManager, aesgcm);
    test_cases!(ChaCha20Poly1305SessionManager, chacha20poly1305);

    mod multi {
        macro_rules! test_cases {
            ($strct1: ident, $strct2: ident, $name: ident) => {
                mod $name {
                    use super::super::{KEY_1, KEY_2};
                    use $crate::session::*;

                    #[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug)]
                    struct Data {
                        string: String,
                    }

                    #[test]
                    fn no_previous() {
                        let manager = $strct1::from_key(KEY_1);
                        let mut sessions = vec![];

                        let data = Data {
                            string: "boots and cats".to_string(),
                        };
                        let session = Session {
                            expires: None,
                            value: Some(data.clone()),
                        };
                        let bytes = manager.serialize(&session).expect("couldn't serialize");
                        sessions.push(bytes);

                        let multi = MultiSessionManager::new(Box::new(manager), vec![]);
                        let bytes = multi.serialize(&session).expect("couldn't serialize");
                        sessions.push(bytes);

                        for session in sessions.iter() {
                            let parsed_session =
                                multi.deserialize(session).expect("couldn't deserialize");
                            assert_eq!(parsed_session.value, Some(data.clone()));
                        }
                    }

                    #[test]
                    fn $name() {
                        let manager_1 = $strct1::from_key(KEY_1);
                        let manager_2 = $strct2::from_key(KEY_2);
                        let mut sessions = vec![];

                        let data = Data {
                            string: "boots and cats".to_string(),
                        };
                        let session = Session {
                            expires: None,
                            value: Some(data.clone()),
                        };
                        let bytes = manager_1.serialize(&session).expect("couldn't serialize");
                        sessions.push(bytes);

                        let bytes = manager_2.serialize(&session).expect("couldn't serialize");
                        sessions.push(bytes);

                        let multi = MultiSessionManager::new(
                            Box::new(manager_1),
                            vec![Box::new(manager_2)],
                        );
                        let bytes = multi.serialize(&session).expect("couldn't serialize");
                        sessions.push(bytes);

                        for session in sessions.iter() {
                            let parsed_session =
                                multi.deserialize(session).expect("couldn't deserialize");
                            assert_eq!(parsed_session.value, Some(data.clone()));
                        }
                    }
                }
            };
        }

        test_cases!(
            AesGcmSessionManager,
            AesGcmSessionManager,
            aesgcm_then_aesgcm
        );

        test_cases!(
            ChaCha20Poly1305SessionManager,
            ChaCha20Poly1305SessionManager,
            chacha20poly1305_then_chacha20poly1305
        );

        test_cases!(
            ChaCha20Poly1305SessionManager,
            AesGcmSessionManager,
            chacha20poly1305_then_aesgcm
        );

        test_cases!(
            AesGcmSessionManager,
            ChaCha20Poly1305SessionManager,
            aesgcm_then_chacha20poly1305
        );
    }
}
