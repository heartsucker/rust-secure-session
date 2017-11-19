//! Sessions and session management utilities.

use bincode::{self, Infinite};
use chrono::{DateTime, Utc};
use crypto::aead::{AeadEncryptor, AeadDecryptor};
use crypto::aes::KeySize;
use crypto::aes_gcm::AesGcm;
use crypto::chacha20poly1305::ChaCha20Poly1305;
use crypto::scrypt::{scrypt, ScryptParams};
use ring::rand::{SecureRandom, SystemRandom};
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use std::marker::PhantomData;

use error::SessionError;

const SCRYPT_SALT: &'static [u8; 31] = b"rust-secure-session-scrypt-salt";

/// A session with an exipiration date and optional value.
#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct Session<V> {
    /// The Utc timestamp when the session expires.
    pub expires: Option<DateTime<Utc>>,
    /// The value of the session.
    pub value: Option<V>,
}


/// Base trait that provides session management.
pub trait SessionManager<V: Serialize + DeserializeOwned>: Send + Sync {
    /// Using `scrypt` with params `n=12`, `r=8`, `p=1`, generate the key material used for the
    /// underlying crypto functions.
    ///
    /// # Panics
    /// This function may panic if the underlying crypto library fails catastrophically.
    fn from_password(password: &[u8]) -> Self;

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
    rng: SystemRandom,
    aead_key: [u8; 32],
    _value: PhantomData<V>,
}

impl<V: Serialize + DeserializeOwned> ChaCha20Poly1305SessionManager<V> {
    /// Using a saved key, generate a `ChaCha20Poly1305SessionManager`.
    pub fn from_key(aead_key: [u8; 32]) -> Self {
        ChaCha20Poly1305SessionManager {
            rng: SystemRandom::new(),
            aead_key: aead_key,
            _value: PhantomData,
        }
    }

    fn random_bytes(&self, buf: &mut [u8]) -> Result<(), SessionError> {
        self.rng.fill(buf).map_err(|err| {
            warn!("Failed to get random bytes: {}", err);
            SessionError::InternalError
        })
    }

    fn aead(&self, nonce: &[u8; 8]) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(&self.aead_key, nonce, &[])
    }
}

impl<V: Serialize + DeserializeOwned + Send + Sync> SessionManager<V>
    for ChaCha20Poly1305SessionManager<V> {
    fn from_password(password: &[u8]) -> Self {
        let params = if cfg!(test) {
            // scrypt is *slow*, so use these params for testing
            ScryptParams::new(1, 8, 1)
        } else {
            ScryptParams::new(12, 8, 1)
        };

        let mut aead_key = [0; 32];
        info!("Generating key material. This may take some time.");
        scrypt(password, SCRYPT_SALT, &params, &mut aead_key);
        info!("Key material generated.");

        ChaCha20Poly1305SessionManager::from_key(aead_key)
    }

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

        bincode::deserialize(&plaintext[16..plaintext.len()]).map_err(|err| {
            warn!("Failed to deserialize session: {}", err);
            SessionError::InternalError
        })
    }

    fn serialize(&self, session: &Session<V>) -> Result<Vec<u8>, SessionError> {
        let mut nonce = [0; 8];
        self.random_bytes(&mut nonce)?;

        let session_bytes = bincode::serialize(&session, Infinite).map_err(|err| {
            warn!("Failed to serialize session: {}", err);
            SessionError::InternalError
        })?;

        let mut padding = [0; 16];
        self.random_bytes(&mut padding)?;

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
    rng: SystemRandom,
    aead_key: [u8; 32],
    _value: PhantomData<V>,
}

impl<V: Serialize + DeserializeOwned> AesGcmSessionManager<V> {
    /// Using a saved key, generate a `AesGcmSessionManager`.
    pub fn from_key(aead_key: [u8; 32]) -> Self {
        AesGcmSessionManager {
            rng: SystemRandom::new(),
            aead_key: aead_key,
            _value: PhantomData,
        }
    }

    fn random_bytes(&self, buf: &mut [u8]) -> Result<(), SessionError> {
        self.rng.fill(buf).map_err(|err| {
            warn!("Failed to get random bytes: {}", err);
            SessionError::InternalError
        })
    }

    fn aead<'a>(&self, nonce: &[u8; 12]) -> AesGcm<'a> {
        AesGcm::new(KeySize::KeySize256, &self.aead_key, nonce, &[])
    }
}

impl<V: Serialize + DeserializeOwned + Send + Sync> SessionManager<V> for AesGcmSessionManager<V> {
    fn from_password(password: &[u8]) -> Self {
        let params = if cfg!(test) {
            // scrypt is *slow*, so use these params for testing
            ScryptParams::new(1, 8, 1)
        } else {
            ScryptParams::new(12, 8, 1)
        };

        let mut aead_key = [0; 32];
        info!("Generating key material. This may take some time.");
        scrypt(password, SCRYPT_SALT, &params, &mut aead_key);
        info!("Key material generated.");

        AesGcmSessionManager::from_key(aead_key)
    }

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

        bincode::deserialize(&plaintext[16..plaintext.len()]).map_err(|err| {
            warn!("Failed to deserialize session: {}", err);
            SessionError::InternalError
        })
    }

    fn serialize(&self, session: &Session<V>) -> Result<Vec<u8>, SessionError> {
        let mut nonce = [0; 12];
        self.random_bytes(&mut nonce)?;

        let session_bytes = bincode::serialize(&session, Infinite).map_err(|err| {
            warn!("Failed to serialize session: {}", err);
            SessionError::InternalError
        })?;

        let mut padding = [0; 16];
        self.random_bytes(&mut padding)?;

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

#[cfg(test)]
mod tests {

    macro_rules! test_cases {
        ($strct: ident, $md: ident) => {
            mod $md  {
                use $crate::error::SessionError;
                use $crate::session::{$strct, SessionManager, Session};

                const KEY: [u8; 32] = *b"01234567012345670123456701234567";

                #[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug)]
                struct Data {
                    string: String,
                }

                #[test]
                fn serde_happy_path() {
                    let manager = $strct::from_key(KEY);
                    let data = Data { string: "boots and cats".to_string() };
                    let session = Session { expires: None, value: Some(data.clone()) };
                    let bytes = manager.serialize(&session).expect("couldn't serialize");
                    let parsed_session = manager.deserialize(&bytes).expect("couldn't deserialize");
                    assert_eq!(parsed_session.value, Some(data));
                }

                #[test]
                fn serde_bad_data_end() {
                    let manager = $strct::from_key(KEY);
                    let data = Data { string: "boots and cats".to_string() };
                    let session = Session { expires: None, value: Some(data.clone()) };
                    let mut bytes = manager.serialize(&session).expect("couldn't serialize");
                    let len = bytes.len();
                    bytes[len - 1] ^= 0x01;

                    let deserialized: Result<Session<Data>, SessionError> = manager.deserialize(&bytes);
                    assert!(deserialized.is_err());
                }

                #[test]
                fn serde_bad_data_start() {
                    let manager = $strct::from_key(KEY);
                    let data = Data { string: "boots and cats".to_string() };
                    let session = Session { expires: None, value: Some(data.clone()) };

                    let mut bytes = manager.serialize(&session).expect("couldn't serialize");
                    bytes[0] ^= 0x01;

                    let deserialized: Result<Session<Data>, SessionError> = manager.deserialize(&bytes);
                    assert!(deserialized.is_err());
                }
            }
        }
    }

    test_cases!(AesGcmSessionManager, aesgcm);
    test_cases!(ChaCha20Poly1305SessionManager, chacha20poly1305);
}
