//! Sessions and session management utilities

use bincode::{self, Infinite};
use crypto::aead::{AeadEncryptor, AeadDecryptor};
use crypto::chacha20poly1305::ChaCha20Poly1305;
use crypto::scrypt::{scrypt, ScryptParams};
use ring::rand::SystemRandom;
use std::collections::HashMap;
use typemap;

use error::SessionError;

const SCRYPT_SALT: &[u8; 31] = b"rust-secure-session-scrypt-salt";

/// Persistent session passed to client as a cookie.
#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct Session {
    expires: Option<i64>, // TODO
    map: HashMap<String, Vec<u8>>,
}

impl Session {
    /// Create an empty session.
    pub fn new() -> Self {
        Session {
            expires: None,
            map: HashMap::new(),
        }
    }

    /// Store bytes for the given key.
    pub fn get_bytes(&self, key: String) -> Option<&Vec<u8>> {
        self.map.get(&key)
    }

    /// Retrieve bytes for the given key.
    pub fn set_bytes(&mut self, key: String, bytes: Vec<u8>) {
        let _ = self.map.insert(key, bytes);
    }

    /// Remove bytes stored at the given key.
    pub fn remove(&mut self, key: String) {
        let _ = self.map.remove(&key);
    }
}

impl typemap::Key for Session {
    type Value = Session;
}


/// Base trait that provides session management.
pub trait SessionManager: Send + Sync {
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
    fn deserialize(&self, bytes: &[u8]) -> Result<Session, SessionError>;

    /// Given a session perform the following options to convert it into a bytes:
    ///
    ///   * Encrypt (optional)
    ///   * Sign / MAC
    ///   * Encode / serialize into bytes
    fn serialize(&self, session: &Session) -> Result<Vec<u8>, SessionError>;

    /// Whether or not the sessions are encrypted.
    fn is_encrypted(&self) -> bool;
}


/// Uses the ChaCha20Poly1305 AEAD to provide signed, encrypted sessions.
pub struct ChaCha20Poly1305SessionManager {
    rng: SystemRandom,
    aead_key: [u8; 32],
}

impl ChaCha20Poly1305SessionManager {
    /// Using a saved key, generate a `ChaCha20Poly1305SessionManager`.
    pub fn from_key(aead_key: [u8; 32]) -> Self {
        ChaCha20Poly1305SessionManager {
            rng: SystemRandom::new(),
            aead_key: aead_key,
        }
    }

    fn random_bytes(&self, buf: &mut [u8]) -> Result<(), SessionError> {
        self.rng
            .fill(buf)
            .map_err(|_| {
                warn!("Failed to get random bytes");
                SessionError::InternalError
            })
    }

    fn aead(&self, nonce: &[u8; 8]) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(&self.aead_key, nonce, &[])
    }
}

impl SessionManager for ChaCha20Poly1305SessionManager {
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

    fn deserialize(&self, bytes: &[u8]) -> Result<Session, SessionError> {
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

        // TODO strip padding

        Ok(bincode::deserialize(&plaintext[16..plaintext.len()]).unwrap()) // TODO unwrap
    }

    fn serialize(&self, session: &Session) -> Result<Vec<u8>, SessionError> {
        let mut nonce = [0; 8];
        self.random_bytes(&mut nonce)?;

        let session_bytes = bincode::serialize(&session, Infinite).unwrap(); // TODO unwrap
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

    fn is_encrypted(&self) -> bool { true }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = *b"01234567012345670123456701234567";

    #[test]
    fn session_basics() {
        let mut session = Session::new();
        let key = "wat".to_string();
        let value = b"lol".to_vec();

        session.set_bytes(key.clone(), value.clone());
        assert_eq!(session.get_bytes(key.clone()), Some(&value));

        session.remove(key.clone());
        assert_eq!(session.get_bytes(key.clone()), None);
    }

    #[test]
    fn chacha20poly1305_basics() {
        let manager = ChaCha20Poly1305SessionManager::from_key(KEY);
        let mut session = Session::new();
        let key = "lol".to_string();
        let value = b"wat".to_vec();
        session.set_bytes(key.clone(), value.clone());

        let bytes = manager.serialize(&session).expect("couldn't serialize");
        let parsed_session = manager.deserialize(&bytes).expect("couldn't deserialize");
        assert_eq!(parsed_session, session);
        assert_eq!(parsed_session.get_bytes(key), Some(&value));
    }
}
