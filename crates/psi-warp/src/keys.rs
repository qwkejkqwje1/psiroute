use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{Result, WarpError};

#[derive(Clone)]
pub struct KeyPair {
    pub private: StaticSecret,
    pub public: PublicKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let private = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&private);
        Self { private, public }
    }

    pub fn from_private_base64(text: &str) -> Result<Self> {
        let private = StaticSecret::from(decode_key(text)?);
        let public = PublicKey::from(&private);
        Ok(Self { private, public })
    }

    pub fn private_base64(&self) -> String {
        STANDARD.encode(self.private.to_bytes())
    }

    pub fn public_base64(&self) -> String {
        STANDARD.encode(self.public.as_bytes())
    }
}

pub fn decode_key(text: &str) -> Result<[u8; 32]> {
    let bytes = STANDARD
        .decode(text.trim())
        .map_err(|error| WarpError::Keys(format!("base64: {error}")))?;
    bytes
        .try_into()
        .map_err(|_| WarpError::Keys("ожидалось 32 байта ключа".to_string()))
}

pub fn public_from_base64(text: &str) -> Result<PublicKey> {
    Ok(PublicKey::from(decode_key(text)?))
}
