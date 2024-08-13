pub mod header;
pub mod keys;
pub mod error;
pub mod encrypt;

use rand_chacha::rand_core::SeedableRng;

use crate::{error::Crypt4GHError, keys::KeyPair};

/// Plaintext newtype, avoids API misuse
pub(crate) struct PlainText {
    inner: Vec<u8>
}

pub(crate) struct CypherText {
    inner: Vec<u8>
}

pub struct Crypt4Gh {
    keys: KeyPair,
}

impl PlainText {
    pub fn new(payload: Vec<u8>) -> Self {
        PlainText { inner: payload }
    }

    pub fn encrypt(self, plaintext: PlainText, keys: KeyPair) -> CypherText {
        let mut session_key = [0_u8; 32];
        let mut rnd = rand_chacha::ChaCha20Rng::from_rng()?;
        
        // random bytes into session_key
        rnd.try_fill_bytes(&mut session_key).map_err(|_| Crypt4GHError::NoRandomNonce)?;
        
        let header_bytes = header::encrypt(recipient_keys, &Some(session_key))?;
    
        log::debug!("header length: {}", header_bytes.len());

        CypherText::new(payload)
    }

    // // FIXME: to_recipient() as alias for this method?
    // pub fn with_pubkey() {

    // }
}

impl CypherText {
    pub fn new(payload: Vec<u8>) -> Self {
        CypherText { inner: payload }
    }

    pub fn decrypt(self, cyphertext: CypherText, keys: KeyPair) {
        todo!()
    }
}

impl Crypt4Gh {
    pub fn new(keys: KeyPair) -> Crypt4Gh {
        Crypt4Gh { keys }
    }

    pub fn encrypt(self, plaintext: PlainText) -> Result<CypherText, Crypt4GHError> {
        let encrypted = plaintext.encrypt();
        Ok(encrypted)
    }
    
    pub fn decrypt(self, cyphertext: PlainText) -> Result<PlainText, Crypt4GHError> {
        let decrypted = cyphertext.decrypt();
        Ok(decrypted)
    }
}