pub mod header;
pub mod keys;
pub mod error;
pub mod encrypt;

use std::default;

use header::Header;
use keys::SessionKeys;
use noodles::cram::data_container::compression_header::preservation_map::tag_ids_dictionary::Key;
use rand::Rng;
use rand::rngs::OsRng;
use rand_chacha::{ChaCha20Rng, rand_core::{ RngCore, SeedableRng }};

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

    pub fn encrypt(self, plaintext: PlainText, keys: KeyPair) -> Result<CypherText, Crypt4GHError> {
        // let recipient_keys = KeyPair::public_key(&self);

        // if recipient_keys.is_empty() {
        //     return Err(Crypt4GHError::NoRecipients);
	    // }

        // log::info!("Encrypting the file");
        // log::debug!("    Start Coordinate: {}", range_start);

        // // Seek
        // if range_start > 0 {
        //     log::info!("Forwarding to position: {}", range_start);
        // }

        let seed = OsRng.gen();
        let mut session_key = SessionKeys::from(Vec::with_capacity(32).as_ref());
        let mut rnd = ChaCha20Rng::seed_from_u64(seed);
        let header = Header::new();
 
        // random bytes into session_key
        // FIXME: Support multiple session keys? Refactor SessionKeys type to single session_key if not used.
        rnd.try_fill_bytes(&mut session_key.inner.unwrap()[0]).map_err(|_| Crypt4GHError::NoRandomNonce)?;

        header.encrypt(plaintext, keys, Some(session_key))

        //log::debug!("header length: {}", header_bytes.len());

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