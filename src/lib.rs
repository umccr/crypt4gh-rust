pub mod header;
pub mod keys;
pub mod error;
pub mod plaintext;
pub mod cyphertext;

use crate::{error::Crypt4GHError, keys::KeyPair};
use header::Header;
use keys::SessionKeys;
use plaintext::PlainText;
use cyphertext::CypherText;

use rand::Rng;
use rand::rngs::OsRng;
use rand_chacha::{ChaCha20Rng, rand_core::{ RngCore, SeedableRng }};

#[derive(Clone)]
pub struct Crypt4Gh<'a> {
    keys: &'a KeyPair<'a>,
    seed: u64,
}

impl<'a> Crypt4Gh<'a> {
    pub fn new(keys: &'a KeyPair) -> Crypt4Gh<'a> {
        let seed = OsRng.gen();
        Crypt4Gh { keys, seed }
    }

    pub fn encrypt(self, plaintext: PlainText) -> Result<CypherText, Crypt4GHError> {
        let session_key = SessionKeys::from(Vec::with_capacity(32).as_ref());
        let header = Header::new();
        let mut seed = ChaCha20Rng::seed_from_u64(self.seed);

        // random bytes into session_key
        // FIXME: Support multiple session keys? Refactor SessionKeys type to single session_key if not used.
        seed.try_fill_bytes(&mut session_key.inner.clone().unwrap()[0]).map_err(|_| Crypt4GHError::NoRandomNonce)?;

        header.encrypt(plaintext, self.keys.to_owned(), Some(session_key))
    }
    
    pub fn decrypt(self, _cyphertext: CypherText) -> Result<PlainText, Crypt4GHError> {
        todo!();
        //Ok(PlainText::from("payload".as_bytes().to_vec()))
    }
}