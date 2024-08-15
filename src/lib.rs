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

pub struct Crypt4Gh {
    keys: KeyPair,
}

impl Crypt4Gh {
    pub fn new(keys: KeyPair) -> Crypt4Gh {
        Crypt4Gh { keys }
    }

    pub fn encrypt(self, plaintext: PlainText) -> Result<CypherText, Crypt4GHError> {
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
        let session_key = SessionKeys::from(Vec::with_capacity(32).as_ref());
        let mut rnd = ChaCha20Rng::seed_from_u64(seed);
        let header = Header::new();
 
        // random bytes into session_key
        // FIXME: Support multiple session keys? Refactor SessionKeys type to single session_key if not used.
        rnd.try_fill_bytes(&mut session_key.inner.clone().unwrap()[0]).map_err(|_| Crypt4GHError::NoRandomNonce)?;

        header.encrypt(plaintext, self.keys, Some(session_key))
    }
    
    pub fn decrypt(self, cyphertext: CypherText) -> Result<PlainText, Crypt4GHError> {
        todo!()
    }
}