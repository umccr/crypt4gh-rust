use crate::cyphertext::CypherText;
use crate::error::Crypt4GHError;
use crate::keys::KeyPair;
use crate::Crypt4Gh;

/// Plaintext newtype, avoids API misuse
#[derive(Debug)]
pub struct PlainText {
    inner: Vec<u8>
}

impl PlainText {
    pub fn from(payload: Vec<u8>) -> Self {
        PlainText { inner: payload }
    }

    pub fn encrypt(self, plaintext: PlainText, keys: KeyPair) -> Result<CypherText, Crypt4GHError> {
        let cg4h = Crypt4Gh::new(&keys);
        let cyphertext = cg4h.encrypt(plaintext)?;
        Ok(cyphertext)
    }

    // // FIXME: to_recipient() as alias for this method?
    // pub fn with_pubkey() {

    // }
}