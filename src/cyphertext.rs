use crate::{error::Crypt4GHError, keys::KeyPair, plaintext::PlainText, Crypt4Gh};

#[derive(Debug)]
pub struct CypherText {
    inner: Vec<u8>
}

impl CypherText {
    pub fn from(cyphertext: CypherText ) -> Self {
        CypherText { inner: cyphertext.inner }
    }

    pub fn decrypt(self, cyphertext: CypherText, keys: KeyPair) -> Result<PlainText, Crypt4GHError> {
        let cg4h = Crypt4Gh::new(keys);
        let plaintext = cg4h.decrypt(cyphertext)?;
        Ok(plaintext)
    }
}
