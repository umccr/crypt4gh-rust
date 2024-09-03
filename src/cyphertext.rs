use crate::{error::Crypt4GHError, keys::KeyPair, plaintext::PlainText, Crypt4Gh};

#[derive(Debug)]
pub struct CypherText {
	inner: Vec<u8>,
}

impl CypherText {
	pub fn from_vec(vec: Vec<u8>) -> Self {
		CypherText { inner: vec }
	}

	pub fn decrypt(self, keys: KeyPair) -> Result<PlainText, Crypt4GHError> {
		let cg4h = Crypt4Gh::new(&keys);
		let plaintext = cg4h.decrypt(self)?;
		Ok(plaintext)
	}
}
