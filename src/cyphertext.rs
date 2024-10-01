use crate::error::Crypt4GHError;
use crate::keys::KeyPair;
use crate::plaintext::PlainText;
use crate::Crypt4Gh;

#[derive(Debug)]
pub struct CypherText {
	inner: Vec<u8>,
}

impl CypherText {
	pub fn new() -> Self {
		CypherText { inner: Vec::new() }
	}

	pub fn from(vec: Vec<u8>) -> Self {
		CypherText { inner: vec }
	}

	pub fn decrypt(self, keys: KeyPair) -> Result<PlainText, Crypt4GHError> {
		let cg4h = Crypt4Gh::new(keys);
		let plaintext = cg4h.decrypt(self)?;
		Ok(plaintext)
	}

	pub fn append_segment(&mut self, segment: &[u8]) {
		self.inner.extend_from_slice(segment);
	}
}
