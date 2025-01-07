use crate::error::Crypt4GHError;
use crate::keys::KeyPair;
use crate::plaintext::PlainText;
use crate::Crypt4GhBuilder;

pub struct Reader<R> {
	inner: R,
}

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
		let cg4h = Crypt4GhBuilder::new(keys.clone()).build();
		let plaintext = cg4h.decrypt(self, keys.private_key)?;
		Ok(plaintext)
	}

	pub fn append_segment(&mut self, segment: &[u8]) {
		self.inner.extend_from_slice(segment);
	}
}
