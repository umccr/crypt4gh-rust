use crate::error::Crypt4GHError;
use crate::keys::KeyPair;
use crate::plaintext::PlainText;
use crate::{Crypt4GhBuilder, Segment};

pub struct Reader<R> {
	inner: R,
}

#[derive(Debug)]
pub struct CypherText {
	segments: Vec<Segment>,
}

impl CypherText {
	pub fn new() -> Self {
		CypherText { segments: Vec::new() }
	}

	pub fn decrypt(self, keys: KeyPair) -> Result<PlainText, Crypt4GHError> {
		let cg4h = Crypt4GhBuilder::new(keys.clone()).build();
		let plaintext = cg4h.decrypt(self, keys.private_key().clone())?;
		Ok(plaintext)
	}

	pub fn append_segment(&mut self, segment: Segment) {
		self.segments.push(segment);
	}
}
