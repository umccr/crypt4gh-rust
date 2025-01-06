use crate::cyphertext::CypherText;
use crate::error::Crypt4GHError;
use crate::keys::KeyPair;
use crate::{Crypt4GhBuilder, Recipients};

/// Plaintext newtype, avoids API misuse
#[derive(Debug)]
pub struct PlainText {
	inner: Vec<u8>,
}

pub struct PlainTextReader {
	// TODO: Reader
}

impl PlainText {
	pub fn from(payload: Vec<u8>) -> Self {
		PlainText { inner: payload }
	}

	pub fn encrypt(
		self,
		plaintext: PlainText,
		recipients: Recipients,
		keys: KeyPair,
	) -> Result<CypherText, Crypt4GHError> {
		// FIXME: Revisit builder and/or this function to adjust .with_range() bounds.
		let cg4h = Crypt4GhBuilder::new(keys).with_range(0..plaintext.length()).build();
		let cyphertext = cg4h.encrypt(plaintext, recipients)?;
		Ok(cyphertext)
	}

	pub fn length(&self) -> usize {
		self.inner.len()
	}

	pub fn as_slice(&self) -> &[u8] {
		&self.inner
	}

	pub fn chunks(&self, chunk_size: usize) -> impl Iterator<Item = &[u8]> {
		self.inner.chunks(chunk_size)
	}
}
