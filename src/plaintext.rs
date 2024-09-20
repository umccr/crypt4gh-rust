use crate::cyphertext::CypherText;
use crate::error::Crypt4GHError;
use crate::keys::KeyPair;
use crate::{Crypt4Gh, Recipients};

/// Plaintext newtype, avoids API misuse
#[derive(Debug)]
pub struct PlainText {
	inner: Vec<u8>,
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
		let cg4h = Crypt4Gh::new(keys);
		let cyphertext = cg4h.encrypt(plaintext, recipients).with_range(plaintext.length())?;
		Ok(cyphertext)
	}

	pub fn length(&self) -> usize {
		self.inner.len()
	}
}
