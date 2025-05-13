use crate::ciphertext::DataBlocks;
use crate::error::Crypt4GHError;
use crate::keys::KeyPair;
use crate::{Crypt4GhBuilder, Recipients, PLAINTEXT_SEGMENT_SIZE};

/// Plaintext newtype, avoids API misuse
#[derive(Debug)]
pub struct PlainText {
	inner: Vec<u8>,
	pos: usize,
}


pub struct Reader<R> {
	inner: R,
}

pub struct Writer<W> {
	inner: W,
}

impl<R> Reader<R> {
	pub fn new(inner: R) -> Self {
		Reader { inner }
	}
}

impl PlainText {
	pub fn from(payload: Vec<u8>) -> Self {
		PlainText { inner: payload, pos: 0 }
	}

	fn encrypt(
		plaintext: PlainText,
		recipients: Recipients,
		keys: KeyPair,
	) -> Result<DataBlocks, Crypt4GHError> {
		// FIXME: Revisit builder and/or this function to adjust .with_range() bounds... 0 is incorrect
		let cg4h = Crypt4GhBuilder::new(keys.clone()).with_range(0..plaintext.length()).build();
		let ciphertext = cg4h.encrypt(Box::new(plaintext), keys, recipients)?;
		Ok(ciphertext.data_blocks)
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
