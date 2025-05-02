use crate::error::Crypt4GHError;
use crate::keys::KeyPair;
use crate::plaintext::PlainText;
use crate::{Crypt4GhBuilder, Mac, Nonce, Segment, MAC_LENGTH, NONCE_LENGTH, PLAINTEXT_SEGMENT_SIZE};

pub struct Reader<R> {
	inner: R,
}

#[derive(Debug, Clone)]
pub struct CipherText {
	pub inner: Vec<u8>
}

impl CipherText {
	pub fn new(inner: Vec<u8>) -> Self {
		Self { inner }
	}
	// TODO: Move this whole struct and impl to ciphertext.rs
	pub fn decrypt(self, keys: KeyPair) -> Result<PlainText, Crypt4GHError> {
		let cg4h = Crypt4GhBuilder::new(keys.clone()).build();
		let plaintext = cg4h.decrypt(self, keys.private_key().clone())?;
		Ok(plaintext)
	}
}

/// Body Data Block: same structure that a header segment has, but with different context/functions.
#[derive(Debug, Clone)]
pub struct DataBlock {
	nonce: Nonce,
	cipher_text: CipherText,
	mac: Mac,
}

/// Body Data BlockS.
#[derive(Debug, Clone)]
pub struct DataBlocks {
	blocks: Vec<DataBlock>
}

impl DataBlock {
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(NONCE_LENGTH + MAC_LENGTH + PLAINTEXT_SEGMENT_SIZE);
		bytes.extend(self.nonce.clone().into_inner());
		bytes.extend(self.cipher_text.clone().inner);
		bytes.extend(self.mac.clone().into_inner());
		bytes
	}
}

impl DataBlocks {
	pub fn new(blocks: Vec<DataBlock>) -> Self {
		Self { blocks }
	}

	pub fn from_bytes(bytes: &[u8]) -> Result<Self, Crypt4GHError> {
		let mut blocks = Vec::new();
		let mut offset = 0;
		let block_size = NONCE_LENGTH + PLAINTEXT_SEGMENT_SIZE + MAC_LENGTH;

		while offset + block_size <= bytes.len() {
			let nonce = Nonce::from_slice(&bytes[offset..offset + NONCE_LENGTH])?;
			offset += NONCE_LENGTH;

			let cipher_text = CipherText::new(bytes[offset..offset + PLAINTEXT_SEGMENT_SIZE].to_vec());
			offset += PLAINTEXT_SEGMENT_SIZE;

			let mac = Mac::from_slice(&bytes[offset..offset + MAC_LENGTH])?;
			offset += MAC_LENGTH;

			blocks.push(DataBlock {
				nonce,
				cipher_text,
				mac,
			});
		}

		if offset != bytes.len() {
			return Err(Crypt4GHError::InvalidDataBlock("oops".to_string()));
		}

		Ok(Self { blocks })
	}

	pub fn to_bytes(&self) -> Vec<u8> {
		self.blocks.iter().flat_map(|block| block.to_bytes()).collect()
	}

	pub fn len(&self) -> usize {
		self.blocks.len()
	}

	pub fn is_empty(&self) -> bool {
		self.blocks.is_empty()
	}

	pub fn blocks(&self) -> &Vec<DataBlock> {
		&self.blocks
	}
}