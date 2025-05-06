use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::consts::U32;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use chacha20poly1305::AeadInPlace;

use crate::error::Crypt4GHError;
use crate::header::SharedKey;
use crate::keys::KeyPair;
use crate::plaintext::PlainText;
use crate::{Crypt4GHFile, Crypt4GhBuilder, Mac, Nonce, MAC_LENGTH, NONCE_LENGTH, PLAINTEXT_SEGMENT_SIZE};

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

	pub fn decrypt(self, keys: KeyPair) -> Result<PlainText, Crypt4GHError> {
		let c4gh = Crypt4GhBuilder::new(keys.clone()).build();
		let file = Crypt4GHFile::from_ciphertext(self)?;
		let plaintext = c4gh.decrypt(file, keys.private_key().clone())?;

		Ok(plaintext)
	}

	/// Encryption
	pub fn from_c4gh_file(c4gh_file: Crypt4GHFile) -> Result<CipherText, Crypt4GHError> {
		let ciphertext = c4gh_file.to_bytes();
		Ok(Self::new(ciphertext))
	}
}

impl TryFrom<Crypt4GHFile> for CipherText {
    type Error = Crypt4GHError;

	fn try_from(c4gh_file: Crypt4GHFile) -> Result<Self, Self::Error> {
		Self::from_c4gh_file(c4gh_file)	
	}
}

#[derive(Debug, Clone)]
pub struct EncryptedData {
	encrypted_data: Vec<u8>
}

impl EncryptedData {
	pub fn new(data: Vec<u8>) -> Self {
		Self { encrypted_data: data }
	}

	pub fn to_bytes(&self) -> Vec<u8> {
		self.encrypted_data.clone()
	}
}

/// Body Data Block: same structure that a header segment has, but with different context/functions.
#[derive(Debug, Clone)]
pub struct DataBlock {
	nonce: Nonce,
	encrypted_data: EncryptedData,
	mac: Mac,
}

impl DataBlock {
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(NONCE_LENGTH + MAC_LENGTH + PLAINTEXT_SEGMENT_SIZE);
		bytes.extend(self.nonce.clone().into_inner());
		bytes.extend(self.encrypted_data.to_bytes());
		bytes.extend(self.mac.clone().into_inner());
		bytes
	}

	pub fn decrypt(self, header_private_key: SharedKey) -> Result<Vec<u8>, Crypt4GHError> {
		let header_key = header_private_key.into_inner();
		let shared_key = GenericArray::<u8, U32>::from_slice(header_key.as_slice());
		let decrypt = ChaCha20Poly1305::new(shared_key);

		let mac = GenericArray::from(self.mac.inner);
		let nonce = GenericArray::from(self.nonce.inner);
		let mut buffer = self.encrypted_data.encrypted_data;
		decrypt.decrypt_in_place_detached(&nonce, &[], &mut buffer, &mac);

		Ok(buffer)
	}
}

/// Body Data BlockS.
#[derive(Debug, Clone)]
pub struct DataBlocks {
	blocks: Vec<DataBlock>
}

impl DataBlocks {
	pub fn new() -> Self {
		Self { blocks: vec![] }
	}

	pub fn from_bytes(bytes: &[u8]) -> Result<Self, Crypt4GHError> {
		let mut blocks = Vec::new();
		let mut offset = 0;
		let block_size = NONCE_LENGTH + PLAINTEXT_SEGMENT_SIZE + MAC_LENGTH;

		while offset + block_size <= bytes.len() {
			let nonce = Nonce::from_slice(&bytes[offset..offset + NONCE_LENGTH])?;
			offset += NONCE_LENGTH;

			let encrypted_data = EncryptedData::new(bytes[offset..offset + PLAINTEXT_SEGMENT_SIZE].to_vec());
			offset += PLAINTEXT_SEGMENT_SIZE;

			let mac = Mac::from_slice(&bytes[offset..offset + MAC_LENGTH])?;
			offset += MAC_LENGTH;

			blocks.push(DataBlock {
				nonce,
				encrypted_data,
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

impl IntoIterator for DataBlocks {
	type Item = DataBlock;
	type IntoIter = std::vec::IntoIter<DataBlock>;

	fn into_iter(self) -> Self::IntoIter {
		self.blocks.into_iter()
	}
}