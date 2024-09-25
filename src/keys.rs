use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use crypto_kx;
use rand::rngs::OsRng;
use serde::Serialize;

use crate::Recipients;

const C4GH_MAGIC_WORD: &[u8; 7] = b"c4gh-v1";
const SSH_MAGIC_WORD: &[u8; 15] = b"openssh-key-v1\x00";

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone, Serialize)]
pub enum EncryptionMethod {
	X25519Chacha20Poly305,
	Aes256Gcm,
}

/// Public/Private KeyPair information.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct KeyPair {
	/// Method used for the key encryption.
	/// > Only method 0 is supported.
	pub method: EncryptionMethod,
	/// Secret key of the encryptor / decryptor (your key).
	pub private_key: PrivateKey,
	/// Public key(s) of the recipient(s)
	pub public_keys: Recipients,
}

/// Represents a collection of session keys.
///
/// The `SessionKeys` struct contains an optional vector of vectors of bytes,
/// which can be used to store multiple session keys.
///
/// # Fields
///
/// * `inner` - An optional vector of vectors of bytes representing the session keys.
#[derive(Debug)]
pub struct SessionKeys {
	pub inner: Option<Vec<Vec<u8>>>,
}

impl SessionKeys {
	/// Create a new SessionKeys instance.
	pub fn new(inner: Vec<Vec<u8>>) -> Self {
		Self { inner: Some(inner) }
	}

	/// Get the inner session keys.
	pub fn inner(&self) -> &Option<Vec<Vec<u8>>> {
		&self.inner
	}

	/// Create a new SessionKeys instance from a slice of session keys.
	pub fn from(session_keys: Vec<Vec<u8>>) -> Self {
		Self {
			inner: Some(session_keys),
		}
	}

	/// Convert the session keys to bytes.
	pub fn to_bytes(&self) -> Vec<u8> {
		match &self.inner {
			Some(keys) => keys.iter().flat_map(|key| key.clone()).collect(),
			None => vec![],
		}
	}

	/// Convert the session keys to a single vector of bytes.
	pub fn to_vec(&self) -> Vec<u8> {
		self.to_bytes()
	}

	/// Add a session key to the inner session keys.
	pub fn add_session_key(&mut self, session_key: Vec<u8>) {
		Some(session_key);
	}
}

/// Private keys are just bytes since it should support disparate formats, i.e: SSH and GA4GH
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct PrivateKey {
	pub bytes: Vec<u8>,
}

/// A wrapper around a vec of bytes that represent a public key.
#[derive(Debug, Clone, PartialEq, Hash, Eq, Serialize)]
pub struct PublicKey {
	pub bytes: Vec<u8>,
}

impl KeyPair {
	/// Generates a KeyPair from scratch using RustCrypto's crypto_kx
	pub fn generate(&mut self) -> Self {
		let keypair = crypto_kx::Keypair::generate(&mut OsRng);

		let mut public_keys = vec![];
		public_keys.push(PublicKey::from(keypair.public().as_ref().as_slice().to_vec()));
		let recipients = Recipients::from(public_keys);

		let private_key = PrivateKey::from(keypair.secret().to_bytes().to_vec());

		self.public_keys = recipients;
		self.private_key = private_key;

		self.to_owned()
	}

	/// Create a new KeyPair from pre-existing public and private keys
	pub fn new(method: EncryptionMethod, private_key: PrivateKey, public_keys: Recipients) -> Self {
		KeyPair {
			method,
			private_key,
			public_keys,
		}
	}

	/// Get the inner keys.
	pub fn into_inner(&self) -> (PrivateKey, Recipients) {
		(self.private_key.clone(), self.public_keys.to_owned())
	}

	/// Get private key.
	pub fn private_key(&self) -> &PrivateKey {
		&self.private_key
	}

	/// Get private key
	pub fn public_key(&self) -> &Recipients {
		&self.public_keys
	}
}

impl PublicKey {
	/// Generate a new (random) public key.
	pub fn new() -> Self {
		let bytes = ChaCha20Poly1305::generate_key(OsRng).to_vec();
		PublicKey { bytes }
	}

	/// Create a new public key from bytes.
	pub fn from(bytes: Vec<u8>) -> Self {
		Self { bytes }
	}

	/// Get the inner bytes.
	pub fn into_inner(self) -> Vec<u8> {
		self.bytes
	}

	/// Get the inner bytes as a reference.
	pub fn get_ref(&self) -> &[u8] {
		self.bytes.as_slice()
	}

	/// Get key length
	pub fn len(&self) -> usize {
		self.bytes.len()
	}
}

impl TryFrom<&[u8]> for PublicKey {
	type Error = crate::error::Crypt4GHError;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		if bytes.is_empty() {
			Err(crate::error::Crypt4GHError::InvalidPublicKey)
		}
		else {
			Ok(PublicKey { bytes: bytes.to_vec() })
		}
	}
}

impl PrivateKey {
	/// Generate a new private key.
	pub fn new() -> Self {
		let bytes = ChaCha20Poly1305::generate_key(OsRng).to_vec();
		PrivateKey { bytes }
	}

	/// Create a new private key from bytes.
	pub fn from(bytes: Vec<u8>) -> Self {
		Self { bytes }
	}

	/// Retrieve public key from private key
	pub fn get_public_key(self) {
		todo!()
	}

	/// Get the inner bytes.
	pub fn into_inner(self) -> Vec<u8> {
		self.bytes
	}

	/// Get the inner bytes as a reference.
	pub fn get_ref(&self) -> &[u8] {
		self.bytes.as_slice()
	}

	/// Get key length
	pub fn len(&self) -> usize {
		self.bytes.len()
	}
}
