/// Implements Crypt4GH §2.1 (Keys)

use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use crypto_kx;
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
// TODO: We'll need to accomodate types such as Crypt4GHPubkey, Crypt4GHPrivkey
use ssh_key::{public::PublicKey as SSHPublicKey, public::Ed25519PublicKey};

use crate::Recipients;

const C4GH_MAGIC_WORD: &[u8; 7] = b"c4gh-v1";
const SSH_MAGIC_WORD: &[u8; 15] = b"openssh-key-v1\x00";

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone, Serialize)]
pub enum EncryptionMethod {
	X25519Chacha20Poly305,
	Aes256Gcm,
}

// User -> private/public -> generate -> GenerateKeyPair.02x
// User -> private/public, public_key -> Send to them.


/// Crypt4GH §2.1.1 Asymmetric Keys

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

/// Crypt4Gh spec §2.1.2
/// K_data: Symmetric data key stored in data encryption parameters header packet.
///
/// It is possible to encrypt parts of a file with different data keys, in which case each key will be 
/// stored in a separate data encryption parameters header packet.
/// 
/// Data Keys are used to encrypt the actual data payload of the file(s) or data stream(s).
pub struct DataKeys {
	inner: Vec<Vec<u8>>
}

impl DataKeys {
	/// Create a new DataKeys instance.
	pub fn new() -> Self {
		Self { inner: Vec::new() }
	}

	/// Add a data key to the inner keys.
	pub fn add_key(&mut self, key: Vec<u8>) {
		self.inner.push(key);
	}

	/// Get the inner data keys.
	pub fn inner(&self) -> &Vec<Vec<u8>> {
		&self.inner
	}

	/// Convert the data keys to bytes.
	pub fn to_bytes(&self) -> Vec<u8> {
		self.inner.iter().flat_map(|key| key.clone()).collect()
	}

	/// Convert the data keys to a single vector of bytes.
	pub fn to_vec(&self) -> Vec<u8> {
		self.to_bytes()
	}
}


/// Private keys are just bytes since it should support disparate formats, i.e: SSH and GA4GH
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct PrivateKey {
	pub bytes: Vec<u8>,
}

/// Different types of public keys are supported 
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub enum PublicKey {
	SSH,
	Crypt4GH,
}

impl KeyPair {
	// /// Generate a new (random) public key.
	// pub fn new_chacha20poly1305() -> Self {
	// 	let genkey = ChaCha20Poly1305::generate_key(OsRng);
	// 	PublicKey::ChaCha20Poly1305(genkey)
	// }
	/// Generates a Crypt4GH KeyPair from scratch using RustCrypto's crypto_kx
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
}

// impl TryFrom<&[u8]> for PublicKey {
// 	type Error = crate::error::Crypt4GHError;

// 	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
// 		if bytes.is_empty() {
// 			Err(crate::error::Crypt4GHError::InvalidPublicKey)
// 		}
// 		else {
// 			Ok(PublicKey { bytes: bytes.to_vec() })
// 		}
// 	}
// }

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

pub fn get_brainstorm_public_key() -> Ed25519PublicKey {
    *SSHPublicKey::from_openssh("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICWwC2CWtve93K0BubV0gf74kvzDG9WM5SfXAAcr+5dy rvalls@Romans-MBP.lan")
        .unwrap()
        .key_data()
        .ed25519()
        .unwrap()
}