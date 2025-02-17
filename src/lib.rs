pub mod ciphertext;
pub mod error;
pub mod header;
pub mod keys;
pub mod plaintext;
pub mod io;

use std::ops::RangeBounds;

use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::{Aead, AeadMutInPlace};
use chacha20poly1305::consts::U32;
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, KeyInit};
use crypto_kx::{Keypair as CryptoKeyPair, SecretKey as CryptoSecretKey};
use ciphertext::DataBlocks;
use header::{Header, HeaderWithKeys};
use keys::{DataKey, PrivateKey};
use plaintext::PlainText;
use chacha20poly1305::aead::OsRng;

use crate::error::Crypt4GHError;
use crate::keys::{KeyPair, PublicKey};

/// Crypt4gh spec §3.4.1 - Chacha20 IETF Poly1305 encryption
///
/// (...) Poly1305 is used to generate a 16-byte message authentication code (MAC) over the cipher-text.
pub const MAC_LENGTH: usize = 16;

/// (...) In IETF mode the nonce is 96 bits long.
pub const NONCE_LENGTH: usize = 12; 

/// Crypt4gh spec §3.4.2 - Segmenting the input
pub const PLAINTEXT_SEGMENT_SIZE: usize = 65535;

#[derive(Debug)]
pub struct CipherText {
	inner: Vec<u8>
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

/// To allow random access without having to authenticate the entire file, the plain-text is divided into 65536-byte (64KiB) segments.
/// If the plain-text is not a multiple of 64KiB long, the last segment will be shorter. Each segment is encrypted
/// using the method defined in the header. The nonce used to encrypt the segment is then stored, followed by the encrypted data, and then the MAC.
///
/// The addition of the nonce and mac bytes will expand the data slightly. For chacha20 ietf poly1305, this expansion will be 28 bytes,
/// so a 65536 byte plain-text input will become a 65564 byte encrypted and authenticated cipher-text output.
#[derive(Debug)]
pub struct Segment {
	nonce: Nonce,
	cipher_text: CipherText,
	mac: Mac,
}

impl Segment {
	pub fn new(nonce: Nonce, cipher_text: CipherText, mac: Mac) -> Self {
		Segment {
			nonce,
			cipher_text,
			mac,
		}
	}

	/// Encrypts a segment with the header's Data Key.
	///
	/// Returns [ nonce + `encrypted_data` + mac].
	///
	pub fn new_from_key(data: &[u8], key: &DataKey) -> Result<Self, Crypt4GHError> {
		// TODO: Add basic input validation? (len(data)>0)...
		
		// Convert Crypt4GH to RustCrypto primitives/cipher
		let key_array = GenericArray::clone_from_slice(key.as_slice());
		let mut cipher = ChaCha20Poly1305::new(&key_array);

		let nonce = GenericArray::clone_from_slice(&Nonce::new()?.into_inner());

		// Detached == return the MAC as a separate "Tag" entity?
		let mut buffer = Vec::with_capacity(data.len());
        buffer.extend_from_slice(data);

		let mac = cipher.encrypt_in_place_detached(&nonce, &[], &mut buffer).map_err(|_| Crypt4GHError::NoSupportedEncryptionMethod)?;
		let nonce = Nonce::from(nonce.to_vec());
		let mac = Mac::from(mac.to_vec());

		let segment = Segment::new(nonce, CipherText::new(buffer), mac);

		Ok(segment)
	}

	pub fn to_bytes(self) -> Vec<u8> {
		let mut bytes = Vec::new();
		bytes.extend_from_slice(&self.nonce.into_inner());
		bytes.extend_from_slice(&self.cipher_text.inner);
		bytes.extend_from_slice(&self.mac.inner);
		bytes
	}
}

#[derive(Clone)]
pub struct Crypt4Gh {
	keys: KeyPair,
	range: std::ops::Range<usize>,
	seed: Seed,
}

pub struct Crypt4GhBuilder {
	keys: KeyPair,
	range: Option<std::ops::Range<usize>>,
	seed: Option<Seed>,
}

/// Multiple recipients and their public keys
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Recipients {
	pub public_keys: Vec<PublicKey>,
}

impl Recipients {
	pub fn from(public_keys: Vec<PublicKey>) -> Self {
		Recipients { public_keys }
	}

	pub fn is_empty(&self) -> bool {
		self.public_keys.is_empty()
	}

	pub fn add(&mut self, public_key: PublicKey) {
		self.public_keys.push(public_key);
	}

	pub fn into_inner(self) -> Vec<PublicKey> {
		self.public_keys
	}
}

#[derive(Clone)]
pub struct Seed {
	pub inner: [u8; 32],
}

/// Crypt4gh spec §3.3.1 - X25519 ChaCha20 IETF Poly1305 Encryption
///
/// (...) The nonce is a unique initialisation vector. In ChaCha20-IETF-Poly1305 it is 12 bytes long.
/// This value MUST be unique for each packet encrypted with the same reader’s and writer’s keys.
/// The best way to ensure this is to generate a value with a cryptographically-secure random number generator.
#[derive(Debug)]
pub struct Nonce {
	pub inner: [u8; NONCE_LENGTH],
}

#[derive(Debug)]
pub struct Mac {
	pub inner: [u8; MAC_LENGTH],
}

impl Mac {
	pub fn into_inner(self) -> [u8; MAC_LENGTH] {
		self.inner
	}

	pub fn as_slice(&self) -> &[u8; MAC_LENGTH] {
		&self.inner
	}
}

impl Nonce {
	pub fn new() -> Result<Self, Crypt4GHError> {
		let nonce = ChaCha20Poly1305::generate_nonce(OsRng).as_slice().try_into().map_err(|_| Crypt4GHError::UnableToWrapNonce)?;
		Ok(Nonce { inner: nonce })
	}

	pub fn into_inner(self) -> [u8; NONCE_LENGTH] {
		self.inner
	}
}


impl From<Vec<u8>> for Nonce {
	fn from(bytes: Vec<u8>) -> Self {
		let mut inner = [0u8; NONCE_LENGTH];
		inner.copy_from_slice(&bytes[..NONCE_LENGTH]);
		Nonce { inner }
	}
}

impl From<Vec<u8>> for Mac {
	fn from(bytes: Vec<u8>) -> Self {
		let mut inner = [0u8; MAC_LENGTH];
		inner.copy_from_slice(&bytes[..MAC_LENGTH]);
		Mac { inner }
	}
}

pub struct Crypt4GHFile {
	header: Header,
	data_blocks: DataBlocks,
}

impl Crypt4GHFile {
	pub fn new(header: Header, data_blocks: DataBlocks) -> Self {
		Self {
			header,
			data_blocks
		}
	}

	/// Convert the file to a little endian vector of bytes.
	pub fn to_bytes(self) -> Vec<u8> {
		let mut bytes = Vec::new();
		bytes.extend_from_slice(&self.header.to_bytes());
		bytes.extend_from_slice(&self.data_blocks.to_bytes());
		bytes
	}
}


impl Crypt4Gh {
	// TODO: Recipients should be Some()
	pub fn encrypt(&self, plaintext: PlainText, keys: KeyPair, recipients: Recipients) -> Result<Crypt4GHFile, Crypt4GHError> {
		if recipients.is_empty() {
			return Err(Crypt4GHError::NoRecipients);
		}

		// Create the crypt4gh header.
		let (header, data_keys) = HeaderWithKeys::from_keypair(recipients, keys)?.into_inner();

		// TODO: Implement for all recipients instead of just the first datake
		let data_key = &data_keys[0];

		let mut data_blocks = DataBlocks::new();
		// let nonce = Nonce::new(); // FIXME: Careful, nonce should be re-calculated for each header packet
		// 								 // unclear if the original implementation did that?

		// Split into 64Kib segments, and encrypt them.
		// Encrypt segments
		for data_slice in plaintext.chunks(PLAINTEXT_SEGMENT_SIZE) {
			let segment = Segment::new_from_key(data_slice, &data_key)?;
			data_blocks.append_segment(segment);
		}

		Ok(Crypt4GHFile::new(header, data_blocks))
	}

	pub fn decrypt(self, cyphertext: CipherText, private_key: PrivateKey) -> Result<PlainText, Crypt4GHError> {
		todo!();
		// Ok(PlainText::from("payload".as_bytes().to_vec()))
	}

	
}

impl Crypt4GhBuilder {
	pub fn new(keys: KeyPair) -> Crypt4GhBuilder {
		Crypt4GhBuilder {
			keys,
			range: None,
			seed: None,
		}
	}

	pub fn with_range<T: RangeBounds<usize>>(mut self, range: T) -> Self {
		let start = match range.start_bound() {
			std::ops::Bound::Included(start) => *start + 1,
			std::ops::Bound::Excluded(start) => *start,
			std::ops::Bound::Unbounded => 0,
		};
		let end = match range.end_bound() {
			std::ops::Bound::Included(end) => *end + 1,
			std::ops::Bound::Excluded(end) => *end,
			std::ops::Bound::Unbounded => usize::MAX,
		};

		self.range = Some(start..end);
		self
	}

	pub fn build(self) -> Crypt4Gh {
		Crypt4Gh {
			keys: self.keys,
			range: self.range.unwrap_or(0..usize::MAX),
			seed: self.seed.unwrap(),
		}
	}

	pub fn add_recipient(mut self, recipient: PublicKey) -> Self {
		self.keys.public_keys.add(recipient);
		self
	}
}

// fn encrypt_x25519_chacha20_poly1305(
// 	data: &[u8],
// 	private_key: PrivateKey,
// 	recipients: Recipients,
// ) -> Result<Vec<u8>, Crypt4GHError> {
// 	let server_sk = CryptoSecretKey::try_from(&private_key.bytes[0..CryptoSecretKey::BYTES])
// 		.map_err(|_| Crypt4GHError::BadClientPrivateKey)?;
// 	let client_pk =
// 		PublicKey::try_from(recipients.public_keys[0].clone()).map_err(|_| Crypt4GHError::BadServerPublicKey)?;

// 	let server_pk = server_sk.public_key();

// 	let nonce = ChaCha20Poly1305::generate_nonce(OsRng);

// 	let keypair = CryptoKeyPair::from(server_sk);
// 	let server_session_keys = keypair.session_keys_from(&client_pk);
// 	let shared_key = GenericArray::<u8, U32>::from_slice(&server_session_keys.rx.as_ref().as_slice());

// 	let cipher = ChaCha20Poly1305::new(shared_key);

// 	let ciphertext = cipher
// 		.encrypt(&nonce, data)
// 		.map_err(|err| Crypt4GHError::UnableToEncryptPacket(err.to_string()))?;

// 	Ok(vec![server_pk.as_ref(), nonce.as_slice(), ciphertext.as_slice()].concat())
// }

