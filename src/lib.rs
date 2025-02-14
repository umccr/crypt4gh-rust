pub mod cyphertext;
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
use cyphertext::CypherText;
use header::Header;
use keys::{DataKey, PrivateKey, SharedKeys};
use plaintext::PlainText;
use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use serde::Serialize;

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

/// To allow random access without having to authenticate the entire file, the plain-text is divided into 65536-byte (64KiB) segments.
/// If the plain-text is not a multiple of 64KiB long, the last segment will be shorter. Each segment is encrypted
/// using the method defined in the header. The nonce used to encrypt the segment is then stored, followed by the encrypted data, and then the MAC.
///
/// The addition of the nonce and mac bytes will expand the data slightly. For chacha20 ietf poly1305, this expansion will be 28 bytes,
/// so a 65536 byte plain-text input will become a 65564 byte encrypted and authenticated cipher-text output.
#[derive(Debug)]
pub struct Segment {
	nonce: Nonce,
	encrypted_data: CypherText,
	mac: Mac,
}

impl Segment {
	pub fn new(nonce: Nonce, encrypted_data: CypherText, mac: Mac) -> Self {
		Segment {
			nonce,
			encrypted_data,
			mac,
		}
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
	public_keys: Vec<PublicKey>,
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
#[derive(Debug, Serialize)]
pub struct Nonce {
	pub inner: [u8; NONCE_LENGTH],
}

#[derive(Debug, Serialize)]
pub struct Mac {
	pub inner: [u8; MAC_LENGTH],
}

impl Nonce {
	pub fn new() -> Self {
		// TODO: Use this instead?
		//let nonce = ChaCha20Poly1305::generate_nonce(OsRng);

		let mut nonce = [0u8; NONCE_LENGTH];
		OsRng.fill_bytes(&mut nonce);
		Nonce { inner: nonce }
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

impl<'a> Crypt4Gh {
	// TODO: Recipients should be Some()
	pub fn encrypt(&self, plaintext: PlainText, keys: KeyPair, recipients: Recipients) -> Result<CypherText, Crypt4GHError> {
		if recipients.is_empty() {
			return Err(Crypt4GHError::NoRecipients);
		}

		let shared_keys = SharedKeys::derive(keys);

		// Create the crypt4gh header.
		let header = Header::encrypt(recipients, shared_keys)?;

		let data_key = DataKey::generate();
		let mut cyphertext = CypherText::new();
		let nonce = Nonce::new(); // FIXME: Careful, nonce should be re-calculated for each header packet
										 // unclear if the original implementation did that?

		// Encrypt segments
		for segment in plaintext.chunks(PLAINTEXT_SEGMENT_SIZE) {
			let encrypted_segment = Crypt4GhBuilder::encrypt_segment(segment, &nonce, &data_key)?;
			cyphertext.append_segment(encrypted_segment);
		}

		Ok(cyphertext)
	}

	pub fn decrypt(self, cyphertext: CypherText, private_key: PrivateKey) -> Result<PlainText, Crypt4GHError> {
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
			seed: self.seed.unwrap_or(Seed { inner: OsRng.gen() }),
		}
	}

	/// Encrypts a segment with the header's Data Key.
	///
	/// Returns [ nonce + `encrypted_data` + mac].
	///
	pub fn encrypt_segment(data: &[u8], nonce: &Nonce, key: &DataKey) -> Result<Segment, Crypt4GHError> {
		// Convert Crypt4GH to RustCrypto primitives/cipher
		let key_array = GenericArray::clone_from_slice(key.as_slice());
		let mut cipher = ChaCha20Poly1305::new(&key_array);

		// Same for Nonce
		let nonce = GenericArray::from_slice(&nonce.inner);

		// Detached == return the MAC as a separate "Tag" entity?
		let mut buffer = Vec::with_capacity(data.len());
        buffer.extend_from_slice(data);

		let mac = cipher.encrypt_in_place_detached(&nonce, &[], &mut buffer).map_err(|_| Crypt4GHError::NoSupportedEncryptionMethod)?;
		let ciphertext = CypherText::from(buffer);

		let nonce = Nonce::from(nonce.to_vec());
		let mac = Mac::from(mac.to_vec());

		let segment = Segment::new(nonce, ciphertext, mac);

		Ok(segment)
	}

	pub fn add_recipient(mut self, recipient: PublicKey) -> Self {
		self.keys.public_keys.add(recipient);
		self
	}
}

fn encrypt_x25519_chacha20_poly1305(
	data: &[u8],
	private_key: PrivateKey,
	recipients: Recipients,
) -> Result<Vec<u8>, Crypt4GHError> {
	let server_sk = CryptoSecretKey::try_from(&private_key.bytes[0..CryptoSecretKey::BYTES])
		.map_err(|_| Crypt4GHError::BadClientPrivateKey)?;
	let client_pk =
		PublicKey::try_from(recipients.public_keys[0].clone()).map_err(|_| Crypt4GHError::BadServerPublicKey)?;

	let server_pk = server_sk.public_key();

	let nonce = ChaCha20Poly1305::generate_nonce(OsRng);

	let keypair = CryptoKeyPair::from(server_sk);
	let server_session_keys = keypair.session_keys_from(&client_pk);
	let shared_key = GenericArray::<u8, U32>::from_slice(&server_session_keys.rx.as_ref().as_slice());

	let cipher = ChaCha20Poly1305::new(shared_key);

	let ciphertext = cipher
		.encrypt(&nonce, data)
		.map_err(|err| Crypt4GHError::UnableToEncryptPacket(err.to_string()))?;

	Ok(vec![server_pk.as_ref(), nonce.as_slice(), ciphertext.as_slice()].concat())
}

