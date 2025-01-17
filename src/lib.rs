pub mod cyphertext;
pub mod error;
pub mod header;
pub mod keys;
pub mod plaintext;
pub mod io;

use std::collections::HashSet;
use std::ops::RangeBounds;

use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::{Aead, AeadMutInPlace};
use chacha20poly1305::consts::U32;
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, KeyInit};
use crypto_kx::{Keypair as CryptoKeyPair, SecretKey as CryptoSecretKey};
use cyphertext::CypherText;
use header::HeaderPacketType;
use keys::{DataKeys, DataKey, EncryptionMethod, PrivateKey, SharedKeys};
use plaintext::PlainText;
use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use serde::Serialize;

use crate::error::Crypt4GHError;
use crate::keys::{KeyPair, PublicKey};

pub const MAC_LENGTH: usize = 16;
pub const NONCE_LENGTH: usize = 12; 

/// Crypt4gh spec §3.4.2
pub const PLAINTEXT_SEGMENT_SIZE: usize = 65535;

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

impl<'a> Crypt4Gh {
	pub fn encrypt(&self, plaintext: PlainText, _recipients: Recipients) -> Result<CypherText, Crypt4GHError> {
		// Create the crypt4gh header.

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

/// Computes the encrypted header part for each key in the given collection
///
/// Given a set of keys and a vector of bytes representing a packet, this function iterates over the keys and encrypts the packet using the x25519_chacha20_poly1305 encryption method.
/// It returns a vector of encrypted segments, where each segment represents the encrypted packet for a specific key.
///
/// * `packet` - A vector of bytes representing the packet to be encrypted
/// * `keys` - A collection of keypairs with `key.method` equal to 0
pub fn compute_encrypted_header(packet: &[u8], keys: &HashSet<KeyPair>) -> Result<Vec<Vec<u8>>, Crypt4GHError> {
	keys.iter()
		.filter(|key| key.method == EncryptionMethod::X25519Chacha20Poly305)
		.map(
			|key| match encrypt_x25519_chacha20_poly1305(packet, key.private_key.clone(), key.public_keys.clone()) {
				Ok(session_key) => Ok(vec![u32::from(key.method as u32).to_le_bytes().to_vec(), session_key].concat()),
				Err(e) => Err(e),
			},
		)
		.collect()
}

/// Constructs an encrypted data packet with the given encryption method and session keys
fn construct_encrypted_data_packet(encryption_method: EncryptionMethod, session_keys: Option<SharedKeys>) -> Vec<u8> {
	vec![
		bincode::serialize(&HeaderPacketType::DataEnc).expect("Unable to serialize packet type"),
		(encryption_method as u32).to_le_bytes().to_vec(),
		session_keys.unwrap().to_bytes(),
	]
	.concat()
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
}

#[derive(Clone)]
pub struct Seed {
	pub inner: [u8; 32],
}

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
