pub mod ciphertext;
pub mod error;
pub mod header;
pub mod keys;
pub mod plaintext;
pub mod io;

use std::io::Read;
use std::ops::RangeBounds;

use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::{Aead, AeadMutInPlace};
use chacha20poly1305::consts::U32;
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, KeyInit};
use crypto_kx::{Keypair as CryptoKeyPair, SecretKey as CryptoSecretKey};
use ciphertext::{CipherText, DataBlock, DataBlocks};
use header::{Header, HeaderWithKeys, SharedKey};
use io::reader::chunks::ChunkDataBlocks;
use io::reader::reader::Reader;
use keys::{DataKey, PrivateKey};
use plaintext::PlainText;
use chacha20poly1305::aead::OsRng;
use ssh_key::rand_core::RngCore;

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
	pub nonce: Nonce,
	pub cipher_text: CipherText,
	pub mac: Mac,
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
		if data.is_empty() {
			return Err(Crypt4GHError::InvalidInputData("Data cannot be empty".to_string()));
		}
		
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

	pub fn from_bytes(bytes: &[u8]) -> Result<Self, Crypt4GHError> {
		if bytes.len() < NONCE_LENGTH + MAC_LENGTH {
			return Err(Crypt4GHError::InvalidInputData("Not enough bytes to form a Segment".to_string()));
		}

		let nonce = Nonce::from(bytes[..NONCE_LENGTH].to_vec());
		let mac = Mac::from(bytes[bytes.len() - MAC_LENGTH..].to_vec());
		let cipher_text = CipherText::new(bytes[NONCE_LENGTH..bytes.len() - MAC_LENGTH].to_vec());

		Ok(Segment::new(nonce, cipher_text, mac))
	}

	pub fn length(&self) -> usize {
		NONCE_LENGTH + self.cipher_text.inner.len() + MAC_LENGTH
	}
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

impl Seed {
	pub fn new() -> Self {
		let mut inner = [0u8; 32];
		OsRng.fill_bytes(&mut inner);
		Seed { inner }
	}
}

/// Crypt4gh spec §3.3.1 - X25519 ChaCha20 IETF Poly1305 Encryption
///
/// (...) The nonce is a unique initialisation vector. In ChaCha20-IETF-Poly1305 it is 12 bytes long.
/// This value MUST be unique for each packet encrypted with the same reader’s and writer’s keys.
/// The best way to ensure this is to generate a value with a cryptographically-secure random number generator.
#[derive(Debug, Clone)]
pub struct Nonce {
	pub inner: [u8; NONCE_LENGTH],
}

#[derive(Debug, Clone)]
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

	pub fn from_slice(slice: &[u8]) -> Result<Self, Crypt4GHError> {
        if slice.len() != MAC_LENGTH {
            return Err(Crypt4GHError::InvalidDataBlock("Invalid MAC length".to_string()));
        }
        let mut inner = [0u8; MAC_LENGTH];
        inner.copy_from_slice(slice);
        Ok(Mac { inner })
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

    pub fn from_slice(slice: &[u8]) -> Result<Self, Crypt4GHError> {
        if slice.len() != NONCE_LENGTH {
            return Err(Crypt4GHError::UnableToWrapNonce);
        }
        let mut inner = [0u8; NONCE_LENGTH];
        inner.copy_from_slice(slice);
        Ok(Nonce { inner })
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

/// Represents encrypted data.
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

	pub fn from_ciphertext(ciphertext: CipherText) -> Result<Self, Crypt4GHError> {
		let header = Header::from_bytes(ciphertext.inner.as_slice())?;

		let length = header.length();
		let (_, data) = ciphertext.inner.split_at(length);

		let data_blocks = DataBlocks::from_bytes(data)?;
		Ok(Crypt4GHFile::new(header, data_blocks))
	}
}

#[derive(Clone)]
pub struct Crypt4Gh {
	keys: KeyPair,
	range: std::ops::Range<usize>,
	seed: Seed,
}

impl Crypt4Gh {
	// TODO: Recipients should be Some()
	pub fn encrypt(&self, plaintext: Reader<PlainText>, keys: KeyPair, recipients: Recipients) -> Result<Crypt4GHFile, Crypt4GHError> {
		if recipients.is_empty() {
			return Err(Crypt4GHError::NoRecipients);
		}

		// Create the crypt4gh header.
		let (header, data_keys) = HeaderWithKeys::from_keypair(recipients, keys)?.into_inner();

		// TODO: Implement for all recipients instead of just the first data_key
		let shared_key = &data_keys[0];
		
		// Encrypt header data blocks
		let data_blocks = DataBlocks::encrypt(&SharedKey::new(shared_key.as_bytes().to_vec()), plaintext.into_inner().as_slice().bytes())?;

		Ok(Crypt4GHFile::new(header, data_blocks))
	}

	/// Crypt4gh spec §4.1 - chacha20 ietf poly1305 Decryption
	/// 
	/// 
	/// An authentication tag is calculated over the cipher-text from that segment, and bit-wise compared to the
	/// MAC. The cipher-text is authenticated if and only if the tags match. If more than one key (K_data) was
	/// included in the header, each should be tried in turn until either one authenticates correctly or no keys are
	/// left to try. An error MUST be reported if the cipher-text is not authenticated.
	/// 
	/// The key K_data and nonce N are then used to decrypt the cipher-text for the segment, returning the plain-
	/// text. Successive segments are decrypted, until the segment containing position Q is reached. The plain-text
	/// segments are concatenated to form the resulting output, discarding P % 65536 bytes from the beginning of
	/// the first segment and retaining Q % 65536 bytes of the last one.
	/// 
	/// If more than one key (K_data) is in use, readers can speed up decryption by trying the previous successful
	/// key first when attempting to authenticate each block. However, this does open up a possible timing attack
	/// where an observer watching the decoding process can find out where key changes occur due to the extra
	/// time needed to select the new key at these points. If this is unacceptable, readers could either try each key
	/// for every block (although this may still be vulnerable to timing attacks which try to detect which key was
	/// successful); or simply insist that only one key is used for the whole file.
	/// 
	/// 
	pub fn decrypt(self, c4gh_file: Crypt4GHFile, private_key: PrivateKey) -> Result<PlainText, Crypt4GHError> {
		// The cipher-text is decrypted by authenticating and decrypting the segment(s) enclosing the requested byte
		// range [P ; Q], where P < Q. For a range starting at position P, the location of the segment seg_start
		// containing that position must first be found. For the chacha20 ietf poly1305 method, when no edit list is in
		// use, this can be done using the formula:
		//
		// seg_start = header_len + floor(P/65536) * 65564
	
		// TODO: Tweak calculation for the case of edit lists present... and add floor()
		// let seg_start = c4gh_file.header.len() + self.range.start_bound().into() * PLAINTEXT_SEGMENT_SIZE;

		let mut data_buffer = vec![];
		/// Get the encrypted payload from the header.
		let header_private_key = c4gh_file.header.decrypt_key(private_key)?;
		// For an encrypted segment starting at position seg_start, the nonce, then the 65536 bytes of cipher-text
		// (possibly fewer if it was the last segment), and finally the MAC are read.
		for data_block in c4gh_file.data_blocks.into_iter() {
			let segment = data_block.decrypt(header_private_key.clone())?;

			data_buffer.extend(segment);
		}

		Ok(PlainText::from(data_buffer))
	}
}

pub struct Crypt4GhBuilder {
	keys: KeyPair,
	range: Option<std::ops::Range<usize>>,
	seed: Option<Seed>,
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
			seed: Seed::new(),
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

