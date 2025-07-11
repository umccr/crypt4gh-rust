//! Encryption and decryption related functionality.
//!

pub mod error;

use crate::v2::error::Error::{DecryptionError, EncryptionError};
pub(crate) use crate::v2::error::{Error, Result};
use crate::v2::parsing;
use crate::v2::parsing::Buf;
use chacha20poly1305::aead::OsRng;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::consts::U32;
use chacha20poly1305::{AeadCore, AeadInPlace, ChaCha20Poly1305, KeyInit};

/// Crypt4gh spec §3.4.1 - Chacha20 IETF Poly1305 encryption
///
/// (...) Poly1305 is used to generate a 16-byte message authentication code (MAC) over the cipher-text.
pub const MAC_LENGTH: usize = 16;

/// (...) In IETF mode the nonce is 96 bits long.
pub const NONCE_LENGTH: usize = 12;

/// Represented an encrypted data segment with the nonce and mac. This is used in two places, as the `DataBlock` in the
/// C4GH spec, and the `Nonce` + `Encrypted Packet Data` + `Mac` in the header. It's not strictly part of the Crypt4GH
/// spec but it represents a component of data that can be decrypted or encrypted, meaning that this functionality
/// doesn't have to be defined in multiple places.
#[derive(Debug)]
pub struct EncryptedData<const N: usize = 0> {
	pub nonce: [u8; NONCE_LENGTH],
	pub data: FixedOrDynamicArray<N>,
	pub mac: [u8; MAC_LENGTH],
}

impl<const N: usize> EncryptedData<N> {
	/// Decrypt the data using ChaCha20Poly1305 AEAD. This is effectively like an `into_inner` function,
	/// as it decrypts the data and returns the bytes.
	pub fn decrypt(mut self, key: &[u8]) -> Result<FixedOrDynamicArray<N>> {
		let decrypt = ChaCha20Poly1305::new(GenericArray::<u8, U32>::from_slice(key));

		decrypt
			.decrypt_in_place_detached(
				&GenericArray::from(self.nonce),
				&[],
				self.data.as_mut_slice(),
				&GenericArray::from(self.mac),
			)
			.map_err(|err| DecryptionError(err))?;

		Ok(self.data)
	}

	/// Encrypt the data with the key using ChaCha20Poly1305 AEAD. This is effectively like a `new`
	/// function, as it creates an `EncryptedData` struct.
	pub fn encrypt(key: &[u8], mut data: FixedOrDynamicArray<N>) -> Result<EncryptedData<N>> {
		let encrypt = ChaCha20Poly1305::new(GenericArray::<u8, U32>::from_slice(key));

		let nonce = ChaCha20Poly1305::generate_nonce(OsRng);
		let mac = encrypt
			.encrypt_in_place_detached(&nonce, &[], data.as_mut_slice())
			.map_err(|err| EncryptionError(err))?;

		Ok(EncryptedData {
			nonce: nonce.into(),
			data,
			mac: mac.into(),
		})
	}

	pub fn to_bytes(&self) -> Vec<u8> {
		todo!()
	}
}

impl EncryptedData {
	pub fn parse_with_size(buf: &mut Buf, size: usize) -> parsing::Result<Self, Error> {
		Ok(Self {
			nonce: buf.parse_array()?,
			data: FixedOrDynamicArray::new_dynamic(buf.parse_vec(size)?),
			mac: buf.parse_array()?,
		})
	}
}

/// A fixed or dynamic array type. This is useful for fixed length data like the data block length,
/// and variable length data like the header packet data.
#[derive(Debug)]
pub enum FixedOrDynamicArray<const N: usize = 0> {
	Fixed([u8; N]),
	Dynamic(Vec<u8>),
}

impl<const N: usize> FixedOrDynamicArray<N> {
	pub fn new_fixed(buf: [u8; N]) -> Self {
		Self::Fixed(buf)
	}

	pub fn new_dynamic(buf: Vec<u8>) -> Self {
		Self::Dynamic(buf)
	}

	/// Get a mutable slice to the data.
	pub fn as_mut_slice(&mut self) -> &mut [u8] {
		match self {
			FixedOrDynamicArray::Fixed(data) => data.as_mut_slice(),
			FixedOrDynamicArray::Dynamic(data) => data.as_mut_slice(),
		}
	}

	pub fn as_slice(&self) -> &[u8] {
		match self {
			FixedOrDynamicArray::Fixed(data) => data.as_slice(),
			FixedOrDynamicArray::Dynamic(data) => data.as_slice(),
		}
	}

	pub fn to_bytes(&self) -> Vec<u8> {
		todo!()
	}
}
