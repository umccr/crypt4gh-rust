//! This module handles the general parsing logic.
//!

use std::array::TryFromSliceError;
use std::fmt::Debug;
use std::num::NonZeroUsize;
use std::result;
use thiserror::Error;

pub type Result<T, E> = result::Result<T, Error<E>>;

#[derive(Debug, Error)]
pub enum Error<E> {
	/// More bytes are needed before parsing can continue. The enum value shows the minimum
	/// amount of bytes required.
	#[error("incomplete bytes, need {0}")]
	Incomplete(NonZeroUsize),
	/// An unrecoverable error has been encountered.
	#[error(transparent)]
	Unrecoverable(E),
}

impl<E> Error<E> {
	pub fn map<T: From<E>>(self) -> Error<T> {
		match self {
			Error::Incomplete(needed) => Error::Incomplete(needed),
			Error::Unrecoverable(error) => Error::Unrecoverable(error.into()),
		}
	}
}

impl<E> From<E> for Error<E> {
	fn from(unrecoverable: E) -> Self {
		Self::Unrecoverable(unrecoverable)
	}
}

/// A buffer of data.
pub struct Buf<'a> {
	pos: usize,
	buf: &'a [u8],
}

impl<'a> Buf<'a> {
	pub fn new(buf: &'a [u8]) -> Self {
		Self { buf, pos: 0 }
	}

	fn decode<T, E>(&mut self, size: usize) -> Result<T, E>
	where
		T: TryFrom<&'a [u8]>,
		<T as TryFrom<&'a [u8]>>::Error: Debug,
	{
		let len = self.len();
		if len < size {
			// Always succeed because N is greater than len.
			Err(Error::Incomplete(
				NonZeroUsize::new(size - len).expect("expected valid non-zero usize"),
			))
		} else {
			// Always succeeds because the buffer contains at least N bytes.
			let result = self.buf[self.pos..size].try_into().expect("expected valid array");
			self.pos += size;

			Ok(result)
		}
	}

	/// The remaining length in the buffer.
	pub fn len(&self) -> usize {
		self.buf.len() - self.pos
	}

	/// Reset the position.
	pub fn reset(&mut self) {
		self.pos = 0;
	}

	pub fn parse_u32<E>(&mut self) -> Result<u32, E> {
		Ok(u32::from_le_bytes(self.parse_array()?))
	}

	pub fn parse_array<E, const N: usize>(&mut self) -> Result<[u8; N], E> {
		self.decode(N)
	}

	pub fn parse_slice<E, const N: usize>(&mut self) -> Result<&[u8; N], E> {
		self.decode(N)
	}

	pub fn parse_vec<E>(&mut self, size: usize) -> Result<Vec<u8>, E> {
		self.decode(size)
	}
}
