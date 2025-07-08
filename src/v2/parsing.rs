//! This module handles the general parsing logic.
//!

use std::array::TryFromSliceError;
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
    Unrecoverable(E)
}

impl<E> From<E> for Error<E> {
    fn from(unrecoverable: E) -> Self {
        Self::Unrecoverable(unrecoverable)
    }
}

/// A buffer of data.
pub struct Buf<'a> {
    buf: &'a [u8],
}

impl<'a> Buf<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    pub fn decode<E, const N: usize>(&self) -> Result<&[u8; N], E> {
        let len = self.buf.len();
        if len < N {
            // Always succeed because N is greater than len.
            Err(Error::Incomplete(NonZeroUsize::new(N - len).expect("expected valid non-zero usize")))
        } else {
            // Always succeeds because the buffer contains at least N bytes.
            Ok(self.buf[..N].try_into().expect("expected valid array"))
        }
    }

    pub fn parse_u32<E>(&self) -> Result<u32, E> {
        Ok(u32::from_le_bytes(*self.decode()?))
    }
}