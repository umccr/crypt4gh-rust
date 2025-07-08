use std::array::TryFromSliceError;
use std::result;
use chacha20poly1305::aead;
use thiserror::Error;

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid encryption method: {0}")]
    InvalidEncryptionMethod(u32),
}

impl Error {
    pub fn invalid_encryption_method(invalid_encryption_method: u32) -> Self {
        Self::InvalidEncryptionMethod(invalid_encryption_method)
    }
}