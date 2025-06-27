//! Error types for encryption/decryption.
//!

use std::result;
use chacha20poly1305::aead;
use thiserror::Error;

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("decryption error: {0}")]
    DecryptionError(aead::Error),
    #[error("encryption error: {0}")]
    EncryptionError(aead::Error),
    #[error("error parsing header: {0}")]
    HeaderParseError(String),
    #[error("io error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("error decoding header: {0}")]
    HeaderDecodeError(String)
}