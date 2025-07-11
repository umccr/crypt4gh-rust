use std::num::TryFromIntError;
use std::result;
use thiserror::Error;

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
	#[error("error converting from int: {0}")]
	IntConversionError(#[from] TryFromIntError),
	#[error("error parsing encrypted header data: {0}")]
	EncryptedDataError(String),
}
