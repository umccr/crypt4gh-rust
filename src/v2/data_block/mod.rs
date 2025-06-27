//! Functionality related to data blocks.
//!

use crate::v2::crypt::EncryptedData;

pub const DATA_BLOCK_SIZE: usize = 65536;

pub struct DataBlock(EncryptedData<DATA_BLOCK_SIZE>);