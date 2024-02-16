use std::cmp::min;

use crate::decoder::Block;
use crate::error::Crypt4GHError;
use crate::keys::{KeyPair, PublicKey};

fn to_current_data_block(pos: u64, header_len: u64) -> u64 {
  header_len + (pos / Block::encrypted_block_size()) * Block::standard_data_block_size()
}

/// Convert an unencrypted file position to an encrypted position if the header length is known.
pub fn to_encrypted(position: u64, header_length: u64) -> u64 {
  let number_data_blocks = position / Block::encrypted_block_size();
  // Additional bytes include the full data block size.
  let mut additional_bytes = number_data_blocks * (Block::nonce_size() + Block::mac_size());

  // If there is left over data, then there are more nonce bytes.
  let remainder = position % Block::encrypted_block_size();
  if remainder != 0 {
    additional_bytes += Block::nonce_size();
  }

  // Then add the extra bytes to the current position.
  header_length + position + additional_bytes
}

/// Convert an encrypted file position to an unencrypted position if the header length is known.
pub fn to_unencrypted(encrypted_position: u64, header_length: u64) -> u64 {
  let number_data_blocks = encrypted_position / Block::standard_data_block_size();
  let mut additional_bytes = number_data_blocks * (Block::nonce_size() + Block::mac_size());

  let remainder = encrypted_position % Block::standard_data_block_size();
  if remainder != 0 {
    additional_bytes += Block::nonce_size();
  }

  encrypted_position - header_length - additional_bytes
}

/// Convert an unencrypted file size to an encrypted file size if the header length is known.
pub fn to_encrypted_file_size(file_size: u64, header_length: u64) -> u64 {
  to_encrypted(file_size, header_length) + Block::mac_size()
}

/// Convert an encrypted file size to an unencrypted file size if the header length is known.
pub fn to_unencrypted_file_size(encrypted_file_size: u64, header_length: u64) -> u64 {
  to_unencrypted(encrypted_file_size, header_length) - Block::mac_size()
}

/// Convert an unencrypted position to an encrypted position as shown in
/// https://samtools.github.io/hts-specs/crypt4gh.pdf chapter 4.1.
pub fn unencrypted_to_data_block(pos: u64, header_len: u64, encrypted_file_size: u64) -> u64 {
  min(encrypted_file_size, to_current_data_block(pos, header_len))
}

/// Get the next data block position from the unencrypted position.
pub fn unencrypted_to_next_data_block(pos: u64, header_len: u64, encrypted_file_size: u64) -> u64 {
  min(
    encrypted_file_size,
    to_current_data_block(pos, header_len) + Block::standard_data_block_size(),
  )
}

fn unencrypted_clamped_position(pos: u64, encrypted_file_size: u64) -> u64 {
  let data_block_positions = unencrypted_to_data_block(pos, 0, encrypted_file_size);
  let data_block_count = data_block_positions / Block::standard_data_block_size();

  data_block_positions - ((Block::nonce_size() + Block::mac_size()) * data_block_count)
}

/// Convert an unencrypted position to the additional bytes prior to the position that must be
/// included when encrypting data blocks.
pub fn unencrypted_clamp(pos: u64, encrypted_file_size: u64) -> u64 {
  min(
    to_unencrypted_file_size(encrypted_file_size, 0),
    unencrypted_clamped_position(pos, encrypted_file_size),
  )
}

/// Convert an unencrypted position to the additional bytes after to the position that must be
/// included when encrypting data blocks.
pub fn unencrypted_clamp_next(pos: u64, encrypted_file_size: u64) -> u64 {
  min(
    to_unencrypted_file_size(encrypted_file_size, 0),
    unencrypted_clamped_position(pos, encrypted_file_size) + Block::encrypted_block_size(),
  )
}

