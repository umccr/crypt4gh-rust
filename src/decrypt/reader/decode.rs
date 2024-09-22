use std::io;

use bytes::{Bytes, BytesMut};
use tokio_util::codec::Decoder;

use crate::{error::Crypt4GHError::{
  self, NumericConversionError, SliceConversionError
}, header::HeaderPacket, header::Header};
pub const ENCRYPTED_BLOCK_SIZE: usize = 65536;
pub const NONCE_SIZE: usize = 12; // ChaCha20 IETF Nonce size
pub const MAC_SIZE: usize = 16;

const DATA_BLOCK_SIZE: usize = NONCE_SIZE + ENCRYPTED_BLOCK_SIZE + MAC_SIZE;

const MAGIC_STRING_SIZE: usize = 8;
const VERSION_STRING_SIZE: usize = 4;
const HEADER_PACKET_COUNT_SIZE: usize = 4;

pub const HEADER_INFO_SIZE: usize =
  MAGIC_STRING_SIZE + VERSION_STRING_SIZE + HEADER_PACKET_COUNT_SIZE;

const HEADER_PACKET_LENGTH_SIZE: usize = 4;

/// Maximum header size
/// FIXME: Does this comply with the spec?
const MAX_HEADER_SIZE: usize = 8 * 1024 * 1024;

/// The type that a block is decoded into.
#[derive(Debug)]
pub enum DecodedBlock {
  /// The magic string, version string and header packet count.
  /// Corresponds to `deconstruct_header_info`.
  Header(Header),
  /// Header packets, both data encryption key packets and a data edit list packets.
  /// Corresponds to `deconstruct_header_body`.
  HeaderPackets(HeaderPacket),
  /// The encrypted data blocks
  /// Corresponds to `body_decrypt`.
  DataBlock(Bytes),
}

/// State to keep track of the current block being decoded corresponding to `BlockType`.
#[derive(Debug)]
enum BlockState {
  /// Expecting header info.
  Header,
  /// Expecting header packets and the number of header packets left to decode.
  HeaderPackets(u32),
  /// Expecting a data block.
  DataBlock,
  /// Expecting the end of the file. This is to account for the last data block potentially being
  /// shorter.
  Eof,
}

#[derive(Debug)]
pub struct Block {
  next_block: BlockState,
}

impl Block {
  fn get_header_info(src: &mut BytesMut) -> Result<Header, Crypt4GHError> {
    deserialize_header_info(
      src
        .split_to(HEADER_INFO_SIZE)
        .as_ref()
        .try_into()
        .map_err(|_| SliceConversionError)?,
    )
  }

  /// Parses the header info, updates the state and returns the block type. Unlike the other
  /// `decode` methods, this method parses the header info before returning a decoded block
  /// because the header info contains the number of packets which is required for decoding
  /// the rest of the source.
  pub fn decode_header_info(&mut self, src: &mut BytesMut) -> Result<Option<DecodedBlock>, Crypt4GHError> {
    // Header info is a fixed size.
    if src.len() < HEADER_INFO_SIZE {
      src.reserve(HEADER_INFO_SIZE);
      return Ok(None);
    }

    // Parse the header info because it contains the number of header packets.
    let header_info = Self::get_header_info(src)?;

    self.next_block = BlockState::HeaderPackets(header_info.packets_count);

    Ok(Some(DecodedBlock::Header(header_info)))
  }

  /// Decodes header packets, updates the state and returns a header packet block type.
  pub fn decode_header_packets(
    &mut self,
    src: &mut BytesMut,
    header_packets: u32,
  ) -> Result<Option<DecodedBlock>, Crypt4GHError> {
    let mut header_packet_bytes = vec![];
    for _ in 0..header_packets {
      // Get enough bytes to read the header packet length.
      if src.len() < HEADER_PACKET_LENGTH_SIZE {
        src.reserve(HEADER_PACKET_LENGTH_SIZE);
        return Ok(None);
      }

      // Read the header packet length.
      let length_bytes = src.split_to(HEADER_PACKET_LENGTH_SIZE).freeze();
      let mut length: usize = u32::from_le_bytes(
        length_bytes
          .as_ref()
          .try_into()
          .map_err(|_| SliceConversionError)?,
      )
      .try_into()
      .map_err(|_| NumericConversionError)?;

      // We have already taken 4 bytes out of the length.
      length -= HEADER_PACKET_LENGTH_SIZE;

      // FIXME: Shouldn't those bytes be known at compile time? 
      // Get enough bytes to read the entire header packet.
      if src.len() < length {
        src.reserve(length - src.len());
        return Ok(None);
      }

      header_packet_bytes.push(EncryptedHeaderPacketBytes::new(
        length_bytes,
        src.split_to(length).freeze(),
      ));
    }

    self.next_block = BlockState::DataBlock;

    let header_length = u64::try_from(
      header_packet_bytes
        .iter()
        .map(|packet| packet.packet_length().len() + packet.header().len())
        .sum::<usize>(),
    )
    .map_err(|_| NumericConversionError)?;

    Ok(Some(DecodedBlock::HeaderPackets(
      EncryptedHeaderPackets::new(header_packet_bytes, header_length),
    )))
  }

  /// Decodes data blocks, updates the state and returns a data block type.
  pub fn decode_data_block(&mut self, src: &mut BytesMut) -> Result<Option<DecodedBlock>, Crypt4GHError> {
    // Data blocks are a fixed size, so we can return the
    // next data block without much processing.
    if src.len() < DATA_BLOCK_SIZE {
      src.reserve(DATA_BLOCK_SIZE);
      return Ok(None);
    }

    self.next_block = BlockState::DataBlock;

    Ok(Some(DecodedBlock::DataBlock(
      src.split_to(DATA_BLOCK_SIZE).freeze(),
    )))
  }

  /// Get the standard size of all non-ending data blocks.
  pub const fn standard_data_block_size() -> u64 {
    DATA_BLOCK_SIZE as u64
  }

  /// Get the size of the magic string, version and header packet count.
  pub const fn header_info_size() -> u64 {
    HEADER_INFO_SIZE as u64
  }

  /// Get the encrypted block size, without nonce and mac bytes.
  pub const fn encrypted_block_size() -> u64 {
    ENCRYPTED_BLOCK_SIZE as u64
  }

  /// Get the size of the nonce.
  pub const fn nonce_size() -> u64 {
    NONCE_SIZE as u64
  }

  /// Get the size of the mac.
  pub const fn mac_size() -> u64 {
    MAC_SIZE as u64
  }

  /// Get the maximum possible header size.
  pub const fn max_header_size() -> u64 {
    MAX_HEADER_SIZE as u64
  }
}

impl Default for Block {
  fn default() -> Self {
    Self {
      next_block: BlockState::Header,
    }
  }
}

impl Decoder for Block {
  type Item = DecodedBlock;
  type Error = Crypt4GHError;

  fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Crypt4GHError> {
    match self.next_block {
      BlockState::Header => self.decode_header_info(src),
      BlockState::HeaderPackets(header_packets) => self.decode_header_packets(src, header_packets),
      BlockState::DataBlock => self.decode_data_block(src),
      BlockState::Eof => Ok(None),
    }
  }

  fn decode_eof(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Crypt4GHError> {
    // Need a custom implementation of decode_eof because the last data block can be shorter.
    match self.decode(buf)? {
      Some(frame) => Ok(Some(frame)),
      None => {
        if buf.is_empty() {
          Ok(None)
        } else if let BlockState::DataBlock = self.next_block {
          // The last data block can be smaller than 64KiB.
          if buf.len() <= DATA_BLOCK_SIZE {
            self.next_block = BlockState::Eof;

            Ok(Some(DecodedBlock::DataBlock(buf.split().freeze())))
          } else {
            Err(Crypt4GHError::UnableToDecryptBlock(buf.to_vec(), 
              "the last data block is too large".to_string(),
            ))
          }
        } else {
          Err(io::Error::new(io::ErrorKind::Other, "bytes remaining on stream").into())
        }
      }
    }
  }
}

