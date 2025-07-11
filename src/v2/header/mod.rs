//! Defines the header components of the Crypt4GH spec.
//!

mod error;
pub mod packet;

use crate::v2::error::Error::HeaderDecodeError;
use crate::v2::error::Result;
use crate::v2::header::packet::{DecryptedPacket, Packet};
use std::array::TryFromSliceError;

const MAGIC_NUMBER_LENGTH: usize = 8;
const MAGIC_NUMBER: &[u8; MAGIC_NUMBER_LENGTH] = b"crypt4gh";
const VERSION: u32 = 1;

/// Crypt4gh spec §3.2 - Header
///
/// Header precedes data blocks and is described in crypt4gh spec §3.2 and §2.2 for a high level graphical
/// representation of the file structure.
#[derive(Debug)]
pub struct Header {
	pub magic: [u8; MAGIC_NUMBER_LENGTH],
	pub version: u32,
	pub count: u32,
	pub packets: Vec<Packet>,
}

impl Header {
	pub fn parse(buf: &[u8]) -> Result<Self> {
		todo!()
	}

	pub fn to_bytes(&self) -> Vec<u8> {
		todo!()
	}

	pub fn decode(buf: &[u8]) -> Result<Option<u32>> {
		let mut packet_pos = (MAGIC_NUMBER_LENGTH + size_of::<u32>() + size_of::<u32>()) as u32;
		// Need to read more bytes first, not enough to reach the first packet.
		if buf.len() < packet_pos as usize {
			return Ok(None);
		}

		let count = u32::from_le_bytes(
			buf[MAGIC_NUMBER_LENGTH + size_of::<u32>()..size_of::<u32>()]
				.try_into()
				.map_err(|err: TryFromSliceError| HeaderDecodeError(err.to_string()))?,
		);

		for _ in 0..count {
			// match Packet::decode(&buf[packet_pos as usize..])? {
			//     Some(amount) => packet_pos += amount,
			//     // More data needed.
			//     None => return Ok(None)
			// }
		}

		Ok(Some(packet_pos))
	}

	// /// Decrypt the header using the key.
	// pub fn decrypt(mut self, key: &[u8]) -> Result<Vec<DecryptedPacket>> {
	//     self.packets.into_iter().map(|packet| packet.decrypt(key)).collect()
	// }
}
