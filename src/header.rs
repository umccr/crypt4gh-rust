use serde::{Deserialize, Serialize};

use crate::error::Crypt4GHError;
use crate::keys::{EncryptionMethod, PrivateKey, PublicKey, SessionKeys};
use crate::{construct_encrypted_data_packet, Crypt4Gh, CypherText, Recipients, Seed};

const MAGIC_NUMBER: &[u8; 8] = b"crypt4gh";
const VERSION: u32 = 1;

#[derive(Debug, Serialize)]
pub struct Magic([u8; 8]);

/// Structs below follow crypt4gh spec §2.2
///
/// Header precedes data blocks and is described in crypt4gh spec §3.2 and §2.2 for a high level graphical representation of
/// the file structure.
///
/// TODO: Are those encrypted?
#[derive(Debug, Serialize)]
pub struct Header {
	magic: Magic,
	version: u32,
	count: u32,
	packets: Vec<HeaderPacket>,
}

/// Encodes actual encrypted data from a header packet or an edit list.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum HeaderPacketType {
	DataEnc,
	EditList,
}

#[derive(Debug)]
struct DataEncryptionKeyPacket {
	encryption_method: u32,
	data_encryption_key: Vec<u8>,
}

/// Crypt4gh spec §3.2.4
///
/// TODO: Enforce this on impl:
///
/// It is not permitted to have more than one edit list. If more than one edit list is present, the file SHOULD
/// be rejected.
#[derive(Debug)]
struct EditListPacket {
	number_lengths: u32,
	lengths: Vec<u64>,
}

/// Data-bearing Header Packet data type as it can hold either depending on packet type
#[derive(Debug, Serialize)]
enum HeaderPacketDataType {
	EditListPacket(Vec<u8>),
	DataPacketEncrypted(Vec<u8>),
}

/// Crypt4gh spec §3.2.1
///
/// Conditional settings for writer_public_key/nonce/mac depending on
/// as described in the spec can be selected at runtime
#[derive(Debug, Serialize)]
pub struct HeaderPacket {
	packet_length: u32,
	encryption_method: EncryptionMethod,
	writer_public_key: PublicKey,
	nonce: Vec<u8>,
	encrypted_payload: Vec<u8>,
	mac: Vec<u8>, /* dalek::Mac type might be more fitting
	               * TODO: MAC[16] for chacha20_ietf_poly1305 */
}

/// Crypt4gh spec §3.2.2
#[derive(Debug)]
pub struct EncryptedHeaderPacket {
	packet_type: HeaderPacketType,
	data_key: Vec<u8>, // TODO: data_key[32] on the spec
	// for chacha20_ietf_poly1305
	data_edit_list: EditListPacket,
}

/// Crypt4gh spec §3.2.3
///
/// TODO: Make clear decision on how to enforce this:
///
/// To allow parts of the data to be encrypted with different Kdata keys, more than one of this packet type may
/// be present. If there is more than one, the data encryption method MUST be the same for all of them to
/// prevent problems with random access in the encrypted file.
struct DataEncryptionPacket {
	encryption_method: EncryptionMethod,
	data_key: PrivateKey,
}

/// Implements all header-related operations described in crypt4gh spec §3.2 and onwards
impl Header {
	/// Encrypt just the header
	pub fn encrypt(
		recipients: Recipients,
		session_keys: Option<SessionKeys>,
		seed: Seed,
	) -> Result<CypherText, Crypt4GHError> {
		// Invariant: Starts at position 0, so no >0 range offsets are needed for header itself and this function?
		let header_content = construct_encrypted_data_packet(EncryptionMethod::X25519Chacha20Poly305, session_keys);
		// let header_packets = crate::Crypt4Gh::encrypt(&header_content, recipients, None)?;
		// let header_bytes = serialize_header_packets(header_packets);

		// Ok(CypherText::from(header_bytes))
		todo!()
	}

	/// Get the header packet bytes
	pub fn packets(&self) -> &Vec<HeaderPacket> {
		&self.packets
	}

	/// Get the size of all the packets.
	pub fn len(&self) -> u64 {
		unimplemented!()
	}

	/// Get the inner bytes and size.
	pub fn into_inner(self) -> (Vec<HeaderPacket>, u64) {
		unimplemented!()
	}
}

/// Serializes the header packets.
///
/// Returns [ Magic "crypt4gh" + version + packet count + header packets... ] serialized.
pub fn serialize_header_packets(packets: Vec<Vec<u8>>) -> Vec<u8> {
	// log::info!("Serializing the header packets ({} packets)", packets.len());
	vec![
		MAGIC_NUMBER.to_vec(),
		(VERSION as u32).to_le_bytes().to_vec(),
		(packets.len() as u32).to_le_bytes().to_vec(),
		packets
			.into_iter()
			.flat_map(|packet| vec![((packet.len() + 4) as u32).to_le_bytes().to_vec(), packet].concat())
			.collect::<Vec<u8>>(),
	]
	.concat()
}
