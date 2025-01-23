use std::collections::HashSet;

use crate::error::Crypt4GHError;
use crate::keys::{DataKey, EncryptionMethod, KeyPair, PublicKey};
use crate::{encrypt_x25519_chacha20_poly1305, CypherText, Mac, Nonce, Recipients};

const MAGIC_NUMBER: &[u8; 8] = b"crypt4gh";
const VERSION: u32 = 1;

#[derive(Debug)]
pub struct Magic([u8; 8]);

/// Structs below follow Crypt4gh spec §2.2 - File Structure as closely as possible.
///
/// Since this file implements header-related functionality, "Header" has been removed from names
/// of the entities (i.e HeaderPacket in the spec becomes Packet here). The only exception is
/// the top level "Header" struct itself.


/// Crypt4gh spec §3.2 - Header
///
/// Header precedes data blocks and is described in crypt4gh spec §3.2 and §2.2 for a high level graphical
/// representation of the file structure.
#[derive(Debug)]
pub struct Header {
	magic: Magic,
	version: u32,
	count: u32,
	packets: Vec<Packet>,
}

/// Crypt4gh spec §3.2.1 - Header Packets
/// (...)
/// Crypt4gh spec §3.3.1 - X25519 ChaCha20 IETF Poly1305 encryption
/// (...)
/// Finally, the packet length, encryption type, writer’s public key Kpw, the nonce N and the
/// encrypted header packet data are combined to make the header packet.
///
/// For extra security, writers MAY choose to discard the writer’s secret key K_sw after use.
/// Due to the symmetry of the Diffie-Hellman algorithm, the holder of either secret key can
/// regenerate the shared key as long as the other public key is known. Deleting the writer’s key
/// K_sw ensures only the holder of the reader’s secret key K_sr can decode the header packet.
/// As long as the writer uses randomly-generated keys, it also makes accidental nonce reuse very unlikely.
#[derive(Debug)]
pub struct Packet {
	length: u32, // Packet length is the length of the entire header packet (including the packet length itself).
				 // To prevent packet types from being guessed by looking at the size, it is permitted for the
				 // packet length to be longer than strictly needed to encode all of the packet data.
				 // Any remaining space after the actual data should be padded in a suitable manner
				 // (for example by setting it to zero) and encrypted.
	encryption_method: EncryptionMethod,
	writer_public_key: PublicKey, // writer_public_key (Kpw) and nonce are parameters needed to decrypt
								  // the encrypted payload in the packet.
	nonce: Nonce,
	encrypted_payload: Vec<u8>, // encrypted payload is the encrypted part of the header packet, the plaintext part is
								// described in §3.2.2
	mac: Mac,
}

/// Crypt4gh spec §3.2.2 - Header packet encrypted payload
///
/// Data-bearing Header Packet data type as it can hold either depending on packet type
#[derive(Debug)]
enum PacketType {
	DataEncryptionParametersPacket(Vec<u8>),
	EditListPacket(Vec<u8>),
}

#[derive(Debug)]
pub enum EncryptedPacketData {
	DataEncryptionParameters(DataEncryptionParametersPacket),
	DataEditList(DataEditListPacket),
}

/// Crypt4gh spec §3.2.3 - Data encryption parameters packet
///
/// To allow parts of the data to be encrypted with different K_data keys, more than one of this packet type may
/// be present. If there is more than one, the data encryption method MUST be the same for all of them to
/// prevent problems with random access in the encrypted file.
#[derive(Debug)]
struct DataEncryptionParametersPacket {
	encryption_method: EncryptionMethod,
	data_key: DataKey,
}

impl DataEncryptionParametersPacket {
	pub fn new(encryption_method: EncryptionMethod, data_key: DataKey) -> Self {
		Self {
			encryption_method,
			data_key,
		}
	}
}

/// Crypt4gh spec §3.2.4 - Data edit list packet
///
/// This packet contains a list of edits that should be applied to the plain-text data following decryption.
///
/// It is not permitted to have more than one edit list. If more than one edit list is present, the file SHOULD
/// be rejected.
#[derive(Debug)]
struct DataEditListPacket {
	number_lengths: usize,  // The number of items in the lengths array.
	lengths: Vec<u64>,		// An array of byte counts.
}

/// Implements all header-related operations described in Crypt4gh spec §3.3 - Header packet encryption
impl Header {
	/// Crypt4gh spec §3.3.1 - X25519 ChaCha20 IETF Poly1305 Encryption
	///
	/// This method uses Elliptic Curve Diffie-Hellman key exchange with additional hashing to generate
	/// a shared key (K_shared). K_shared is then used along with a randomly-generated nonce to encrypt
	/// the header packet data using the ChaCha20-IETF-Poly1305 construction. The elliptic curve algorithm
	/// used is X25519, described in section 5 of [RFC7748].
	/// (...)
	/// The header packet type, data and any padding is then encrypted using the method described in the
	/// chacha20 ietf poly1305 Encryption section 3.4.1. Note that header packets are not segmented; they are
	/// always encrypted in a single block.
	pub fn encrypt(
		recipients: Recipients,
		data_key: DataKey,
	) -> Result<CypherText, Crypt4GHError> {

		// Build header packet
		let header_packet = EncryptedPacketData::DataEncryptionParameters(
			DataEncryptionParametersPacket::new(EncryptionMethod::X25519Chacha20Poly305, data_key)
		);

		// Encrypt it
		let encrypted_header_packet  = encrypt_packet(header_packet, );

		// Invariant: Starts at position 0, so no >0 range offsets are needed for header itself and this function?
		// let header_content = construct_encrypted_data_packet(EncryptionMethod::X25519Chacha20Poly305, shared_keys);
		// Packs HeaderPacketType::DataEnc twice with different representations?

		// let header_packets = crate::Crypt4Gh::encrypt(&header_content, recipients, None)?;
		// let header_bytes = serialize_header_packets(header_packets);

		// Ok(CypherText::from(header_bytes))
		Ok(encrypted_header_packet)
	}

	/// Get the header packet bytes
	pub fn packets(&self) -> &Vec<Packet> {
		&self.packets
	}

	/// Get the size of all the packets.
	pub fn len(&self) -> u64 {
		unimplemented!()
	}

	/// Get the inner bytes and size.
	pub fn into_inner(self) -> (Vec<Packet>, u64) {
		unimplemented!()
	}

	/// Computes the encrypted header part for each key in the given collection
	///
	/// Given a set of keys and a vector of bytes representing a packet, this function iterates over the keys and encrypts the packet using the x25519_chacha20_poly1305 encryption method.
	/// It returns a vector of encrypted segments, where each segment represents the encrypted packet for a specific key.
	///
	/// * `packet` - A vector of bytes representing the packet to be encrypted
	/// * `keys` - A collection of keypairs with `key.method` equal to 0
	fn encrypt_packet(packet: DataEncryptionParametersPacket, keypairs: &HashSet<KeyPair>) -> Result<Vec<Vec<u8>>, Crypt4GHError> {
		keypairs.iter()
			.filter(|key| key.method == EncryptionMethod::X25519Chacha20Poly305)
			.map(
				|key| match encrypt_x25519_chacha20_poly1305(packet, key.private_key.clone(), key.public_keys.clone()) {
					Ok(session_key) => Ok(vec![u32::from(key.method as u32).to_le_bytes().to_vec(), session_key].concat()),
					Err(e) => Err(e),
				},
			)
			.collect()
	}
}

// /// Serializes the header packets.
// ///
// /// Returns [ Magic "crypt4gh" + version + packet count + header packets... ] serialized.
// pub fn serialize_header_packets(packets: Vec<Vec<u8>>) -> Vec<u8> {
// 	// log::info!("Serializing the header packets ({} packets)", packets.len());
// 	vec![
// 		MAGIC_NUMBER.to_vec(),
// 		(VERSION as u32).to_le_bytes().to_vec(),
// 		(packets.len() as u32).to_le_bytes().to_vec(),
// 		packets
// 			.into_iter()
// 			.flat_map(|packet| vec![((packet.len() + 4) as u32).to_le_bytes().to_vec(), packet].concat())
// 			.collect::<Vec<u8>>(),
// 	]
// 	.concat()
// }
