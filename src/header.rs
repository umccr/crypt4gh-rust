
use std::mem;
use crate::error::Crypt4GHError;
use crate::keys::{self, DataKey, EncryptionMethod, KeyPair, PublicKey, ENCRYPTION_METHOD_SIZE};

use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::AeadMutInPlace;
use chacha20poly1305::consts::U32;
// use chacha20poly1305::{AeadCore, KeyInit, ChaCha20Poly1305, aead::rand::StdRng, aead::rand::SeedableRng};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce
};

use crate::{Mac, Recipients, MAC_LENGTH};

const MAGIC_NUMBER: &[u8; 8] = b"crypt4gh";
const VERSION: u32 = 1;

#[derive(Debug)]
pub struct Magic([u8; 8]);

/// Structs below follow Crypt4gh spec §2.2 - File Structure, as closely as possible.
///
/// Since this file implements header-related functionality, "Header" has been removed from names
/// of the entities (i.e "HeaderPacket" named in the spec becomes "Packet" here). The only exception is
/// the top level "Header" struct itself.

// TODO: Rethink struct naming
pub struct HeaderWithKeys {
	header: Header,
	data_keys: Vec<DataKey>,
}

impl HeaderWithKeys {
	pub fn new(header: Header, data_keys: Vec<DataKey>) -> Self {
		Self {
			header,
			data_keys,
		}
	}

	// TODO: Rethink naming, this is a public API
	pub fn from_keypair(
		recipients: Recipients,
		key_pair: KeyPair,
	) -> Result<Self, Crypt4GHError> {
		let (header, keys) = Header::from_keypair(recipients, key_pair)?;
		Ok(Self::new(header, keys))
	}

	pub fn into_inner(self) -> (Header, Vec<DataKey>) {
		(self.header, self.data_keys)
	}

	pub fn header(&self) -> &Header {
		&self.header
	}

	pub fn header_mut(&mut self) -> &mut Header {
		&mut self.header
	}

	pub fn data_keys(&self) -> &[DataKey] {
		&self.data_keys
	}

	pub fn data_keys_mut(&mut self) -> &mut [DataKey] {
		&mut self.data_keys
	}
}

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
/// Finally, the packet length, encryption type, writer’s public key K_pw, the nonce N and the
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
	writer_public_key: PublicKey, // writer_public_key (K_pw) and nonce are parameters needed to decrypt
								  // the encrypted payload in the packet.
	nonce: Nonce,
	encrypted_payload: Vec<u8>, // encrypted payload is the encrypted part of the header packet, the plaintext part is
											// described in §3.2.2
	mac: Mac,
}

impl Packet {
	pub fn new(
		length: u32,
		encryption_method: EncryptionMethod,
		writer_public_key: PublicKey,
		nonce: Nonce,
		encrypted_payload: Vec<u8>,
		mac: Mac,
	) -> Self {
		Self {
			length,
			encryption_method,
			writer_public_key,
			nonce,
			encrypted_payload,
			mac,
		}
	}
}

/// Crypt4gh spec §2.3 - Header Packet Types
///
/// There are two types of header packet:
#[derive(Debug)]
enum PacketType {
	DataEncryptionParameters,	// Data encryption key packets.
								//
								// These describe the parameters used to encrypt one or more of the data blocks.
								// They contain a code indicating the type of encryption, and the symmetric key (K_data)
								// needed to decrypt the data. If parts of the data have been encrypted with different keys,
								// more than one of this packet type will be present.

	EditList,					// Data edit list packets.
								//
								// These packets allow parts of the data to be discarded after decryption. They can be used
								// to avoid having to decrypt and re-encrypt files during splicing operations.
								// For example, a user may want to extract the blocks corresponding to Chromosome X from a CRAM
								// file and store them in a new file. If the start and end points of the extract do not
								// correspond to a 64Kbyte data block boundary, they would normally have to decrypt all
								// of the data blocks covering the region, discard a few bytes from the start and end,
								// re-encrypt the remaining data and store it in a new file.
								//
								// The data edit list enables a simpler solution where the necessary encrypted data blocks are copied
								// directly into the new file. On reading, the data blocks are decrypted and then the edit list is used to
								// find out which parts of the unencrypted data should be discarded.
}

impl PacketType {
	/// Convert the enum to bytes.
	pub fn to_bytes(self) -> [u8; 4] {
		(self as u32).to_le_bytes()
	}
}

/// Crypt4gh spec §3.2.3 - Data encryption parameters packet
///
/// To allow parts of the data to be encrypted with different K_data keys, more than one of this packet type may
/// be present. If there is more than one, the data encryption method MUST be the same for all of them to
/// prevent problems with random access in the encrypted file.
#[derive(Debug)]
pub struct EncryptedPacketData {
	packet_type: PacketType,
	encryption_method: EncryptionMethod,
	data_key: DataKey,
}

impl EncryptedPacketData {
	pub fn new(packet_type: PacketType, encryption_method: EncryptionMethod, data_key: DataKey) -> Self {
		Self {
			packet_type: packet_type,
			encryption_method,
			data_key,
		}
	}

	/// Concat the struct fields into bytes to be encrypted.
	pub fn to_bytes(self) -> Vec<u8> {
		[self.packet_type.to_bytes().as_slice(), self.encryption_method.to_bytes().as_slice(), self.data_key.as_slice()].concat()
	}
}

/// Crypt4gh spec §3.2.4 - Data edit list packet
///
/// This packet contains a list of edits that should be applied to the plain-text data following decryption.
///
/// It is not permitted to have more than one edit list. If more than one edit list is present, the file SHOULD
/// be rejected.
#[derive(Debug)]
struct EditListPacket {
	number_lengths: usize,  // The number of items in the lengths array.
	lengths: Vec<u64>,		// An array of byte counts.
}

/// Implements all header-related operations described in Crypt4gh spec §3.3 - Header packet encryption
impl Header {
	pub fn new(packets: Vec<Packet>) -> Self {
		Self {
			magic: Magic(*MAGIC_NUMBER),
			version: VERSION,
			count: packets.len() as u32,
			packets,
		}
	}

	// TODO: Rethink naming, this is a public API
	pub fn from_keypair(
		recipients: Recipients,
		key_pair: KeyPair,
	) -> Result<(Self, Vec<DataKey>), Crypt4GHError> {
		let packets = Self::encrypt(recipients, key_pair)?;
		let (packets, data_keys) = packets.into_iter().unzip();
		Ok((Self::new(packets), data_keys))
	}

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
		key_pair: KeyPair,
	) -> Result<Vec<(Packet, DataKey)>, Crypt4GHError> {
		let mut header_packets = vec![];

		for reader_public_key in recipients.into_inner().into_iter() {
			// Build header packet
			let header_packet = EncryptedPacketData::new(PacketType::DataEncryptionParameters,
																			EncryptionMethod::X25519Chacha20Poly305,
																			DataKey::generate()
														);

			let data_key = header_packet.data_key.clone();												
			// Encrypt it
			let header_packet_bytes = header_packet.to_bytes();
			let (nonce, encrypted_payload, mac) = Self::encrypt_packet(header_packet_bytes, key_pair.clone(), reader_public_key)?;
			let writer_public_key = key_pair.clone().private_key.get_public_key()?;

			let length = size_of::<u32>() + ENCRYPTION_METHOD_SIZE + writer_public_key.as_slice().len() + nonce.len() + encrypted_payload.len() + MAC_LENGTH;															

			let packet = Packet {
				length: length as u32,
				encryption_method: EncryptionMethod::X25519Chacha20Poly305,
				writer_public_key,
				nonce,
				encrypted_payload,
				mac,
			};

			header_packets.push((packet, data_key));
		}
		

		// Invariant: Starts at position 0, so no >0 range offsets are needed for header itself and this function?
		// let header_content = construct_encrypted_data_packet(EncryptionMethod::X25519Chacha20Poly305, shared_keys);
		// Packs HeaderPacketType::DataEnc twice with different representations?

		// let header_packets = crate::Crypt4Gh::encrypt(&header_content, recipients, None)?;
		// let header_bytes = serialize_header_packets(header_packets);

		// Ok(CipherText::from(header_bytes))
		Ok(header_packets)
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

	/// Convert the header to bytes.
	pub fn to_bytes(self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(
			MAGIC_NUMBER.len() + mem::size_of::<u32>() + mem::size_of::<u32>() + self.packets.iter().map(|p| p.length as usize).sum::<usize>()
		);
		bytes.extend_from_slice(&self.magic.0);
		bytes.extend_from_slice(&self.version.to_le_bytes());
		bytes.extend_from_slice(&self.count.to_le_bytes());
		for packet in &self.packets {
			bytes.extend_from_slice(&packet.length.to_le_bytes());
			bytes.extend_from_slice(&packet.encryption_method.to_bytes());
			bytes.extend_from_slice(packet.writer_public_key.as_slice());
			bytes.extend_from_slice(packet.nonce.as_slice());
			bytes.extend_from_slice(&packet.encrypted_payload);
			bytes.extend_from_slice(packet.mac.as_slice());
		}
		
		bytes
	}

	/// Crypt4gh spec §3.3.1 - X25519 ChaCha20 IETF Poly1305 Encryption
	/// (...)
	/// Encryption requires the writer’s public and secret keys (K_pw and K_sw), the reader’s public key (K_pr) and a nonce (N).
	/// (...)
	/// Crypt4GH spec §2.4 - Encoding For Multiple Public/Secret Key Pairs
	/// 
	/// It is sometimes useful to encrypt files so that they can be accessed using more than one secret key (K_sr).
	/// For example, multiple members of a team may need to access to a file with their own key.
	/// To allow this, the header packet data is encrypted using each reader’s public key (K_pr) and stored in a
	/// separate header packet for each individual reader.
	/// 
	/// [^ This is implemented by our Keypair and Recipients types below ]
	///
	/// Where this is done, it is likely that anyone reading the file will only have the correct secret key (K_sr) for a
	/// subset of the header packets. Attempting to decode a header packet with the wrong key will result in a failure
	/// to verify the MAC stored in the file. When this happens, implementations should ignore the undecodable
	/// header packet and move on to the next one. Failing to decrypt a packet in this way SHOULD NOT cause
	/// an error to be reported; however an error MUST be raised if, on reaching the end of the header, it has not
	/// been possible to decrypt at least one data encryption key packet.
	fn encrypt_packet(packet: Vec<u8>, key_pair: KeyPair, reader_public_key: PublicKey) -> Result<(Nonce, Vec<u8>, Mac), Crypt4GHError> {
		let writer_private_key: &[u8] = key_pair.private_key.as_slice();

		let slice: [u8; keys::DATA_KEY_LENGTH] = writer_private_key.try_into().map_err(|_| Crypt4GHError::BadKey)?;
		let kx_key_pair = crypto_kx::Keypair::from(crypto_kx::SecretKey::from(slice));

		let slice: [u8; keys::DATA_KEY_LENGTH] = reader_public_key.as_slice().try_into().map_err(|_| Crypt4GHError::BadKey)?;
		let kx_public_key = crypto_kx::PublicKey::from(slice);
		
		let key_shared = kx_key_pair.session_keys_from(&kx_public_key);

		let shared_key = GenericArray::<u8, U32>::from_slice(&key_shared.rx.as_ref().as_slice());
		let nonce = ChaCha20Poly1305::generate_nonce(OsRng);
		let mut encrypt = ChaCha20Poly1305::new(shared_key);

		let mut buffer = Vec::with_capacity(packet.len());
        buffer.extend_from_slice(&packet);
		
		let mac = encrypt.encrypt_in_place_detached(&nonce, &[], &mut buffer).map_err(|_| Crypt4GHError::NoSupportedEncryptionMethod)?;
		let mac = Mac::from(mac.to_vec());

		Ok((nonce, encrypt
			.encrypt(&nonce, packet.as_ref())
			.map_err(|err| Crypt4GHError::UnableToEncryptPacket(err.to_string()))?, mac))


		// let mut encrypted_packets = vec![];
		// for reader_public_key in recipients.into_inner().into_iter() {
		// 	// writer_private_key
		// 	// writer_public_key
		// 	// reader_public_key

		// 	// key_diffie = X25519(writer_private_key, reader_public_key)
		// 	// key_shared = Blake2b(key_diffie || key_diffie || writer_public_key)

		// 	let writer_private_key: &[u8] = key_pair.private_key.as_slice();
		// 	let kx_key_pair = crypto_kx::Keypair::from(crypto_kx::SecretKey::from(writer_private_key.try_into().map_err(|err| Crypt4GHError::BadKey)?));
		// 	let key_shared = kx_key_pair.session_keys_from(&crypto_kx::PublicKey::from(reader_public_key.as_slice().try_into().map_err(|err| Crypt4GHError::BadKey)?));


		// 	let shared_key = GenericArray::<u8, U32>::from_slice(&key_shared.rx.as_ref().as_slice());
		// 	let nonce = ChaCha20Poly1305::generate_nonce(OsRng);
		// 	let encrypt = ChaCha20Poly1305::new(shared_key);
		// 	let ciphertext = encrypt
		// 		.encrypt(&nonce, packet.as_ref())
		// 		.map_err(|err| Crypt4GHError::UnableToEncryptPacket(err.to_string()))?;
		
		// 	encrypted_packets.push(cip);	
		// 	Ok(vec![server_pk.as_ref(), nonce.as_slice(), ciphertext.as_slice()].concat())
		// }

		// keypairs.iter()
		// 	.filter(|key| key.method == EncryptionMethod::X25519Chacha20Poly305)
		// 	.map(
		// 		|key| match encrypt_x25519_chacha20_poly1305(packet, key.private_key.clone(), key.public_keys.clone()) {
		// 			Ok(session_key) => Ok(vec![u32::from(key.method as u32).to_le_bytes().to_vec(), session_key].concat()),
		// 			Err(e) => Err(e),
		// 		},
		// 	)
		// 	.collect()
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
