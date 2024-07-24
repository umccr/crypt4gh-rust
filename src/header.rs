use std::collections::HashSet;
use std::io::Read;
use bytes::Bytes;

use aead::consts::U32;
use aead::generic_array::GenericArray;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::aead::OsRng;
use chacha20poly1305::Nonce;
use chacha20poly1305::{self, aead, ChaCha20Poly1305, KeyInit, AeadCore};
use crypto_kx::{SecretKey, Keypair};

use serde::{Deserialize, Serialize};

use crate::decrypt;
use crate::encrypt;
use crate::encrypt::encrypted_data::SEGMENT_SIZE;
use crate::encrypt::header;
use crate::error::Crypt4GHError;
use crate::keys;
use crate::keys::EncryptionMethod;
use crate::keys::KeyPair;
use crate::keys::KeyPairInfo;
use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::keys::SessionKeys;

const MAGIC_NUMBER: &[u8; 8] = b"crypt4gh";
const VERSION: u32 = 1;

pub struct Magic([u8; 8]);

/// Structs below follow crypt4gh spec §2.2
/// 
/// Header precedes data blocks and is described in crypt4gh spec §3.2 and §2.2 for a high level graphical representation of
/// the file structure. 
#[derive(Debug)]
pub struct Header {
	magic: Magic,
	version: u32,
	count: u32,
	packets: Vec<HeaderPacket>
}

/// Encodes actual encrypted data from a header packet or an edit list. 
#[derive(Debug, Serialize, Deserialize, PartialEq)]
enum HeaderPacketType {
	DataEnc,
	EditList
}

#[derive(Debug)]
struct DataEncryptionKeyPacket {
	encryption_method: u32,
	data_encryption_key: Vec<u8>
}

/// Crypt4gh spec §3.2.4
/// 
/// TODO: Enforce this:
/// 
/// It is not permitted to have more than one edit list. If more than one edit list is present, the file SHOULD
/// be rejected.
struct EditListPacket {
	number_lengths: u32,
	lengths: Vec<u64>
}

/// Data-bearing Header Packet data type as it can hold either depending on packet type
#[derive(Debug)]
enum HeaderPacketDataType {
	EditListPacket(Vec<u8>),
	DataPacketEncrypted(Vec<u8>),
}

/// Crypt4gh spec §3.2.1
/// 
/// Conditional settings for writer_public_key/nonce/mac depending on
/// as described in the spec can be selected at runtime
#[derive(Debug)]
pub struct HeaderPacket {
	packet_length: u32,
	encryption_method: EncryptionMethod, 
	writer_public_key: PublicKey,
	nonce: Nonce,
	encrypted_payload: Bytes,
	mac: Bytes //dalek::Mac type might be more fitting
			   // TODO: MAC[16] for chacha20_ietf_poly1305
}

/// Crypt4gh spec §3.2.2
#[derive(Debug)]
pub struct EncryptedHeaderPacket {
	packet_type: HeaderPacketType,
	data_key: Bytes, // TODO: data_key[32] on the spec
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


/// FIXME: (MOVED from packets.rs) This should be probably moved to header.rs along with header as it only concerns Header ops?
/// Since packets are not data blocks I think that for clarity it does not deserve its own file, but
/// belongs to header.rs instead.

/// A struct which will poll a decrypter stream until the session keys are found.
/// After polling the future, the underlying decrypter stream should have processed
/// the session keys.
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct SessionKeysFuture<'a, R> {
  handle: &'a mut DecryptStream<R>,
}

impl<'a, R> SessionKeysFuture<'a, R> {
  /// Create the future.
  pub fn new(handle: &'a mut DecryptStream<R>) -> Self {
    Self { handle }
  }

  /// Get the inner handle.
  pub fn get_mut(&mut self) -> &mut DecryptStream<R> {
    self.handle
  }
}

impl<'a, R> Future for SessionKeysFuture<'a, R>
where
  R: AsyncRead + Unpin,
{
  type Output = Result<(), Crypt4GHError>;

  fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    self.handle.poll_session_keys_unpin(cx)
  }
}

impl HeaderPacketsDecrypter {
	pub fn new(
	  header_packets: Vec<Bytes>,
	  keys: Vec<KeyPairInfo>,
	  sender_pubkey: Option<PublicKey>,
	) -> Self {
	  Self {
		handle: spawn_blocking(|| {
		  HeaderPacketsDecrypter::decrypt(header_packets, keys, sender_pubkey)
		}),
	  }
	}
  
	pub fn decrypt(
	  header_packets: Vec<Bytes>,
	  keys: Vec<KeyPairInfo>,
	  sender_pubkey: Option<PublicKey>,
	) -> Result<Header, Crypt4GHError> {
	  let header = Header::new_from_bytes(header_packets.as_slice());
  
	  Ok(header.deserialize(
		header_packets
		  .into_iter()
		  .map(|bytes| bytes.to_vec())
		  .collect(),
		keys.as_slice(),
		&sender_pubkey.map(|pubkey| pubkey.into_inner())
	  ))
	}
  }
  
  impl Future for HeaderPacketsDecrypter {
	type Output = Result<Header, Crypt4GHError>;
  
	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
	  self.project().handle.poll(cx).map_err(JoinHandleError)?
	}
  }

/// Implements all header-related operations described in crypt4gh spec §3.2 and onwards
impl Header {
	pub fn new() -> Self {
		todo!()
	}
	
	/// Get the header packet bytes
	pub fn packets(&self) -> &Vec<HeaderPacket> {
		&self.packets
	}

	/// Get the size of all the packets.
	pub fn length(&self) -> u64 {
		unimplemented!()
	}

	/// Get the inner bytes and size.
	pub fn into_inner(self) -> (Vec<HeaderPacket>, u64) {
		unimplemented!()
	}

	// FIXME: implement default

	/// New header from Bytes
	// pub fn from(self, header_bytes: Bytes) {
	// 	unimplemented!();
	// }

	/// Constructs an encrypted data packet
	pub fn make_data_enc_packet(encryption_method: usize, session_key: &[u8; 32]) -> Vec<u8> {
		vec![
			bincode::serialize(&HeaderPacketType::DataEnc).expect("Unable to serialize packet type"),
			(encryption_method as u32).to_le_bytes().to_vec(),
			session_key.to_vec(),
		]
		.concat()
	}

	/// Constructs an edit list packet
	pub fn make_data_edit_list(edit_list: Vec<usize>) -> Vec<u8> {
		vec![
			bincode::serialize(&HeaderPacketType::EditList).unwrap(),
			(edit_list.len() as u32).to_le_bytes().to_vec(),
			edit_list
				.into_iter()
				.flat_map(|n| (n as u64).to_le_bytes().to_vec())
				.collect(),
		]
		.concat()
	}

	fn encrypt_x25519_chacha20_poly1305(
		data: &[u8],
		seckey: &[u8],
		recipient_pubkey: &[u8],
	) -> Result<Vec<u8>, Crypt4GHError> {

		let server_sk = SecretKey::try_from(&seckey[0..SecretKey::BYTES]).map_err(|_| Crypt4GHError::BadClientPrivateKey)?;
		let client_pk = PublicKey::try_from(recipient_pubkey).map_err(|_| Crypt4GHError::BadServerPublicKey)?;

		let pubkey = server_sk.public_key();


		log::debug!("   packed data({}): {:02x?}", data.len(), data);
		log::debug!("   public key({}): {:02x?}", pubkey.as_ref().len(), pubkey.as_ref());
		log::debug!(
			"   private key({}): {:02x?}",
			seckey[0..32].len(),
			&seckey[0..32]
		);
		log::debug!(
			"   recipient public key({}): {:02x?}",
			recipient_pubkey.len(),
			recipient_pubkey
		);

		// TODO: Make sure this doesn't exceed 2^32 executions, otherwise implement a counter and/or other countermeasures against repeats
		let nonce = ChaCha20Poly1305::generate_nonce(OsRng);

		let keypair = Keypair::from(server_sk);
		let server_session_keys = keypair.session_keys_from(&client_pk);
		let shared_key = GenericArray::<u8, U32>::from_slice(&server_session_keys.rx.as_ref().as_slice());

		log::debug!("   shared key: {:02x?}", shared_key.to_vec());

		let cipher = ChaCha20Poly1305::new(shared_key);

		let ciphertext = cipher.encrypt(&nonce, data)
			.map_err(|err| Crypt4GHError::UnableToEncryptPacket(err.to_string()))?;

		Ok(vec![
			pubkey.as_ref(),
			nonce.as_slice(),
			ciphertext.as_slice()
		].concat())
	}

	/// Computes the encrypted part, using all keys
	///
	/// Given a set of keys and a vector of bytes, it iterates the keys and for every valid key (key.method == 0), it encrypts the packet.
	/// It uses chacha20 and poly1305 to encrypt the packet. It returns a set of encrypted segments that represent the packet for every key.
	///
	/// * `packet` is a vector of bytes of information to be encrypted
	/// * `keys` is a unique collection of keys with `key.method` == 0
	pub fn encrypt(&self, packet: &[u8], keys: &HashSet<KeyPairInfo>) -> Result<Vec<Vec<u8>>, Crypt4GHError> {
		keys.iter()
			.filter(|key| key.method == 0)
			.map(
				|key| match Self::encrypt_x25519_chacha20_poly1305(packet, &key.privkey, &key.recipient_pubkey) {
					Ok(session_key) => Ok(vec![u32::from(key.method).to_le_bytes().to_vec(), session_key].concat()),
					Err(e) => Err(e),
				},
			)
			.collect()
	}

	/// Serializes the header.
	///
	/// Returns [ Magic "crypt4gh" + version + packet count + header packets... ] serialized.
	pub fn serialize(&self, packets: Vec<Vec<u8>>) -> Vec<u8> {
		log::info!("Serializing the header ({} packets)", packets.len());
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

	/// Deserializes the data info from the header bytes.
	///
	/// Reads the magic number, the version and the number of packets from the input bytes.
	pub fn deserialize(&self,
		header: Bytes,
		keys: Vec<KeyPair>,
		sender_pubkey: &Option<Vec<u8>>
	) -> Result<Header, Crypt4GHError> {
		let header_info =
			bincode::deserialize::<Header>(header.bytes()).map_err(|e| Crypt4GHError::ReadHeaderError(e))?;

		if &header_info.magic != MAGIC_NUMBER {
			return Err(Crypt4GHError::MagicStringError);
		}

		if header_info.version != VERSION {
			return Err(Crypt4GHError::InvalidCrypt4GHVersion(header_info.version));
		}

		Ok(header_info)
	}


	pub fn decrypt(
		&mut self,
		encrypted_packets: Vec<Vec<u8>>,
		keys: &[KeyPairInfo],
		sender_pubkey: &Option<Vec<u8>>,
	) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
		let mut decrypted_packets = Vec::new();
		let mut ignored_packets = Vec::new();

		for packet in encrypted_packets {
			match Self::decrypt_packet(&packet, keys, sender_pubkey) {
				Ok(decrypted_packet) => decrypted_packets.push(decrypted_packet),
				Err(e) => {
					log::warn!("Ignoring packet because: {}", e);
					ignored_packets.push(packet);
				},
			}
		}

		(decrypted_packets, ignored_packets)
	}

	fn decrypt_packet(packet: &[u8], keys: &[KeyPairInfo], sender_pubkey: &Option<Vec<u8>>) -> Result<Vec<u8>, Crypt4GHError> {
		let packet_encryption_method =
			bincode::deserialize::<u32>(packet).map_err(|_| Crypt4GHError::ReadPacketEncryptionMethod)?;

		log::debug!("Header Packet Encryption Method: {}", packet_encryption_method);

		for key in keys {
			if packet_encryption_method != u32::from(key.method) {
				continue;
			}

			match packet_encryption_method {
				0 => {
					let plaintext_packet = Self::decrypt_x25519_chacha20_poly1305(&packet[4..], &key.privkey, sender_pubkey);
					//log::debug!("Decrypting packet: {:?}\n into plaintext packet: {:?}\n", &packet[8..], &plaintext_packet);
					return plaintext_packet;
				},
				1 => unimplemented!("AES-256-GCM support is not implemented"),
				n => return Err(Crypt4GHError::BadHeaderEncryptionMethod(n)),
			}
		}
		Err(Crypt4GHError::UnableToEncryptPacket("Error encrypting".to_string()))
	}

	fn decrypt_x25519_chacha20_poly1305(
		encrypted_part: &[u8],
		privkey: &[u8],
		sender_pubkey: &Option<Vec<u8>>,
	) -> Result<Vec<u8>, Crypt4GHError> {
		log::debug!("    secret key: {:02x?}", &privkey[0..32]);

		let peer_pubkey = &encrypted_part[0..32];//PublicKey::BYTES];
		//log::debug!("   peer_pubkey({}): {:02x?}", peer_pubkey.len(), peer_pubkey);

		if sender_pubkey.is_some() && sender_pubkey.clone().unwrap().as_slice() != peer_pubkey {
			return Err(Crypt4GHError::InvalidPeerPubPkey);
		}

		let nonce = GenericArray::from_slice(&encrypted_part[32..44]);
		let packet_data = &encrypted_part[44..];

		let client_sk = SecretKey::try_from(&privkey[0..SecretKey::BYTES]).map_err(|_| Crypt4GHError::BadClientPrivateKey)?;
		let server_pk = PublicKey::try_from(peer_pubkey).map_err(|_| Crypt4GHError::BadServerPublicKey)?;

		let keypair = Keypair::from(client_sk);
		let client_session_keys = keypair.session_keys_to(&server_pk);
		let shared_key = GenericArray::<u8, U32>::from_slice(&client_session_keys.tx.as_ref().as_slice());

		let cipher = ChaCha20Poly1305::new(shared_key);

		log::debug!("    peer pubkey: {:02x?}", peer_pubkey);
		log::debug!("    nonce: {:02x?}", &nonce);
		log::debug!(
			"    encrypted data ({}): {:02x?}",
			packet_data.len(),
			packet_data
		);

		log::debug!("shared key: {:02x?}", shared_key);

		let plaintext = cipher.decrypt(&nonce, packet_data)
			.map_err(|err| Crypt4GHError::UnableToDecryptBlock(packet_data.to_vec(), err.to_string()))?;

		Ok(plaintext)
	}

	fn partition_packets(packets: Vec<Vec<u8>>) -> Result<Vec<HeaderPacket>, Crypt4GHError> {
		let mut enc_packets = Vec::new();
		let mut edits = None;

		for packet in packets {
			let packet_type =
				bincode::deserialize::<HeaderPacketType>(&packet[0..4]).map_err(|_| Crypt4GHError::InvalidPacketType)?;

			match packet_type {
				HeaderPacketType::DataEnc => {
					enc_packets.push(packet[4..].to_vec());
				},
				HeaderPacketType::EditList => {
					match edits {
						None => edits = Some(packet[4..].to_vec()),
						Some(_) => return Err(Crypt4GHError::TooManyEditListPackets),
					};
				},
			}
		}

		Ok(HeaderPackets {
			data_enc_packets: enc_packets,
			edit_list_packet: edits,
		})
	}

	fn parse_enc_packet(packet: &[u8]) -> Result<Vec<u8>, Crypt4GHError> {
		match packet[0..4] {
			[0, 0, 0, 0] => Ok(packet[4..].to_vec()),
			_ => Err(Crypt4GHError::UnsupportedEncryptionMethod(
				bincode::deserialize::<u32>(&packet[0..4]).expect("Unable to deserialize bulk encryption method"),
			)),
		}
	}

	fn parse_edit_list_packet(packet: &[u8]) -> Result<Vec<u64>, Crypt4GHError> {
		let nb_lengths: u32 = bincode::deserialize::<u32>(packet).map_err(|_| Crypt4GHError::NoEditListLength)?;

		log::info!("Edit list length: {}", nb_lengths);
		log::info!("packet content length: {}", packet.len() - 4);

		if ((packet.len() as u32) - 4) < (8 * nb_lengths) {
			return Err(Crypt4GHError::InvalidEditList);
		}

		(4..nb_lengths * 8)
			.step_by(8)
			.map(|i| bincode::deserialize::<u64>(&packet[i as usize..]).map_err(|_| Crypt4GHError::InvalidEditList))
			.collect()
	}

	/// Gets data packets and edit list packets from the encrypted packets.
	///
	/// Decrypts the encrypted packets and partitions the encrypted packets in two groups,
	/// the data packets and the edit list packets. Finally, it parses the packets.
	pub fn deconstruct_header_body(
		encrypted_packets: Vec<Vec<u8>>,
		keys: &[KeyPairInfo],
		sender_pubkey: &Option<Vec<u8>>,
	) -> Result<Vec<HeaderPacket>, Crypt4GHError> {
		let (packets, _) = decrypt(encrypted_packets, keys, sender_pubkey)?;

		if packets.is_empty() {
			return Err(Crypt4GHError::NoSupportedEncryptionMethod);
		}

		let Vec<HeaderPacket> {
			data_enc_packets,
			edit_list_packet,
		} = Self::partition_packets(packets)?;

		let session_keys = data_enc_packets
			.into_iter()
			.map(|d| Self::parse_enc_packet(&d))
			.collect::<Result<Vec<_>, Crypt4GHError>>()?;

		let edit_list = match edit_list_packet {
			Some(packet) => Some(Self::parse_edit_list_packet(&packet)?),
			None => None,
		};

		Ok(Vec<HeaderPacket> {
			data_enc_packets: session_keys,
			edit_list_packet: edit_list,
		})
	}


	/// Reencrypts the header.
	///
	/// Decrypts the header using the `keys` and then, encrypts the content again for every
	/// key in `recipient_keys`. If trim is specified, the packets that cannot be decrypted are discarded.
	pub fn reencrypt(
		header_packets: Vec<Vec<u8>>,
		keys: &[KeyPairInfo],
		recipient_keys: &HashSet<KeyPairInfo>,
		trim: bool,
	) -> Result<Header, Crypt4GHError> {
		log::info!("Reencrypting the header");

		let (decrypted_packets, mut ignored_packets) = decrypt(header_packets, keys, &None)?;

		if decrypted_packets.is_empty() {
			Err(Crypt4GHError::NoValidHeaderPacket)
		}
		else {
			let mut packets: Vec<Vec<u8>> = decrypted_packets
				.into_iter()
				.flat_map(|packet| encrypt(&packet, recipient_keys).unwrap())
				.collect();

			if !trim {
				packets.append(&mut ignored_packets);
			}

			Ok(packets)
		}
	}

	/// Gets the packages to rearrange.
	///
	/// Rearranges the edit list in accordance to the range. It returns the data packets
	/// along with an oracle that decides if the next packet should be kept (starting by the first).
	pub fn rearrange<'a>(
		header_packets: Vec<Vec<u8>>,
		keys: Vec<KeyPairInfo>,
		range_start: usize,
		range_span: Option<usize>,
		sender_pubkey: &Option<Vec<u8>>,
	) -> Result<(Vec<Vec<u8>>, impl Iterator<Item = bool> + 'a), Crypt4GHError> {
		if range_span <= Some(0) {
			//assert!(span > 0, "Span should be greater than 0");
			return Err(Crypt4GHError::InvalidRangeSpan(range_span));
		}

		log::info!("Rearranging the header");

		log::debug!("    Start coordinate: {}", range_start);
		range_span.map_or_else(
			|| {
				log::debug!("    End coordinate: EOF");
			},
			|span| {
				log::debug!("    End coordinate: {}", range_start + span);
			},
		);
		log::debug!("    Segment size: {}", SEGMENT_SIZE);

		if range_start == 0 && range_span.is_none() {
			return Err(Crypt4GHError::Done);
		}

		let (decrypted_packets, _) = decrypt(header_packets, &keys, sender_pubkey)?;

		if decrypted_packets.is_empty() {
			return Err(Crypt4GHError::NoValidHeaderPacket);
		}

		let HeaderPackets {
			data_enc_packets,
			edit_list_packet,
		} = partition_packets(decrypted_packets)?;

		if edit_list_packet.is_some() {
			unimplemented!()
		}

		log::info!("No edit list present: making one");

		let start_segment = range_start / SEGMENT_SIZE;
		let start_offset = range_start % SEGMENT_SIZE;
		let end_segment = range_span.map(|span| (range_start + span) / SEGMENT_SIZE);
		let end_offset = range_span.map(|span| (range_start + span) % SEGMENT_SIZE);

		log::debug!("Start segment: {} | Offset: {}", start_segment, start_offset);
		log::debug!("End segment: {:?} | Offset: {:?}", end_segment, end_offset);

		let segment_oracle = (0..).map(move |count| {
			if count < start_segment {
				false
			}
			else {
				match end_segment {
					Some(end) => count < end || (count == end && end_offset.unwrap() > 0),
					None => true,
				}
			}
		});

		let mut edit_list = vec![start_offset];
		if let Some(span) = range_span {
			edit_list.push(span);
		}

		log::debug!("New edit list: {:?}", edit_list);
		let edit_packet = make_packet_data_edit_list(edit_list);

		log::info!("Reencrypting all packets");

		let mut packets = data_enc_packets
			.into_iter()
			.map(|packet| vec![bincode::serialize(&HeaderPacketType::DataEnc).unwrap(), packet].concat())
			.collect::<Vec<Vec<u8>>>();

		packets.push(edit_packet);

		let hash_keys = keys.into_iter().collect::<HashSet<KeyPairInfo>>();

		let final_packets = packets
			.into_iter()
			.map(|packet| encrypt(&packet, &hash_keys).map(|encrypted_packets| encrypted_packets.concat()))
			.collect::<Result<Vec<Vec<u8>>, Crypt4GHError>>()?;

		Ok((final_packets, segment_oracle))
	}

	/// Builds a header with a random session key
	///
	/// Returns the encrypted header bytes
	pub fn encrypt_header(
		recipient_keys: &HashSet<keys::KeyPairInfo>,
		session_key: SessionKeys,
	) -> Result<Vec<u8>, Crypt4GHError> {
		let encryption_method = 0;
		
		let session_key_or_new = session_key.map_or_else(|| {
			let mut session_key = [0_u8; 32];
			let mut rnd = rand_chacha::ChaCha20Rng::from_entropy();

			rnd.try_fill_bytes(&mut session_key).map_err(|_| Crypt4GHError::NoRandomNonce)?; // TODO: Custom error for this

			Ok::<_, Crypt4GHError>(session_key)
		}, |value| { Ok(value)} )?;

		let header_content = header::make_packet_data_enc(encryption_method, &session_key_or_new);
		let header_packets = header::encrypt(&header_content, recipient_keys)?;
		let header_bytes = header::serialize(header_packets);
		Ok(header_bytes)
	}
}

impl Default for Header {
    fn default() -> Self {
        Self {
            magic: MAGIC_NUMBER,
            version: VERSION,
            packet_count: 0,
            header_packets: Vec::new(),
        }
    }
}

