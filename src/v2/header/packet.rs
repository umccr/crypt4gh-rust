//! Structs and parsing for the header packet types.
//!

use std::array::TryFromSliceError;
use crate::v2::crypt::EncryptedData;
use crate::v2::error::Error::{HeaderDecodeError, HeaderParseError};
use crate::v2::error::Result;

/// Crypt4GH §A.1
/// For symmetric encryption, the main candidates for authenticated encryption were AES-GCM and ChaCha20-
/// Poly1305. Both have good security guarantees, and thanks to their use in TLS 1.3 both have good library sup-
/// port. ChaCha20-Poly1305 was chosen because it allows much longer files to be encrypted
#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
pub enum EncryptionMethod {
    X25519Chacha20Poly305,
}

impl EncryptionMethod {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        match u32::from_le_bytes(buf.try_into().map_err(|err: TryFromSliceError| HeaderParseError(err.to_string()))?) {
            0 => Ok(EncryptionMethod::X25519Chacha20Poly305),
            _ => Err(HeaderParseError(format!("unknown encryption method: {}", buf.len()))),
        }
    }

    pub fn to_bytes(&self) -> [u8; size_of::<u32>()] {
        match self {
            EncryptionMethod::X25519Chacha20Poly305 => 0u32.to_le_bytes(),
        }
    }
}

/// Crypt4gh spec §3.2.1 - Header Packets
pub const PUBLIC_KEY_LENGTH: usize = 32;
pub const PRIVATE_KEY_LENGTH: usize = 32;

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
    pub length: u32,
    pub encryption_method: EncryptionMethod,
    pub writer_public_key: [u8; PUBLIC_KEY_LENGTH],
    pub encrypted_data: EncryptedData,
}

impl Packet {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        todo!()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        todo!()
    }

    pub fn decode(buf: &[u8]) -> Result<Option<u32>> {
        // Need to read more bytes first.
        if buf.len() < size_of::<u32>() {
            return Ok(None);
        }

        Ok(Some(u32::from_le_bytes(buf[..size_of::<u32>()].try_into().map_err(|err: TryFromSliceError| HeaderDecodeError(err.to_string()))?)))
    }

    /// Decrypt the packet using the key.
    pub fn decrypt(mut self, key: &[u8]) -> Result<DecryptedPacket> {
        let buf = self.encrypted_data.decrypt(key)?;
        DecryptedPacket::parse(buf.as_slice())
    }
}

/// Crypt4gh spec §2.3 - Header Packet Types
///
/// There are two types of header packet:
#[derive(Debug)]
pub enum DecryptedPacket {
    EncryptionPacket(EncryptionPacket),
    EditList(EditListPacket),
}

impl DecryptedPacket {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        match u32::from_le_bytes(buf.try_into().map_err(|err: TryFromSliceError| HeaderParseError(err.to_string()))?) {
            0 => EncryptionPacket::parse(buf).map(DecryptedPacket::EncryptionPacket),
            1 => EditListPacket::parse(buf).map(DecryptedPacket::EditList),
            _ => Err(HeaderParseError(format!("unknown encryption method: {}", buf.len()))),
        }
    }

    pub fn to_bytes(&self) -> [u8; size_of::<Self>()] {
        let mut buf = [0; size_of::<Self>()];

        match self {
            DecryptedPacket::EncryptionPacket(packet) => {
                buf[..size_of::<u32>()].copy_from_slice(&0u32.to_le_bytes());
                buf[size_of::<u32>()..].copy_from_slice(packet.to_bytes().as_slice());
            }
            DecryptedPacket::EditList(packet) => {
                buf[..size_of::<u32>()].copy_from_slice(&0u32.to_le_bytes());
                buf[size_of::<u32>()..].copy_from_slice(packet.to_bytes().as_slice());
            }
        }

        buf
    }
    
    pub fn encrypt(self, key: &[u8]) -> Result<Packet> {
        todo!()
    }
}

#[derive(Debug)]
pub struct EncryptionPacket {
    encryption_method: EncryptionMethod,
    data_key: [u8; PRIVATE_KEY_LENGTH],
}

impl EncryptionPacket {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        Ok(
            Self {
                encryption_method: EncryptionMethod::parse(buf)?,
                data_key: {
                    let mut data_key = [0; PRIVATE_KEY_LENGTH];
                    data_key.copy_from_slice(&buf[..PRIVATE_KEY_LENGTH]);
                    data_key
                }
            }
        )
    }

    pub fn to_bytes(&self) -> [u8; size_of::<Self>()] {
        let mut buf = [0; size_of::<Self>()];
        let encryption_method = self.encryption_method.to_bytes();

        buf[..size_of::<EncryptionMethod>()].copy_from_slice(encryption_method.as_slice());
        buf[size_of::<EncryptionMethod>()..].copy_from_slice(self.data_key.as_ref());

        buf
    }
}

#[derive(Debug)]
pub struct EditListPacket {
    packet_lengths: u32,
    edit_list: Vec<u8>,
}


impl EditListPacket {
    pub fn parse(buf: &[u8]) -> Result<Self> {
        todo!()
    }

    pub fn to_bytes(&self) -> [u8; size_of::<Self>()] {
        todo!()
    }
}
