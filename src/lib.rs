pub mod cyphertext;
pub mod error;
pub mod header;
pub mod keys;
pub mod plaintext;

use std::collections::HashSet;

use crate::{error::Crypt4GHError, keys::KeyPair, keys::PublicKey};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::consts::U32;
use chacha20poly1305::{aead::generic_array::GenericArray, AeadCore, ChaCha20Poly1305, KeyInit};
use crypto_kx::{Keypair as CryptoKeyPair, PublicKey as CryptoPubKey, SecretKey as CryptoSecretKey};
use cyphertext::CypherText;
use header::HeaderPacketType;
use keys::{EncryptionMethod, PrivateKey, SessionKeys};
use plaintext::PlainText;

use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use rand_chacha::{
	rand_core::SeedableRng,
	ChaCha20Rng,
};

#[derive(Clone)]
pub struct Crypt4Gh {
	keys: KeyPair,
	seed: Seed,
}

impl<'a> Crypt4Gh {
	pub fn new(keys: KeyPair) -> Crypt4Gh {
		let seed = Seed { inner: OsRng.gen() };
		Crypt4Gh { keys, seed }
	}

	pub fn encrypt(self, plaintext: PlainText) -> Result<CypherText, Crypt4GHError> {
		let session_key = SessionKeys::from(Vec::with_capacity(32));
		// FIXME: Unsure if this is correct, revisit
		let mut seed = ChaCha20Rng::seed_from_u64(u64::from_be_bytes(self.seed.inner[0..8].try_into().unwrap()));
		let mut rnd = ChaCha20Rng::from_seed(seed.get_seed());

		// random bytes into session_key
		// FIXME: Support multiple session keys? Refactor SessionKeys type to single session_key if not used.
		rnd.try_fill_bytes(&mut session_key.inner.clone().unwrap()[0])
			.map_err(|_| Crypt4GHError::NoRandomNonce)?;

		todo!();
		//let header = Header::encrypt(, Some(session_key), self.seed)?;
		//Ok(())
	}

	pub fn decrypt(self, _cyphertext: CypherText) -> Result<PlainText, Crypt4GHError> {
		todo!();
		//Ok(PlainText::from("payload".as_bytes().to_vec()))
	}
}

/// Computes the encrypted header part for each key in the given collection
///
/// Given a set of keys and a vector of bytes representing a packet, this function iterates over the keys and encrypts the packet using the x25519_chacha20_poly1305 encryption method.
/// It returns a vector of encrypted segments, where each segment represents the encrypted packet for a specific key.
///
/// * `packet` - A vector of bytes representing the packet to be encrypted
/// * `keys` - A collection of keypairs with `key.method` equal to 0
pub fn compute_encrypted_header(packet: &[u8], keys: &HashSet<KeyPair>) -> Result<Vec<Vec<u8>>, Crypt4GHError> {
	keys.iter()
		.filter(|key| key.method == EncryptionMethod::X25519Chacha20Poly305)
		.map(|key| {
			match encrypt_x25519_chacha20_poly1305(packet, key.private_key.clone(), key.public_keys.clone()) {
				Ok(session_key) => Ok(vec![u32::from(key.method as u32).to_le_bytes().to_vec(), session_key].concat()),
				Err(e) => Err(e),
			}
		})
		.collect()
}

/// Constructs an encrypted data packet with the given encryption method and session keys
fn construct_encrypted_data_packet(encryption_method: EncryptionMethod, session_keys: SessionKeys) -> Vec<u8> {
	vec![
		bincode::serialize(&HeaderPacketType::DataEnc).expect("Unable to serialize packet type"),
		(encryption_method as u32).to_le_bytes().to_vec(),
		session_keys.to_bytes(),
	]
	.concat()
}

fn encrypt_x25519_chacha20_poly1305(
	data: &[u8],
	private_key: PrivateKey,
	recipients: Recipients,
) -> Result<Vec<u8>, Crypt4GHError> {

    let server_sk = CryptoSecretKey::try_from(&private_key.bytes[0..CryptoSecretKey::BYTES]).map_err(|_| Crypt4GHError::BadClientPrivateKey)?;
	let client_pk = PublicKey::try_from(recipients.recipients[0].clone()).map_err(|_| Crypt4GHError::BadServerPublicKey)?;

    let pubkey = server_sk.public_key();

	// log::debug!("   packed data({}): {:02x?}", data.len(), data);
	// log::debug!("   public key({}): {:02x?}", pubkey.as_ref().len(), pubkey.as_ref());
	// log::debug!(
	// 	"   private key({}): {:02x?}",
	// 	seckey[0..32].len(),
	// 	&seckey[0..32]
	// );
	// log::debug!(
	// 	"   recipient public key({}): {:02x?}",
	// 	recipient_pubkey.len(),
	// 	recipient_pubkey
	// );

	// TODO: Make sure this doesn't exceed 2^32 executions, otherwise implement a counter and/or other countermeasures against repeats
	let nonce = ChaCha20Poly1305::generate_nonce(OsRng);

    let keypair = CryptoKeyPair::from(server_sk);
	let client_crypto_pubkey = CryptoPubKey::from(<[u8; CryptoPubKey::BYTES]>::try_from(client_pk.bytes.as_slice()).expect("slice with incorrect length"));
    let server_session_keys = keypair.session_keys_from(&client_crypto_pubkey);
    let shared_key = GenericArray::<u8, U32>::from_slice(&server_session_keys.rx.as_ref().as_slice());

    //log::debug!("   shared key: {:02x?}", shared_key.to_vec());

    let cipher = ChaCha20Poly1305::new(shared_key);

    let ciphertext = cipher.encrypt(&nonce, data)
        .map_err(|err| Crypt4GHError::UnableToEncryptPacket(err.to_string()))?;

    Ok(vec![
        pubkey.as_ref(),
        nonce.as_slice(),
        ciphertext.as_slice()
    ].concat())
}


/// Multiple recipients and their public keys
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Recipients {
	pub recipients: Vec<PublicKey>
}

impl Recipients {
	pub fn from(public_keys: Vec<PublicKey>) -> Self {
		Recipients { recipients: public_keys }
	}
}

#[derive(Clone)]
pub struct Seed {
	pub inner: [u8; 32]
}