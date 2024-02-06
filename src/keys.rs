#![warn(missing_docs)]
#![warn(rustdoc::missing_doc_code_examples)]

use aes::cipher::{StreamCipher, generic_array::GenericArray};

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Read, Write, BufWriter};
use std::path::PathBuf;

use base64::engine::general_purpose;
use base64::Engine;

use lazy_static::lazy_static;

use rand_chacha;
use rand::{SeedableRng, RngCore, Rng};

use crypto_kx::{Keypair, SecretKey};

use aes::cipher::{KeyInit, KeyIvInit};
use aes::cipher::consts::U48;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::aead::OsRng;
use chacha20poly1305::{self, ChaCha20Poly1305};

use ctr;

use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::traits::IsIdentity;

use crate::error::Crypt4GHError;

const C4GH_MAGIC_WORD: &[u8; 7] = b"c4gh-v1";
const SSH_MAGIC_WORD: &[u8; 15] = b"openssh-key-v1\x00";

lazy_static! {
	static ref KDFS: HashMap<&'static str, (usize, u32)> = [
		("scrypt", (16, 0)),
		("bcrypt", (16, 100)),
		("pbkdf2_hmac_sha256", (16, 100_000)),
	]
	.iter()
	.copied()
	.collect();
}

lazy_static! {
	static ref CIPHER_INFO: HashMap<&'static str, (u64, u64)> = [
		("aes128-ctr", (16, 16)),
		("aes192-ctr", (16, 24)),
		("aes256-ctr", (16, 32)),
		("aes128-cbc", (16, 16)),
		("aes192-cbc", (16, 24)),
		("aes256-cbc", (16, 32)),
		("3des-cbc",   ( 8, 24)),
		//("blowfish-cbc", (8, 16)),
	]
	.iter()
	.copied()
	.collect();
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
/// Key information.
pub struct Keys {
	/// Method used for the key encryption.
	/// > Only method 0 is supported.
	pub method: u8,
	/// Secret key of the encryptor / decryptor (your key).
	pub privkey: Vec<u8>,
	/// Public key of the recipient (the key you want to encrypt for).
	pub recipient_pubkey: Vec<u8>,
}

pub struct SessionKeys {
	inner: Vec<Vec<u8>>
}