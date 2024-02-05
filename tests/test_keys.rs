mod test_common;

use crypt4gh::{keys::get_private_key, Keys};
use rand::Rng;
use rand_chacha::rand_core::OsRng;
use ssh_key::PrivateKey;
pub use test_common::*;
use testresult::TestResult;

#[test]
fn encrypt_decrypt_ssh() -> TestResult {
	// Init
	let init = Cleanup::new();
	pretty_env_logger::init();
	let mut rng = rand::thread_rng();

	// Generate 10MB of "cleartext" payload
	let mut cleartext = vec![0u8; 10 * 1024 * 1024];
	rng.fill(&mut cleartext[..]);

	// Generate a random SSH key, no pubkey for sender and no range values
	let private_key = PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519)?;
	let sender_pubkey = None;
	let (range_start, range_span) = (0, None);

	let keys = vec![Keys {
		method: 0,
		privkey: private_key.to_bytes()?.to_vec(),
		recipient_pubkey: vec![],
	}];

	// Encrypt
	let cryptext = crypt4gh::encrypt(
		&keys, 
		range_start, 
		range_span
	);

	// Decrypt
	let plaintext = crypt4gh::decrypt(
		&keys,
		range_start,
		range_span,
		&sender_pubkey,
	)?;

	// Compare
	equal(&cleartext, &plaintext);

	// Cleanup
	drop(init);

	Ok(())
}