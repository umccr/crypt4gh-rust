use std::{error::Error, path::PathBuf};

use crypt4gh::error::Crypt4GHError;
use crypt4gh::keys::{EncryptionMethod, KeyPair, PrivateKey, PublicKey};
use crypt4gh::plaintext::PlainText;
use crypt4gh::{Crypt4Gh, Recipients};

use noodles::cram;
use tokio::fs::File;

async fn read_cram_header(src: PathBuf) -> Result<String, Crypt4GHError> {
	let mut reader = File::open(src).await.map(cram::AsyncReader::new)?;
	let header = reader.read_header().await?;
	Ok(header)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
	// Setup PKI
	let mut pubkeys = vec![];
    pubkeys.push(PublicKey::new());

	let privkey = PrivateKey::new();
	let keypair = KeyPair::new(EncryptionMethod::X25519Chacha20Poly305, privkey, pubkeys);

	// Init the Crypt4GH client
	let c4gh = Crypt4Gh::new(keys.clone());

	// Read header bytes from a CRAM file
	let cram_header = read_cram_header(PathBuf::from("./data/cram/htsnexus_test_NA12878.cram"))
		.await?
		.as_bytes()
		.to_vec();
	let plaintext = PlainText::from(cram_header);

	// Encrypt and decrypt payload
	let recipients = Recipients::from(pubkeys);

	let enc = c4gh.encrypt(plaintext, recipients)
				  .with_range("0-200")?; // TODO: Determine Range type:
										 //
										 // Range::None
										 // Range::Header
										 // Range::Body
										 // Range::Full
										 // Range::Custom(usize) ???

	let dec = enc.decrypt(keypair.private_key)?;

	dbg!(dec);

	// All is fine
	Ok(())
}
