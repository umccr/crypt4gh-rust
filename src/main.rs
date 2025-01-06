use std::error::Error;
use std::path::PathBuf;

use crypt4gh::error::Crypt4GHError;
use crypt4gh::keys::{EncryptionMethod, KeyPair, PrivateKey, PublicKey};
use crypt4gh::plaintext::PlainText;
use crypt4gh::{Crypt4GhBuilder, Recipients};
use noodles::cram;
use tokio::fs::File;

async fn read_cram_header(src: PathBuf) -> Result<String, Crypt4GHError> {
	let mut reader = File::open(src).await.map(cram::AsyncReader::new)?;
	let header = reader.read_header().await?;
	let header_str = format!("{:?}", header); // FIXME: Yikes...
	Ok(header_str)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
	// Setup PKI
	let mut pubkeys = vec![];
	pubkeys.push(PublicKey::new());

	let privkey = PrivateKey::new();
	let keypair = KeyPair::new(EncryptionMethod::X25519Chacha20Poly305, privkey, crypt4gh::Recipients { public_keys: pubkeys.clone() });

	// Init the Crypt4GH client
	let c4gh = Crypt4GhBuilder::new(keypair.clone()).build();
	//.with_range(..);

	// Read header bytes from a CRAM file
	let cram_header = read_cram_header(PathBuf::from("./data/cram/htsnexus_test_NA12878.cram"))
		.await?
		.as_bytes()
		.to_vec();

	let plaintext = PlainText::from(cram_header);

	// Encrypt and decrypt payload
	let recipients = Recipients::from(pubkeys.clone());

	let enc = c4gh.encrypt(plaintext, recipients)?;
	let dec = enc.decrypt(keypair)?;

	dbg!(dec);

	// All is fine
	Ok(())
}
