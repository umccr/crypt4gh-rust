use std::{error::Error, path::PathBuf};

use crypt4gh::error::Crypt4GHError;
use crypt4gh::keys::{EncryptionMethod, KeyPair, PrivateKey, PublicKey};
use crypt4gh::Crypt4Gh;
use crypt4gh::plaintext::PlainText;
use crypt4gh::cyphertext::CypherText;

use noodles::cram;
use tokio::fs::File;

async fn read_cram_header(src: PathBuf) -> Result<String, Crypt4GHError> {
    let mut reader = File::open(src).await.map(cram::AsyncReader::new)?;
    let header = reader.read_file_header().await?;
    Ok(header)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Setup PKI
    let pubkey = PublicKey::new();
    let privkey = PrivateKey::new();
    let keys = KeyPair::new(EncryptionMethod::X25519Chacha20Poly305, privkey, pubkey);

    // Init the Crypt4GH client
    let c4gh = Crypt4Gh::new(keys);

    // Read bytes from stdin for a CRAM
    let plain = read_cram_header(PathBuf::from("./data/cram/htsnexus_test_NA12878.cram")).await?.as_bytes().to_vec();
    let plain = PlainText::from(plain);

    // Encrypt and decrypt payload
    let enc = c4gh.encrypt(plain)?;
    let cypher = CypherText::from(enc);
    let dec = c4gh.decrypt(enc)?;

    dbg!(plain);
    dbg!(enc);

    // Make sure it worked
    //assert_eq!(plain, dec);

    // All is fine
    Ok(())
}