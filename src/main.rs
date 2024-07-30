use std::{error::Error, path::PathBuf};

use crypt4gh::{error::Crypt4GHError, keys::{EncryptionMethod, KeyPair, PrivateKey, PublicKey}};
use noodles::cram;

async fn read_cram(path: PathBuf) -> Result<Vec<u8>, Crypt4GHError> {
    let mut reader = cram::r#async::io::reader::Builder::default()
        .set_reference_sequence_repository(repository)
        .build_from_path(path)
        .await?;

    let header = reader.read_header().await?;
    let mut records = reader.records(&header);

    // TODO: Read (whole?) payload, not just header

    Ok(records)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Setup PKI
    let pubkey = PublicKey::new();
    let privkey = PrivateKey::new();
    let keys = KeyPair::new(EncryptionMethod::X25519Chacha20Poly305, privkey, pubkey);
    
    // Init the Crypt4GH client
    let c4gh = crypt4gh::new();
    
    // Read bytes from stdin for a Crypt4GH encrypted BAM/CRAM
    let plain = read_cram(PathBuf::from("./data/cram/htsnexus_test_NA12878.cram")).await;

    // Encrypt and decrypt payload
    let enc = c4gh.encrypt(plain, keys);
    let dec = c4gh.decrypt(enc, keys);
    
    // Make sure it worked
    assert!(plain, dec);

    // All is fine
    Ok(())
}
