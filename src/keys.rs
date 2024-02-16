#![warn(missing_docs)]
#![warn(rustdoc::missing_doc_code_examples)]

const C4GH_MAGIC_WORD: &[u8; 7] = b"c4gh-v1";
const SSH_MAGIC_WORD: &[u8; 15] = b"openssh-key-v1\x00";

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
	pub inner: Vec<Vec<u8>>
}

/// Private keys are just bytes since it should support disparate formats, i.e: SSH and GA4GH
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateKey {
  pub bytes: Vec<u8>,
}

/// A wrapper around a vec of bytes that represent a public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
  pub bytes: Vec<u8>,
}

/// A key pair containing a public and private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPair {
  private_key: PrivateKey,
  public_key: PublicKey,
}

impl KeyPair {
  /// Create a new key pair.
  pub fn new(private_key: PrivateKey, public_key: PublicKey) -> Self {
    Self {
      private_key,
      public_key,
    }
  }

  /// Get the inner keys.
  pub fn into_inner(self) -> (PrivateKey, PublicKey) {
    (self.private_key, self.public_key)
  }

  /// Get private key.
  pub fn private_key(&self) -> &PrivateKey {
    &self.private_key
  }

  /// Get private key
  pub fn public_key(&self) -> &PublicKey {
    &self.public_key
  }
}

impl PublicKey {
  /// Create a new sender public key from bytes.
  pub fn new(bytes: Vec<u8>) -> Self {
    Self { bytes }
  }

  /// Get the inner bytes.
  pub fn into_inner(self) -> Vec<u8> {
    self.bytes
  }

  /// Get the inner bytes as a reference.
  pub fn get_ref(&self) -> &[u8] {
    self.bytes.as_slice()
  }
}