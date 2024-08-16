const C4GH_MAGIC_WORD: &[u8; 7] = b"c4gh-v1";
const SSH_MAGIC_WORD: &[u8; 15] = b"openssh-key-v1\x00";

use crate::error::Crypt4GHError;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum EncryptionMethod { // TODO: Spec says u32 for this enum, how to encode?
  X25519Chacha20Poly305,
  Aes256Gcm
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
/// Key information.
pub struct KeyPair {
	/// Method used for the key encryption.
	/// > Only method 0 is supported.
	pub method: EncryptionMethod,
	/// Secret key of the encryptor / decryptor (your key).
	pub private_key: PrivateKey,
	/// Public key(s) of the recipient(s)
	pub public_key: Vec<PublicKey>,
}

#[derive(Debug)]
pub struct SessionKeys {
	pub inner: Option<Vec<Vec<u8>>>
}

/// Private keys are just bytes since it should support disparate formats, i.e: SSH and GA4GH
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct PrivateKey {
  pub bytes: Vec<u8>,
}

/// A wrapper around a vec of bytes that represent a public key.
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct PublicKey {
  pub bytes: Vec<u8>,
}


impl KeyPair {
  /// Create a new key pair.
  pub fn new(method: EncryptionMethod, private_key: PrivateKey, public_key: PublicKey) -> Self {
    let mut pub_key = Vec::new();
    pub_key.push(public_key);

    KeyPair {
      method,
      private_key,
      public_key: pub_key,
    }
  }

  /// Get the inner keys.
  pub fn into_inner(self) -> (PrivateKey, Vec<PublicKey>) {
    (self.private_key, self.public_key)
  }

  /// Get private key.
  pub fn private_key(&self) -> &PrivateKey {
    &self.private_key
  }

  /// Get private key
  pub fn public_key(&self) -> &Vec<PublicKey> {
    &self.public_key
  }
}

impl PublicKey {
  /// Generate a new sender public key.
  pub fn new() -> Self {
    unimplemented!()
  }  
  
  /// Create a new sender public key from bytes.
  pub fn new_from_bytes(bytes: Vec<u8>) -> Self {
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

impl PrivateKey {
  /// Generate a new private key.
  pub fn new() -> Self {
    unimplemented!()
  }  
  
  /// Create a new private key from bytes.
  pub fn new_from_bytes(bytes: Vec<u8>) -> Self {
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

impl SessionKeys {
  /// Create a new SessionKeys instance.
  pub fn new(inner: Vec<Vec<u8>>) -> Self {
    Self {
      inner: Some(inner),
    }
  }

  /// Get the inner session keys.
  pub fn inner(&self) -> &Option<Vec<Vec<u8>>> {
    &self.inner
  }

  /// Create a new SessionKeys instance from a slice of session keys.
  pub fn from(session_keys: &[Vec<u8>]) -> Self {
    Self {
      inner: Some(session_keys.to_vec()),
    }
  }

  /// Add a session key to the inner session keys.
  pub fn add_session_key(&mut self, session_key: Vec<u8>) {
    Some(session_key);
  }
}

/// Generate a private and public key pair.
pub fn generate_key_pair() -> Result<KeyPair, Crypt4GHError> {
  let method = EncryptionMethod::X25519Chacha20Poly305;
  let private_key = PrivateKey::new();
  let public_key = PublicKey::new();
  
  Ok(KeyPair::new(
    method,
    private_key,
    public_key
  ))
}