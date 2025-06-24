use std::io::Read;

use tokio::io::AsyncRead;

use crate::{ciphertext::DataBlocks, error::Crypt4GHError, keys::KeyPair, CipherText, Crypt4GhBuilder};
use crate::{Crypt4GHFile, PLAINTEXT_SEGMENT_SIZE};

// Generic reader
pub struct Reader<R> {
    inner: R,
    buf: Vec<u8>,
}

impl<R> Reader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buf: Vec::new(),
        }
    }

    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R> Reader<R>
where
    R: AsyncRead + Unpin,
{
    async fn read_header(self) -> Header {
        let bytes = self.inner.read_exact();
        Header::from_bytes()
    }

    fn decrypt(&self) -> PlainText {
        todo!()
    }

    // pub fn decrypt(&mut self, keys: KeyPair, crypt4gh_file: Crypt4GHFile) -> Result<PlainText, Crypt4GHError> {
    //     crypt4gh_file.decrypt(keys)
    // }
}

impl<R> From<R> for Reader<R> {
    fn from(inner: R) -> Self {
        Self {
            inner,
            buf: Vec::new(),
        }
    }
}

/// Plaintext newtype, avoids API misuse
#[derive(Debug)]
pub struct PlainText<R> {
	inner: R,
}