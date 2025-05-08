use tokio::io::AsyncRead;

use crate::{ciphertext::DataBlocks, error::Crypt4GHError, keys::KeyPair, plaintext::PlainText, CipherText, Crypt4GhBuilder};
use crate::Crypt4GHFile;

pub struct Reader<R> {
    inner: R,
    buf: Vec<u8>,
}

impl<R> Reader<R> {
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
    pub fn decrypt(&mut self, keys: KeyPair, crypt4gh_file: Crypt4GHFile) -> Result<PlainText, Crypt4GHError> {
        crypt4gh_file.decrypt(keys)
    }
}

impl<R> From<R> for Reader<R> {
    // TODO
    //fn read_header
    //fn read_block
    fn from(inner: R) -> Self {
        Self {
            inner,
            buf: Vec::new(),
        }
    }
}