use chacha20poly1305::Key;
use tokio::io::AsyncRead;

use crate::{cyphertext::{self, CypherText}, error::Crypt4GHError, keys::KeyPair, plaintext::{self, PlainText}, Crypt4GhBuilder};

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
    pub fn decrypt(&mut self, keys: KeyPair, cyphertext: CypherText) -> Result<PlainText, Crypt4GHError> {
        let c4gh = Crypt4GhBuilder::new(keys.clone()).build(); // TODO: Take as_ref() in this new to avoid .clone()?
        c4gh.decrypt(cyphertext, keys.private_key)
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