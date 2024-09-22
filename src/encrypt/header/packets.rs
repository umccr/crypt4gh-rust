use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use crate::error::Crypt4GHError;
use crate::keys::{KeyPair, PublicKey};
use pin_project_lite::pin_project;
use tokio::task::{spawn_blocking, JoinHandle};

pin_project! {
    #[must_use = "futures do nothing unless you `.await` or poll them"]
    pub struct HeaderPacketsDecrypt {
        #[pin]
        handle: JoinHandle<Result<DecryptedHeaderPackets, Crypt4GHError>>
    }
}

impl HeaderPacketsDecrypt {
  pub fn new(
    header_packets: Vec<Bytes>,
    keys: KeyPair,
    sender_pubkey: Option<PublicKey>,
  ) -> Self {
    Self {
      handle: spawn_blocking(|| {
        HeaderPacketsDecrypt::decrypt(header_packets, keys, sender_pubkey)
      }),
    }
  }

  pub fn decrypt(
    header_packets: Vec<Bytes>,
    keys: Vec<KeyPair>, // FIXME: Not quite right
    sender_pubkey: Option<PublicKey>,
  ) -> Result<DecryptedHeaderPackets, Crypt4GHError> {
    Ok(deconstruct_header_body(
      header_packets
        .into_iter()
        .map(|bytes| bytes.to_vec())
        .collect(),
      keys.as_slice(),
      &sender_pubkey.map(|pubkey| pubkey.into_inner()),
    )?)
  }
}

impl Future for HeaderPacketsDecrypt {
  type Output = Result<DecryptedHeaderPackets, Crypt4GHError>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    self.project().handle.poll(cx).map_err(Crypt4GHError::JoinHandleError)?
  }
}