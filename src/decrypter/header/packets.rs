use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use crate::header::{DecryptedHeaderPackets, Header};
use pin_project_lite::pin_project;
use tokio::task::{spawn_blocking, JoinHandle};

use crate::error::Crypt4GHError::{self, JoinHandleError};
use crate::keys::{KeyPairInfo, PublicKey};

pin_project! {
    #[must_use = "futures do nothing unless you `.await` or poll them"]
    pub struct HeaderPacketsDecrypter {
        #[pin]
        handle: JoinHandle<Result<DecryptedHeaderPackets, Crypt4GHError>>
    }
}

impl HeaderPacketsDecrypter {
  pub fn new(
    header_packets: Vec<Bytes>,
    keys: Vec<KeyPairInfo>,
    sender_pubkey: Option<PublicKey>,
  ) -> Self {
    Self {
      handle: spawn_blocking(|| {
        HeaderPacketsDecrypter::decrypt(header_packets, keys, sender_pubkey)
      }),
    }
  }

  pub fn decrypt(
    header_packets: Vec<Bytes>,
    keys: Vec<KeyPairInfo>,
    sender_pubkey: Option<PublicKey>,
  ) -> Result<DecryptedHeaderPackets, Crypt4GHError> {
    let header = Header::new_from_bytes(header_packets.as_slice());

    
    Ok(deserialize_header_info(
      header_packets
        .into_iter()
        .map(|bytes| bytes.to_vec())
        .collect(),
      keys.as_slice(),
      &sender_pubkey.map(|pubkey| pubkey.into_inner())
    ))
  }
}

impl Future for HeaderPacketsDecrypter {
  type Output = Result<DecryptedHeaderPackets, Crypt4GHError>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    self.project().handle.poll(cx).map_err(JoinHandleError)?
  }
}