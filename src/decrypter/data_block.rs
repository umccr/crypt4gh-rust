use std::future::Future;
use std::io::Cursor;
use std::ops::Deref;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use crate::{body_decrypt, WriteInfo};
use pin_project_lite::pin_project;
use tokio::task::JoinHandle;

use crate::decrypter::DecrypterStream;
use crate::error::Crypt4GHError::{Crypt4GHError, JoinHandleError};
use crate::error::Result;

pin_project! {
    #[must_use = "futures do nothing unless you `.await` or poll them"]
    pub struct DataBlockDecrypter {
        #[pin]
        handle: JoinHandle<Result<DecryptedDataBlock>>
    }
}

/// Represents the decrypted data block and its original encrypted size.
#[derive(Debug, Default)]
pub struct DecryptedDataBlock {
  bytes: DecryptedBytes,
  encrypted_size: usize,
}

impl DecryptedDataBlock {
  /// Create a new decrypted data block.
  pub fn new(bytes: DecryptedBytes, encrypted_size: usize) -> Self {
    Self {
      bytes,
      encrypted_size,
    }
  }

  /// Get the plain text bytes.
  pub fn bytes(&self) -> &DecryptedBytes {
    &self.bytes
  }

  /// Get the encrypted size.
  pub fn encrypted_size(&self) -> usize {
    self.encrypted_size
  }

  /// Get the inner bytes and size.
  pub fn into_inner(self) -> (DecryptedBytes, usize) {
    (self.bytes, self.encrypted_size)
  }

  /// Get the length of the decrypted bytes.
  pub const fn len(&self) -> usize {
    self.bytes.len()
  }

  /// Check if the decrypted bytes are empty
  pub const fn is_empty(&self) -> bool {
    self.bytes.is_empty()
  }
}

impl Deref for DecryptedDataBlock {
  type Target = [u8];

  #[inline]
  fn deref(&self) -> &[u8] {
    self.bytes.deref()
  }
}

/// A wrapper around a vec of bytes that represents decrypted data.
#[derive(Debug, Default, Clone)]
pub struct DecryptedBytes(Bytes);

impl DecryptedBytes {
  /// Create new decrypted bytes from bytes.
  pub fn new(bytes: Bytes) -> Self {
    Self(bytes)
  }

  /// Get the inner bytes.
  pub fn into_inner(self) -> Bytes {
    self.0
  }

  /// Get the length of the inner bytes.
  pub const fn len(&self) -> usize {
    self.0.len()
  }

  /// Check if the inner bytes are empty.
  pub const fn is_empty(&self) -> bool {
    self.0.is_empty()
  }
}

impl Deref for DecryptedBytes {
  type Target = [u8];

  #[inline]
  fn deref(&self) -> &[u8] {
    self.0.deref()
  }
}


impl DataBlockDecrypter {
  pub fn new(
    data_block: Bytes,
    session_keys: Vec<Vec<u8>>,
    edit_list_packet: Option<Vec<u64>>,
  ) -> Self {
    Self {
      handle: tokio::task::spawn_blocking(move || {
        DataBlockDecrypter::decrypt(data_block, session_keys, edit_list_packet)
      }),
    }
  }

  pub fn decrypt(
    data_block: Bytes,
    session_keys: Vec<Vec<u8>>,
    edit_list_packet: Option<Vec<u64>>,
  ) -> Result<DecryptedDataBlock> {
    let size = data_block.len();

    let read_buf = Cursor::new(data_block.to_vec());
    let mut write_buf = Cursor::new(vec![]);
    let mut write_info = WriteInfo::new(0, None, &mut write_buf);

    // Todo crypt4gh-rust body_decrypt_parts does not work properly, so just apply edit list here.
    body_decrypt(read_buf, session_keys.as_slice(), &mut write_info, 0)
      .map_err(|err| Crypt4GHError(err.to_string()))?;
    let mut decrypted_bytes: Bytes = write_buf.into_inner().into();
    let mut edited_bytes = Bytes::new();

    let edits = DecrypterStream::<()>::create_internal_edit_list(edit_list_packet)
      .unwrap_or(vec![(false, decrypted_bytes.len() as u64)]);
    if edits.iter().map(|(_, edit)| edit).sum::<u64>() > decrypted_bytes.len() as u64 {
      return Err(Crypt4GHError(
        "invalid edit lists for the decrypted data block".to_string(),
      ));
    }

    edits.into_iter().for_each(|(discarding, edit)| {
      if !discarding {
        let edit = decrypted_bytes.slice(0..edit as usize);
        edited_bytes = [edited_bytes.clone(), edit].concat().into();
      }

      decrypted_bytes = decrypted_bytes.slice(edit as usize..);
    });

    Ok(DecryptedDataBlock::new(
      DecryptedBytes::new(edited_bytes),
      size,
    ))
  }
}

impl Future for DataBlockDecrypter {
  type Output = Result<DecryptedDataBlock>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    self.project().handle.poll(cx).map_err(JoinHandleError)?
  }
}

#[cfg(test)]
mod tests {
  use crate::decoder::tests::{assert_first_data_block, get_data_block};
  //use crate::tests::get_original_file;

  use super::*;

  #[tokio::test]
  async fn data_block_decrypter() {
    let (header_packets, data_block) = get_data_block(0).await;

    let data = DataBlockDecrypter::new(
      data_block,
      header_packets.data_enc_packets,
      header_packets.edit_list_packet,
    )
    .await
    .unwrap();

    assert_first_data_block(data.bytes.to_vec()).await;
  }

  #[tokio::test]
  async fn data_block_decrypter_with_edit_list() {
    let (header_packets, data_block) = get_data_block(0).await;

    let data = DataBlockDecrypter::new(
      data_block,
      header_packets.data_enc_packets,
      Some(vec![0, 4668, 60868]),
    )
    .await
    .unwrap();

    // FIXME: No "file" constructs in this crate!
    //let original_bytes = get_original_file().await;

    //assert_eq!(data.bytes.to_vec(), original_bytes[..4668]);
  }
}
