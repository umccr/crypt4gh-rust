use std::cmp::min;
use std::io;
use std::io::SeekFrom;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use crate::header::{EncryptedHeaderPacketBytes, HeaderInfo};
use crate::Keys;
use futures::ready;
use futures::Stream;
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncSeek, AsyncSeekExt};
use tokio_util::codec::FramedRead;

use crate::decoder::Block;
use crate::decoder::DecodedBlock;
use crate::decrypter::data_block::DataBlockDecrypter;
use crate::decrypter::header::packets::HeaderPacketsDecrypter;
use crate::decrypter::header::SessionKeysFuture;
use crate::error::Crypt4GHError;
use crate::{util, keys::PublicKey};

pub mod builder;
pub mod data_block;
pub mod header;

pin_project! {
    /// A decrypter for an entire AsyncRead Crypt4GH file.
    pub struct DecrypterStream<R> {
        #[pin]
        inner: FramedRead<R, Block>,
        #[pin]
        header_packet_future: Option<HeaderPacketsDecrypter>,
        keys: Vec<Keys>,
        sender_pubkey: Option<PublicKey>,
        encrypted_header_packets: Option<Vec<EncryptedHeaderPacketBytes>>,
        header_info: Option<HeaderInfo>,
        session_keys: Vec<Vec<u8>>,
        edit_list_packet: Option<Vec<(bool, u64)>>,
        header_length: Option<u64>,
        current_block_size: Option<usize>,
        stream_length: Option<u64>,
    }
}

impl<R> DecrypterStream<R>
where
  R: AsyncRead,
{
  /// Partitions the edit list packet so that it applies to the current data block, returning a new
  /// edit list that correctly discards and keeps the specified bytes this particular data block.
  /// Todo, this should possibly go into the decoder, where bytes can be skipped directly.
  pub fn partition_edit_list(mut self: Pin<&mut Self>, data_block: &Bytes) -> Option<Vec<u64>> {
    let this = self.as_mut().project();

    if let Some(edit_list) = this.edit_list_packet {
      let mut new_edit_list = vec![];
      let mut bytes_consumed = 0;

      edit_list.retain_mut(|(discarding, value)| {
        // If this is not a discarding edit, then discard 0 at the start.
        if !*discarding && new_edit_list.is_empty() {
          new_edit_list.push(0);
        }

        // Get the encrypted block size.
        let data_block_len = data_block.len() as u64 - Block::nonce_size() - Block::mac_size();

        // Can only consume as many bytes as there are in the data block.
        if min(bytes_consumed + *value, data_block_len) == data_block_len {
          if bytes_consumed != data_block_len {
            // If the whole data block hasn't been consumed yet, an edit still needs to be added.
            let last_edit = data_block_len - bytes_consumed;
            new_edit_list.push(last_edit);

            // And remove this edit from the next value.
            *value -= last_edit;
            // Now the whole data block has been consumed.
            bytes_consumed = data_block_len;
          }

          // Keep all values from now.
          true
        } else {
          // Otherwise, consume the value and remove it from the edit list packet.
          bytes_consumed += *value;
          new_edit_list.push(*value);
          false
        }
      });

      (!new_edit_list.is_empty()).then_some(new_edit_list)
    } else {
      // If there is no edit list to begin with, we just keep the whole block.
      None
    }
  }

  /// Polls a data block. This function shouldn't execute until all the header packets have been
  /// processed.
  pub fn poll_data_block(
    mut self: Pin<&mut Self>,
    data_block: Bytes,
  ) -> Poll<Option<Result<DataBlockDecrypter, Crypt4GHError>>> {
    let edit_list = self.as_mut().partition_edit_list(&data_block);

    let this = self.project();
    Poll::Ready(Some(Ok(DataBlockDecrypter::new(
      data_block,
      // Todo make this so it doesn't use owned Keys and SenderPublicKey as it will be called asynchronously.
      this.session_keys.clone(),
      edit_list,
    ))))
  }

  /// Poll the stream until the header packets and session keys are processed.
  pub fn poll_session_keys(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Crypt4GHError>> {
    // Only execute this function if there are no session keys.
    if !self.session_keys.is_empty() {
      return Poll::Ready(Ok(()));
    }

    // Header packets are waiting to be decrypted.
    if let Some(header_packet_decrypter) = self.as_mut().project().header_packet_future.as_pin_mut()
    {
      return match ready!(header_packet_decrypter.poll(cx)) {
        Ok(header_packets) => {
          let mut this = self.as_mut().project();

          // Update the session keys and edit list packets.
          this.header_packet_future.set(None);
          this.session_keys.extend(header_packets.data_enc_packets);
          if this.edit_list_packet.is_none() {
            *this.edit_list_packet =
              Self::create_internal_edit_list(header_packets.edit_list_packet);
          }

          Poll::Ready(Ok(()))
        }
        Err(err) => Poll::Ready(Err(err)),
      };
    }

    // No header packets yet, so more data needs to be decoded.
    let mut this = self.as_mut().project();
    match ready!(this.inner.poll_next(cx)) {
      Some(Ok(buf)) => match buf {
        DecodedBlock::HeaderInfo(header_info) => {
          // Store the header info but otherwise ignore it and poll again.
          *this.header_info = Some(header_info);
          cx.waker().wake_by_ref();
          Poll::Pending
        }
        // todo no clones here.
        DecodedBlock::HeaderPackets(header_packets) => {
          // Update the header length because we have access to the header packets.
          let (header_packets, header_length) = header_packets.into_inner();
          *this.encrypted_header_packets = Some(header_packets.clone());
          *this.header_length = Some(header_length + Block::header_info_size());

          // Add task for decrypting the header packets.
          this
            .header_packet_future
            .set(Some(HeaderPacketsDecrypter::new(
              header_packets
                .into_iter()
                .map(|packet| packet.into_header_bytes())
                .collect(),
              this.keys.clone(),
              this.sender_pubkey.clone(),
            )));

          // Poll again.
          cx.waker().wake_by_ref();
          Poll::Pending
        }
        DecodedBlock::DataBlock(_) => Poll::Ready(Err(Crypt4GHError(
          "data block reached without finding session keys".to_string(),
        ))),
      },
      Some(Err(e)) => Poll::Ready(Err(e)),
      None => Poll::Ready(Err(Crypt4GHError(
        "end of stream reached without finding session keys".to_string(),
      ))),
    }
  }

  /// Convenience for calling [`poll_session_keys`] on [`Unpin`] types.
  pub fn poll_session_keys_unpin(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Crypt4GHError>>
  where
    Self: Unpin,
  {
    Pin::new(self).poll_session_keys(cx)
  }

  /// Poll the stream until the header has been read.
  pub async fn read_header(&mut self) -> Result<(), Crypt4GHError>
  where
    R: Unpin,
  {
    SessionKeysFuture::new(self).await
  }
}

impl<R> DecrypterStream<R> {
  /// An override for setting the stream length.
  pub async fn set_stream_length(&mut self, length: u64) {
    self.stream_length = Some(length);
  }

  /// Get a reference to the inner reader.
  pub fn get_ref(&self) -> &R {
    self.inner.get_ref()
  }

  /// Get a mutable reference to the inner reader.
  pub fn get_mut(&mut self) -> &mut R {
    self.inner.get_mut()
  }

  /// Get a pinned mutable reference to the inner reader.
  pub fn get_pin_mut(self: Pin<&mut Self>) -> Pin<&mut R> {
    self.project().inner.get_pin_mut()
  }

  /// Get the inner reader.
  pub fn into_inner(self) -> R {
    self.inner.into_inner()
  }

  /// Get the length of the header, including the magic string, version number, packet count
  /// and the header packets. Returns `None` before the header packet is polled.
  pub fn header_size(&self) -> Option<u64> {
    self.header_length
  }

  /// Get the size of the current data block represented by the encrypted block returned by calling
  /// poll_next. This will equal `decoder::DATA_BLOCK_SIZE` except for the last block which may be
  /// less than that. Returns `None` before the first data block is polled.
  pub fn current_block_size(&self) -> Option<usize> {
    self.current_block_size
  }

  /// Clamps the byte position to the nearest data block if the header length is known. This
  /// function takes into account the stream length if it is present.
  pub fn clamp_position(&self, position: u64) -> Option<u64> {
    self.header_size().map(|length| {
      if position < length {
        length
      } else {
        match self.stream_length {
          Some(end_length) if position >= end_length => end_length,
          _ => {
            let remainder = (position - length) % Block::standard_data_block_size();

            position - remainder
          }
        }
      }
    })
  }

  /// Convert an unencrypted position to an encrypted position if the header length is known.
  pub fn to_encrypted(&self, position: u64) -> Option<u64> {
    self.header_size().map(|length| {
      let encrypted_position = util::to_encrypted(position, length);

      match self.stream_length {
        Some(end_length) if encrypted_position + Block::mac_size() > end_length => end_length,
        _ => encrypted_position,
      }
    })
  }

  /// Get the session keys. Empty before the header is polled.
  pub fn session_keys(&self) -> &[Vec<u8>] {
    &self.session_keys
  }

  /// Get the edit list packet. Empty before the header is polled.
  pub fn edit_list_packet(&self) -> Option<Vec<u64>> {
    self
      .edit_list_packet
      .as_ref()
      .map(|packet| packet.iter().map(|(_, edit)| *edit).collect())
  }

  /// Get the header info.
  pub fn header_info(&self) -> Option<&HeaderInfo> {
    self.header_info.as_ref()
  }

  /// Get the original encrypted header packets, not including the header info.
  pub fn encrypted_header_packets(&self) -> Option<&Vec<EncryptedHeaderPacketBytes>> {
    self.encrypted_header_packets.as_ref()
  }

  /// Get the stream's keys.
  pub fn keys(&self) -> &[Keys] {
    self.keys.as_slice()
  }

  pub(crate) fn create_internal_edit_list(edit_list: Option<Vec<u64>>) -> Option<Vec<(bool, u64)>> {
    edit_list.map(|edits| [true, false].iter().cloned().cycle().zip(edits).collect())
  }
}

impl<R> DecrypterStream<R>
where
  R: AsyncRead + AsyncSeek + Unpin,
{
  /// Recompute the stream length. Having a stream length means that data block positions past the
  /// end of the stream will be valid and will equal the the length of the stream. By default this
  /// struct contains no stream length when it is initialized.
  ///
  /// This can take up to 3 seek calls. If the size of the underlying buffer changes, this function
  /// should be called again, otherwise data block positions may not be valid.
  pub async fn recompute_stream_length(&mut self) -> Result<u64, Crypt4GHError> {
    let inner = self.inner.get_mut();

    let position = inner.seek(SeekFrom::Current(0)).await?;
    let length = inner.seek(SeekFrom::End(0)).await?;

    if position != length {
      inner.seek(SeekFrom::Start(position)).await?;
    }

    self.stream_length = Some(length);

    Ok(length)
  }
}

impl<R> Stream for DecrypterStream<R>
where
  R: AsyncRead,
{
  type Item = Result<DataBlockDecrypter, Crypt4GHError>;

  fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
    // When polling, we first need to process enough data to get the session keys.
    if let Err(err) = ready!(self.as_mut().poll_session_keys(cx)) {
      return Poll::Ready(Some(Err(err)));
    }

    let this = self.as_mut().project();
    let item = this.inner.poll_next(cx);

    match ready!(item) {
      Some(Ok(buf)) => match buf {
        DecodedBlock::HeaderInfo(_) | DecodedBlock::HeaderPackets(_) => {
          // Session keys have already been read, so ignore the header info and header packets
          // and poll again
          cx.waker().wake_by_ref();
          Poll::Pending
        }
        DecodedBlock::DataBlock(data_block) => {
          // The new size of the data block is available, so update it.
          *this.current_block_size = Some(data_block.len());

          // Session keys have been obtained so process the data blocks.
          self.poll_data_block(data_block)
        }
      },
      Some(Err(e)) => Poll::Ready(Some(Err(e))),
      None => Poll::Ready(None),
    }
  }
}

impl<R> DecrypterStream<R>
where
  R: AsyncRead + AsyncSeek + Unpin + Send,
{
  /// Seek to a position in the encrypted stream.
  pub async fn seek_encrypted(&mut self, position: SeekFrom) -> io::Result<u64> {
    // Make sure that session keys are polled.
    self.read_header().await?;

    // First poll to the position specified.
    let seek = self.inner.get_mut().seek(position).await?;

    // Then advance to the correct data block position.
    let advance = self.advance_encrypted(seek).await?;

    // Then seek to the correct position.
    let seek = self.inner.get_mut().seek(SeekFrom::Start(advance)).await?;
    self.inner.read_buffer_mut().clear();

    Ok(seek)
  }

  /// Seek to a position in the unencrypted stream.
  pub async fn seek_unencrypted(&mut self, position: u64) -> io::Result<u64> {
    // Make sure that session keys are polled.
    self.read_header().await?;

    // Convert to an encrypted position and seek
    let position = self
      .to_encrypted(position)
      .ok_or_else(|| Crypt4GHError("Unable to convert to encrypted position.".to_string()))?;

    // Then do the seek.
    self.seek_encrypted(SeekFrom::Start(position)).await
  }
}