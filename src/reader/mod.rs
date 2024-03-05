use std::io::SeekFrom;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{cmp, io};

use crate::decoder::DecodedBlock::HeaderInfo;
use crate::keys::KeyPairInfo;
use futures::ready;
use futures::stream::TryBuffered;
use futures::Stream;
use pin_project_lite::pin_project;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncSeek, ReadBuf};

use crate::decoder::Block;
use crate::error::Crypt4GHError::{self, NumericConversionError};
use crate::reader::builder::Builder;
use crate::{DecryptedDataBlock, header::EncryptedHeaderPacketBytes};

use super::decrypter::DecrypterStream;

pub mod builder;

pin_project! {
    pub struct Reader<R>
      where R: AsyncRead
    {
      #[pin]
      stream: TryBuffered<DecrypterStream<R>>,
      current_block: DecryptedDataBlock,
      // The current position in the decrypted buffer.
      buf_position: usize,
      // The encrypted position of the current data block minus the size of the header.
      block_position: Option<u64>
    }
}

impl<R> Reader<R>
where
  R: AsyncRead,
{
  /// Gets the position of the data block which includes the current position of the underlying
  /// reader. This function will return a value that always corresponds the beginning of a data
  /// block or `None` if the reader has not read any bytes.
  pub fn current_block_position(&self) -> Option<u64> {
    self.block_position
  }

  /// Gets the position of the next data block from the current position of the underlying reader.
  /// This function will return a value that always corresponds the beginning of a data block, the
  /// size of the file, or `None` if the reader has not read any bytes.
  pub fn next_block_position(&self) -> Option<u64> {
    self.block_position.and_then(|block_position| {
      self
        .stream
        .get_ref()
        .clamp_position(block_position + Block::standard_data_block_size())
    })
  }

  /// Get a reference to the inner reader.
  pub fn get_ref(&self) -> &R {
    self.stream.get_ref().get_ref()
  }

  /// Get a mutable reference to the inner reader.
  pub fn get_mut(&mut self) -> &mut R {
    self.stream.get_mut().get_mut()
  }

  /// Get a pinned mutable reference to the inner reader.
  pub fn get_pin_mut(self: Pin<&mut Self>) -> Pin<&mut R> {
    self.project().stream.get_pin_mut().get_pin_mut()
  }

  /// Get the inner reader.
  pub fn into_inner(self) -> R {
    self.stream.into_inner().into_inner()
  }

  /// Get the session keys. Empty before the header is polled.
  pub fn session_keys(&self) -> &[Vec<u8>] {
    self.stream.get_ref().session_keys()
  }

  /// Get the edit list packet. Empty before the header is polled.
  pub fn edit_list_packet(&self) -> Option<Vec<u64>> {
    self.stream.get_ref().edit_list_packet()
  }

  /// Get the header info.
  pub fn header_info(&self) -> Option<&HeaderInfo> {
    self.stream.get_ref().header_info()
  }

  /// Get the header size
  pub fn header_size(&self) -> Option<u64> {
    self.stream.get_ref().header_size()
  }

  /// Get the original encrypted header packets, not including the header info.
  pub fn encrypted_header_packets(&self) -> Option<&Vec<EncryptedHeaderPacketBytes>> {
    self.stream.get_ref().encrypted_header_packets()
  }

  /// Poll the reader until the header has been read.
  pub async fn read_header(&mut self) -> Result<(), Crypt4GHError>
  where
    R: Unpin,
  {
    self.stream.get_mut().read_header().await
  }

  /// Get the reader's keys.
  pub fn keys(&self) -> &[KeyPairInfo] {
    self.stream.get_ref().keys()
  }
}

impl<R> From<DecrypterStream<R>> for Reader<R>
where
  R: AsyncRead,
{
  fn from(stream: DecrypterStream<R>) -> Self {
    Builder::default().build_with_stream(stream)
  }
}

impl<R> AsyncRead for Reader<R>
where
  R: AsyncRead,
{
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    // Defer to poll_fill_buf to do the read.
    let src = ready!(self.as_mut().poll_fill_buf(cx))?;

    // Calculate the correct amount to read and copy over to the read buf.
    let amt = cmp::min(src.len(), buf.remaining());
    buf.put_slice(&src[..amt]);

    // Inform the internal buffer that amt has been consumed.
    self.consume(amt);

    Poll::Ready(Ok(()))
  }
}

impl<R> AsyncBufRead for Reader<R>
where
  R: AsyncRead,
{
  fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
    let this = self.project();

    // If this is the beginning of the stream, set the block position to the header length, if any.
    if let (None, length @ Some(_)) = (
      this.block_position.as_ref(),
      this.stream.get_ref().header_size(),
    ) {
      *this.block_position = length;
    }

    // If the position is past the end of the buffer, then all the data has been read and a new
    // buffer should be initialised.
    if *this.buf_position >= this.current_block.len() {
      match ready!(this.stream.poll_next(cx)) {
        Some(Ok(block)) => {
          // Update the block position with the previous block size.
          *this.block_position = Some(
            this.block_position.unwrap_or_default()
              + u64::try_from(this.current_block.encrypted_size())
                .map_err(|_| NumericConversionError)?,
          );

          // We have a new buffer, reinitialise the position and buffer.
          *this.current_block = block;
          *this.buf_position = 0;
        }
        Some(Err(e)) => return Poll::Ready(Err(e.into())),
        None => return Poll::Ready(Ok(&[])),
      }
    }

    // Return the unconsumed data from the buffer.
    Poll::Ready(Ok(&this.current_block[*this.buf_position..]))
  }

  fn consume(self: Pin<&mut Self>, amt: usize) {
    let this = self.project();
    // Update the buffer position until the consumed amount reaches the end of the buffer.
    *this.buf_position = cmp::min(*this.buf_position + amt, this.current_block.len());
  }
}

impl<R> Reader<R>
where
  R: AsyncRead + AsyncSeek + Unpin + Send,
{
  /// Seek to a position in the encrypted stream.
  pub async fn seek_encrypted(&mut self, position: SeekFrom) -> io::Result<u64> {
    let position = self.stream.get_mut().seek_encrypted(position).await?;

    self.block_position = Some(position);

    Ok(position)
  }

  /// Seek to a position in the unencrypted stream.
  pub async fn seek_unencrypted(&mut self, position: u64) -> io::Result<u64> {
    let position = self.stream.get_mut().seek_unencrypted(position).await?;

    self.block_position = Some(position);

    Ok(position)
  }
}