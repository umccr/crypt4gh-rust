#[cfg(test)]
pub(crate) mod tests {
  use std::io::Cursor;

  use crate::header::{deconstruct_header_body, DecryptedHeaderPackets};
  use crate::{body_decrypt, Keys, WriteInfo};
  use futures_util::stream::Skip;
  use futures_util::StreamExt;
  use tokio::io::AsyncReadExt;
  use tokio_util::codec::FramedRead;
  use super::*;

  #[tokio::test]
  async fn decode_header_info() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let mut reader = FramedRead::new(src, Block::default());

    let header_info = reader.next().await.unwrap().unwrap();

    // Assert that the first block output is a header info with one packet.
    assert!(
      matches!(header_info, DecodedBlock::HeaderInfo(header_info) if header_info.packets_count == 1)
    );
  }

  #[tokio::test]
  async fn decode_header_packets() {
    let (recipient_private_key, sender_public_key, header_packet, _) =
      get_first_header_packet().await;
    let header = get_header_packets(recipient_private_key, sender_public_key, header_packet);

    assert_first_header_packet(header);

    // Todo handle case where there is more than one header packet.
  }

  #[tokio::test]
  async fn decode_data_block() {
    let (header, data_block) = get_data_block(0).await;

    let read_buf = Cursor::new(data_block.to_vec());
    let mut write_buf = Cursor::new(vec![]);
    let mut write_info = WriteInfo::new(0, None, &mut write_buf);

    body_decrypt(read_buf, &header.data_enc_packets, &mut write_info, 0).unwrap();

    let decrypted_bytes = write_buf.into_inner();

    assert_first_data_block(decrypted_bytes).await;
  }

  #[tokio::test]
  async fn decode_eof() {
    let (header, data_block) = get_data_block(39).await;

    let read_buf = Cursor::new(data_block.to_vec());
    let mut write_buf = Cursor::new(vec![]);
    let mut write_info = WriteInfo::new(0, None, &mut write_buf);

    body_decrypt(read_buf, &header.data_enc_packets, &mut write_info, 0).unwrap();

    let decrypted_bytes = write_buf.into_inner();

    assert_last_data_block(decrypted_bytes).await;
  }

  /// Assert that the first header packet is a data encryption key packet.
  pub(crate) fn assert_first_header_packet(header: DecryptedHeaderPackets) {
    assert_eq!(header.data_enc_packets.len(), 1);
    assert!(header.edit_list_packet.is_none());
  }

  /// Assert that the last data block is equal to the expected ending bytes of the original file.
  pub(crate) async fn assert_last_data_block(decrypted_bytes: Vec<u8>) {
    let mut original_file = get_test_file("bam/htsnexus_test_NA12878.bam").await;
    let mut original_bytes = vec![];
    original_file
      .read_to_end(&mut original_bytes)
      .await
      .unwrap();

    assert_eq!(
      decrypted_bytes,
      original_bytes
        .into_iter()
        .rev()
        .take(40895)
        .rev()
        .collect::<Vec<u8>>()
    );
  }

  /// Assert that the first data block is equal to the first 64KiB of the original file.
  pub(crate) async fn assert_first_data_block(decrypted_bytes: Vec<u8>) {
    let original_bytes = get_original_file().await;

    assert_eq!(decrypted_bytes, original_bytes[..65536]);
  }

  /// Get the first header packet from the test file.
  pub(crate) async fn get_first_header_packet(
  ) -> (Keys, Vec<u8>, Vec<Bytes>, Skip<FramedRead<File, Block>>) {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut reader = FramedRead::new(src, Block::default()).skip(1);

    // The second block should contain a header packet.
    let header_packets = reader.next().await.unwrap().unwrap();

    let (header_packet, header_length) =
      if let DecodedBlock::HeaderPackets(header_packets) = header_packets {
        Some(header_packets)
      } else {
        None
      }
      .unwrap()
      .into_inner();

    assert_eq!(header_length, 108);

    (
      recipient_private_key,
      sender_public_key,
      header_packet
        .into_iter()
        .map(|packet| packet.into_header_bytes())
        .collect(),
      reader,
    )
  }

  /// Get the first data block from the test file.
  pub(crate) async fn get_data_block(skip: usize) -> (DecryptedHeaderPackets, Bytes) {
    let (recipient_private_key, sender_public_key, header_packets, reader) =
      get_first_header_packet().await;
    let header = get_header_packets(recipient_private_key, sender_public_key, header_packets);

    let data_block = reader.skip(skip).next().await.unwrap().unwrap();

    let data_block = if let DecodedBlock::DataBlock(data_block) = data_block {
      Some(data_block)
    } else {
      None
    }
    .unwrap();

    (header, data_block)
  }

  /// Get the header packets from a decoded block.
  pub(crate) fn get_header_packets(
    recipient_private_key: Keys,
    sender_public_key: Vec<u8>,
    header_packets: Vec<Bytes>,
  ) -> DecryptedHeaderPackets {
    // Assert the size of the header packet is correct.
    assert_eq!(header_packets.len(), 1);
    assert_eq!(header_packets.first().unwrap().len(), 104);

    deconstruct_header_body(
      header_packets
        .into_iter()
        .map(|header_packet| header_packet.to_vec())
        .collect(),
      &[recipient_private_key],
      &Some(sender_public_key),
    )
    .unwrap()
  }
}