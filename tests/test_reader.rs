#[cfg(test)]
mod tests {
  use std::io::SeekFrom;

  use futures_util::TryStreamExt;
  use noodles::bam::AsyncReader;
  use noodles::sam::Header;
  use tokio::io::AsyncReadExt;

  use crate::reader::builder::Builder;
  use crate::keys::PublicKey;

  #[tokio::test]
  async fn reader() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut reader = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    let mut decrypted_bytes = vec![];
    reader.read_to_end(&mut decrypted_bytes).await.unwrap();

    let original_bytes = get_original_file().await;
    assert_eq!(decrypted_bytes, original_bytes);
  }

  #[tokio::test]
  async fn reader_with_noodles() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let reader = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    let mut reader = AsyncReader::new(reader);

    let original_file = get_test_file("bam/htsnexus_test_NA12878.bam").await;
    let mut original_reader = AsyncReader::new(original_file);

    let header: Header = reader.read_header().await.unwrap().parse().unwrap();
    let reference_sequences = reader.read_reference_sequences().await.unwrap();

    let original_header: Header = original_reader
      .read_header()
      .await
      .unwrap()
      .parse()
      .unwrap();
    let original_reference_sequences = original_reader.read_reference_sequences().await.unwrap();

    assert_eq!(header, original_header);
    assert_eq!(reference_sequences, original_reference_sequences);

    let mut stream = original_reader.records(&original_header);
    let mut original_records = vec![];
    while let Some(record) = stream.try_next().await.unwrap() {
      original_records.push(record);
    }

    let mut stream = reader.records(&header);
    let mut records = vec![];
    while let Some(record) = stream.try_next().await.unwrap() {
      records.push(record);
    }

    assert_eq!(records, original_records);
  }

  #[tokio::test]
  async fn first_current_block_position() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut reader = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    // Before anything is read the current block should not be known.
    assert_eq!(reader.current_block_position(), None);

    // Read the first byte of the decrypted data.
    let mut buf = [0u8; 1];
    reader.read_exact(&mut buf).await.unwrap();

    // Now the current position should be at the end of the header.
    assert_eq!(reader.current_block_position(), Some(124));
  }

  #[tokio::test]
  async fn first_next_block_position() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut reader = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    // Before anything is read the next block should not be known.
    assert_eq!(reader.next_block_position(), None);

    // Read the first byte of the decrypted data.
    let mut buf = [0u8; 1];
    reader.read_exact(&mut buf).await.unwrap();

    // Now the next position should be at the second data block.
    assert_eq!(reader.next_block_position(), Some(124 + 65564));
  }

  #[tokio::test]
  async fn last_current_block_position() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut reader = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    // Before anything is read the current block should not be known.
    assert_eq!(reader.current_block_position(), None);

    // Read the whole file.
    let mut decrypted_bytes = vec![];
    reader.read_to_end(&mut decrypted_bytes).await.unwrap();

    // Now the current position should be at the last data block.
    assert_eq!(reader.current_block_position(), Some(2598043 - 40923));
  }

  #[tokio::test]
  async fn last_next_block_position() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut reader = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    // Before anything is read the next block should not be known.
    assert_eq!(reader.next_block_position(), None);

    // Read the whole file.
    let mut decrypted_bytes = vec![];
    reader.read_to_end(&mut decrypted_bytes).await.unwrap();

    // Now the next position should be the size of the file.
    assert_eq!(reader.next_block_position(), Some(2598043));
  }

  #[tokio::test]
  async fn seek_first_data_block() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut reader = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    // Before anything is read the block positions should not be known.
    assert_eq!(reader.current_block_position(), None);
    assert_eq!(reader.next_block_position(), None);

    reader.seek_encrypted(SeekFrom::Start(0)).await.unwrap();

    // Now the positions should be at the first data block.
    assert_eq!(reader.current_block_position(), Some(124));
    assert_eq!(reader.next_block_position(), Some(124 + 65564));
  }

  #[tokio::test]
  async fn seek_to_end() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut reader = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    // Before anything is read the block positions should not be known.
    assert_eq!(reader.current_block_position(), None);
    assert_eq!(reader.next_block_position(), None);

    reader
      .seek_encrypted(SeekFrom::Start(2598042))
      .await
      .unwrap();

    // Now the positions should be at the first data block.
    assert_eq!(reader.current_block_position(), Some(2598043 - 40923));
    assert_eq!(reader.next_block_position(), Some(2598043));
  }

  #[tokio::test]
  async fn seek_past_end() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut reader = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    // Before anything is read the block positions should not be known.
    assert_eq!(reader.current_block_position(), None);
    assert_eq!(reader.next_block_position(), None);

    reader
      .seek_encrypted(SeekFrom::Start(2598044))
      .await
      .unwrap();

    // Now the positions should be at the first data block.
    assert_eq!(reader.current_block_position(), Some(2598043));
    assert_eq!(reader.next_block_position(), Some(2598043));
  }

  #[tokio::test]
  async fn seek_past_end_stream_length_override() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut reader = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .with_stream_length(2598043)
      .build_with_reader(src, vec![recipient_private_key]);

    // Before anything is read the block positions should not be known.
    assert_eq!(reader.current_block_position(), None);
    assert_eq!(reader.next_block_position(), None);

    reader
      .seek_encrypted(SeekFrom::Start(2598044))
      .await
      .unwrap();

    // Now the positions should be at the first data block.
    assert_eq!(reader.current_block_position(), Some(2598043));
    assert_eq!(reader.next_block_position(), Some(2598043));
  }

  #[tokio::test]
  async fn advance_first_data_block() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut reader = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    // Before anything is read the block positions should not be known.
    assert_eq!(reader.current_block_position(), None);
    assert_eq!(reader.next_block_position(), None);

    reader.advance_encrypted(0).await.unwrap();

    // Now the positions should be at the first data block.
    assert_eq!(reader.current_block_position(), Some(124));
    assert_eq!(reader.next_block_position(), Some(124 + 65564));
  }

  #[tokio::test]
  async fn advance_to_end() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut reader = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    // Before anything is read the block positions should not be known.
    assert_eq!(reader.current_block_position(), None);
    assert_eq!(reader.next_block_position(), None);

    reader.advance_encrypted(2598042).await.unwrap();

    // Now the positions should be at the first data block.
    assert_eq!(reader.current_block_position(), Some(2598043 - 40923));
    assert_eq!(reader.next_block_position(), Some(2598043));
  }

  #[tokio::test]
  async fn advance_past_end() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut reader = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    // Before anything is read the block positions should not be known.
    assert_eq!(reader.current_block_position(), None);
    assert_eq!(reader.next_block_position(), None);

    reader.advance_encrypted(2598044).await.unwrap();

    // Now the positions should be at the first data block.
    assert_eq!(reader.current_block_position(), Some(2598043));
    assert_eq!(reader.next_block_position(), Some(2598043));
  }

  #[tokio::test]
  async fn advance_past_end_stream_length_override() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut reader = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .with_stream_length(2598043)
      .build_with_reader(src, vec![recipient_private_key]);

    // Before anything is read the block positions should not be known.
    assert_eq!(reader.current_block_position(), None);
    assert_eq!(reader.next_block_position(), None);

    reader.advance_encrypted(2598044).await.unwrap();

    // Now the positions should be at the first data block.
    assert_eq!(reader.current_block_position(), Some(2598043));
    assert_eq!(reader.next_block_position(), Some(2598043));
  }

  #[tokio::test]
  async fn seek_first_data_block_unencrypted() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut reader = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    // Before anything is read the block positions should not be known.
    assert_eq!(reader.current_block_position(), None);
    assert_eq!(reader.next_block_position(), None);

    reader.seek_unencrypted(0).await.unwrap();

    // Now the positions should be at the first data block.
    assert_eq!(reader.current_block_position(), Some(124));
    assert_eq!(reader.next_block_position(), Some(124 + 65564));
  }

  #[tokio::test]
  async fn seek_to_end_unencrypted() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut reader = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    // Before anything is read the block positions should not be known.
    assert_eq!(reader.current_block_position(), None);
    assert_eq!(reader.next_block_position(), None);

    reader.seek_unencrypted(2596799).await.unwrap();

    // Now the positions should be at the first data block.
    assert_eq!(reader.current_block_position(), Some(2598043 - 40923));
    assert_eq!(reader.next_block_position(), Some(2598043));
  }

  #[tokio::test]
  async fn seek_past_end_unencrypted() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut reader = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    // Before anything is read the block positions should not be known.
    assert_eq!(reader.current_block_position(), None);
    assert_eq!(reader.next_block_position(), None);

    reader.seek_unencrypted(2596800).await.unwrap();

    // Now the positions should be at the first data block.
    assert_eq!(reader.current_block_position(), Some(2598043));
    assert_eq!(reader.next_block_position(), Some(2598043));
  }

  #[tokio::test]
  async fn seek_past_end_unencrypted_stream_length_override() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut reader = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .with_stream_length(2598043)
      .build_with_reader(src, vec![recipient_private_key]);

    // Before anything is read the block positions should not be known.
    assert_eq!(reader.current_block_position(), None);
    assert_eq!(reader.next_block_position(), None);

    reader.seek_unencrypted(2596800).await.unwrap();

    // Now the positions should be at the first data block.
    assert_eq!(reader.current_block_position(), Some(2598043));
    assert_eq!(reader.next_block_position(), Some(2598043));
  }

  #[tokio::test]
  async fn advance_first_data_block_unencrypted() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut reader = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    // Before anything is read the block positions should not be known.
    assert_eq!(reader.current_block_position(), None);
    assert_eq!(reader.next_block_position(), None);

    reader.advance_unencrypted(0).await.unwrap();

    // Now the positions should be at the first data block.
    assert_eq!(reader.current_block_position(), Some(124));
    assert_eq!(reader.next_block_position(), Some(124 + 65564));
  }

  #[tokio::test]
  async fn advance_to_end_unencrypted() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut reader = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    // Before anything is read the block positions should not be known.
    assert_eq!(reader.current_block_position(), None);
    assert_eq!(reader.next_block_position(), None);

    reader.advance_unencrypted(2596799).await.unwrap();

    // Now the positions should be at the first data block.
    assert_eq!(reader.current_block_position(), Some(2598043 - 40923));
    assert_eq!(reader.next_block_position(), Some(2598043));
  }

  #[tokio::test]
  async fn advance_past_end_unencrypted() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut reader = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    // Before anything is read the block positions should not be known.
    assert_eq!(reader.current_block_position(), None);
    assert_eq!(reader.next_block_position(), None);

    reader.advance_unencrypted(2596800).await.unwrap();

    // Now the positions should be at the first data block.
    assert_eq!(reader.current_block_position(), Some(2598043));
    assert_eq!(reader.next_block_position(), Some(2598043));
  }

  #[tokio::test]
  async fn advance_past_end_unencrypted_stream_length_override() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut reader = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .with_stream_length(2598043)
      .build_with_reader(src, vec![recipient_private_key]);

    // Before anything is read the block positions should not be known.
    assert_eq!(reader.current_block_position(), None);
    assert_eq!(reader.next_block_position(), None);

    reader.advance_unencrypted(2596800).await.unwrap();

    // Now the positions should be at the first data block.
    assert_eq!(reader.current_block_position(), Some(2598043));
    assert_eq!(reader.next_block_position(), Some(2598043));
  }
}