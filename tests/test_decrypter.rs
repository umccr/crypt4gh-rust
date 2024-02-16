// FIXME: Test suite highly dependent on fs and File(s), migrate to Bytes and/or Streams instead
#[cfg(test)]
mod tests {
  use bytes::BytesMut;
  use futures_util::future::join_all;
  use futures_util::StreamExt;
  // use tokio::fs::File;

  use crate::decoder::tests::assert_last_data_block;
  use crate::decrypter::builder::Builder;
  // use crate::tests::get_original_file;

  use super::*;

  #[tokio::test]
  async fn partition_edit_lists() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut stream = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .with_edit_list(vec![60113, 100000, 65536])
      .build(src, vec![recipient_private_key]);

    assert_edit_list(&mut stream, Some(vec![60113, 5423]), vec![0; 65564]);
    assert_edit_list(&mut stream, Some(vec![0, 65536]), vec![0; 65564]);
    assert_edit_list(&mut stream, Some(vec![0, 29041, 36495]), vec![0; 65564]);
    assert_edit_list(&mut stream, Some(vec![29041]), vec![0; 29041 + 12 + 16]);
  }

  fn assert_edit_list(
    stream: &mut DecrypterStream<File>, // FIXME: No files!
    expected: Option<Vec<u64>>,
    bytes: Vec<u8>,
  ) {
    let stream = Pin::new(stream);
    let edit_list = stream.partition_edit_list(&Bytes::from(bytes));
    assert_eq!(edit_list, expected);
  }

  #[tokio::test]
  async fn decrypter_stream() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut stream = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    let mut futures = vec![];
    while let Some(block) = stream.next().await {
      futures.push(block.unwrap());
    }

    let decrypted_bytes =
      join_all(futures)
        .await
        .into_iter()
        .fold(BytesMut::new(), |mut acc, bytes| {
          let (bytes, _) = bytes.unwrap().into_inner();
          acc.extend(bytes.0);
          acc
        });

    // Assert that the decrypted bytes are equal to the original file bytes.
    let original_bytes = get_original_file().await;
    assert_eq!(decrypted_bytes, original_bytes);
  }

  #[tokio::test]
  async fn get_header_length() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut stream = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    assert!(stream.header_size().is_none());

    let _ = stream.next().await.unwrap().unwrap().await;

    assert_eq!(stream.header_size(), Some(124));
  }

  #[tokio::test]
  async fn first_block_size() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut stream = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    assert!(stream.current_block_size().is_none());

    let _ = stream.next().await.unwrap().unwrap().await;

    assert_eq!(stream.current_block_size(), Some(65564));
  }

  #[tokio::test]
  async fn last_block_size() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let stream = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    assert!(stream.current_block_size().is_none());

    let mut stream = stream.skip(39);
    let _ = stream.next().await.unwrap().unwrap().await;

    assert_eq!(stream.get_ref().current_block_size(), Some(40923));
  }

  #[tokio::test]
  async fn clamp_position_first_data_block() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut stream = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    let _ = stream.next().await.unwrap().unwrap().await;

    assert_eq!(stream.clamp_position(0), Some(124));
    assert_eq!(stream.clamp_position(124), Some(124));
    assert_eq!(stream.clamp_position(200), Some(124));
  }

  #[tokio::test]
  async fn clamp_position_second_data_block() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut stream = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    let _ = stream.next().await.unwrap().unwrap().await;

    assert_eq!(stream.clamp_position(80000), Some(124 + 65564));
  }

  #[tokio::test]
  async fn clamp_position_past_end() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut stream = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();
    let _ = stream.next().await.unwrap().unwrap().await;

    assert_eq!(stream.clamp_position(2598044), Some(2598043));
  }

  #[tokio::test]
  async fn convert_position_first_data_block() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut stream = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    let _ = stream.next().await.unwrap().unwrap().await;

    let pos = stream.to_encrypted(0);
    assert_eq!(pos, Some(124));
    assert_eq!(stream.clamp_position(pos.unwrap()), Some(124));

    let pos = stream.to_encrypted(200);
    assert_eq!(pos, Some(124 + 12 + 200));
    assert_eq!(stream.clamp_position(pos.unwrap()), Some(124));
  }

  #[tokio::test]
  async fn convert_position_second_data_block() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut stream = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    let _ = stream.next().await.unwrap().unwrap().await;

    let pos = stream.to_encrypted(80000);
    assert_eq!(pos, Some(124 + 65564 + 12 + (80000 - 65536)));
    assert_eq!(stream.clamp_position(pos.unwrap()), Some(124 + 65564));
  }

  #[tokio::test]
  async fn convert_position_past_end() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut stream = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();
    let _ = stream.next().await.unwrap().unwrap().await;

    let pos = stream.to_encrypted(2596800);
    assert_eq!(pos, Some(2598043));
    assert_eq!(stream.clamp_position(pos.unwrap()), Some(2598043));
  }

  #[tokio::test]
  async fn seek_first_data_block() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut stream = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    let seek = stream.seek_encrypted(SeekFrom::Start(0)).await.unwrap();

    assert_eq!(seek, 124);
    assert_eq!(stream.header_size(), Some(124));
    assert_eq!(stream.current_block_size(), None);

    let mut futures = vec![];
    while let Some(block) = stream.next().await {
      futures.push(block.unwrap());
    }

    let decrypted_bytes =
      join_all(futures)
        .await
        .into_iter()
        .fold(BytesMut::new(), |mut acc, bytes| {
          let (bytes, _) = bytes.unwrap().into_inner();
          acc.extend(bytes.0);
          acc
        });

    // Assert that the decrypted bytes are equal to the original file bytes.
    let original_bytes = get_original_file().await;
    assert_eq!(decrypted_bytes, original_bytes);
  }

  #[tokio::test]
  async fn seek_second_data_block() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut stream = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    let seek = stream.seek_encrypted(SeekFrom::Start(80000)).await.unwrap();

    assert_eq!(seek, 124 + 65564);
    assert_eq!(stream.header_size(), Some(124));
    assert_eq!(stream.current_block_size(), None);

    let seek = stream
      .seek_encrypted(SeekFrom::Current(-20000))
      .await
      .unwrap();

    assert_eq!(seek, 124);
    assert_eq!(stream.header_size(), Some(124));
    assert_eq!(stream.current_block_size(), None);

    let mut futures = vec![];
    while let Some(block) = stream.next().await {
      futures.push(block.unwrap());
    }

    let decrypted_bytes =
      join_all(futures)
        .await
        .into_iter()
        .fold(BytesMut::new(), |mut acc, bytes| {
          let (bytes, _) = bytes.unwrap().into_inner();
          acc.extend(bytes.0);
          acc
        });

    // Assert that the decrypted bytes are equal to the original file bytes.
    let original_bytes = get_original_file().await;
    assert_eq!(decrypted_bytes, original_bytes);
  }

  #[tokio::test]
  async fn seek_to_end() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut stream = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    let seek = stream.seek_encrypted(SeekFrom::End(-1000)).await.unwrap();

    assert_eq!(seek, 2598043 - 40923);
    assert_eq!(stream.header_size(), Some(124));
    assert_eq!(stream.current_block_size(), None);

    let block = stream.next().await.unwrap().unwrap().await.unwrap();
    assert_last_data_block(block.bytes.to_vec()).await;
  }

  #[tokio::test]
  async fn seek_past_end() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut stream = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    let seek = stream.seek_encrypted(SeekFrom::End(80000)).await.unwrap();

    assert_eq!(seek, 2598043);
    assert_eq!(stream.header_size(), Some(124));
    assert_eq!(stream.current_block_size(), None);
    assert!(stream.next().await.is_none());
  }

  #[tokio::test]
  async fn seek_past_end_stream_length_override() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut stream = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .with_stream_length(2598043)
      .build(src, vec![recipient_private_key]);

    let seek = stream.seek_encrypted(SeekFrom::End(80000)).await.unwrap();

    assert_eq!(seek, 2598043);
    assert_eq!(stream.header_size(), Some(124));
    assert_eq!(stream.current_block_size(), None);
    assert!(stream.next().await.is_none());
  }

  #[tokio::test]
  async fn advance_first_data_block() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut stream = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    let advance = stream.advance_encrypted(0).await.unwrap();

    assert_eq!(advance, 124);
    assert_eq!(stream.header_size(), Some(124));
    assert_eq!(stream.current_block_size(), None);

    let mut futures = vec![];
    while let Some(block) = stream.next().await {
      futures.push(block.unwrap());
    }

    let decrypted_bytes =
      join_all(futures)
        .await
        .into_iter()
        .fold(BytesMut::new(), |mut acc, bytes| {
          let (bytes, _) = bytes.unwrap().into_inner();
          acc.extend(bytes.0);
          acc
        });

    // Assert that the decrypted bytes are equal to the original file bytes.
    let original_bytes = get_original_file().await;
    assert_eq!(decrypted_bytes, original_bytes);
  }

  #[tokio::test]
  async fn advance_second_data_block() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut stream = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    let advance = stream.advance_encrypted(80000).await.unwrap();

    assert_eq!(advance, 124 + 65564);
    assert_eq!(stream.header_size(), Some(124));
    assert_eq!(stream.current_block_size(), None);

    let mut futures = vec![];
    while let Some(block) = stream.next().await {
      futures.push(block.unwrap());
    }

    let decrypted_bytes =
      join_all(futures)
        .await
        .into_iter()
        .fold(BytesMut::new(), |mut acc, bytes| {
          let (bytes, _) = bytes.unwrap().into_inner();
          acc.extend(bytes.0);
          acc
        });

    // Assert that the decrypted bytes are equal to the original file bytes.
    let original_bytes = get_original_file().await;
    assert_eq!(decrypted_bytes, original_bytes);
  }

  #[tokio::test]
  async fn advance_to_end() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut stream = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    let advance = stream.advance_encrypted(2598042).await.unwrap();

    assert_eq!(advance, 2598043 - 40923);
    assert_eq!(stream.header_size(), Some(124));
    assert_eq!(stream.current_block_size(), None);

    let mut futures = vec![];
    while let Some(block) = stream.next().await {
      futures.push(block.unwrap());
    }

    let decrypted_bytes =
      join_all(futures)
        .await
        .into_iter()
        .fold(BytesMut::new(), |mut acc, bytes| {
          let (bytes, _) = bytes.unwrap().into_inner();
          acc.extend(bytes.0);
          acc
        });

    // Assert that the decrypted bytes are equal to the original file bytes.
    let original_bytes = get_original_file().await;
    assert_eq!(decrypted_bytes, original_bytes);
  }

  #[tokio::test]
  async fn advance_past_end() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut stream = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    let advance = stream.advance_encrypted(2598044).await.unwrap();

    assert_eq!(advance, 2598043);
    assert_eq!(stream.header_size(), Some(124));
    assert_eq!(stream.current_block_size(), None);

    let mut futures = vec![];
    while let Some(block) = stream.next().await {
      futures.push(block.unwrap());
    }

    let decrypted_bytes =
      join_all(futures)
        .await
        .into_iter()
        .fold(BytesMut::new(), |mut acc, bytes| {
          let (bytes, _) = bytes.unwrap().into_inner();
          acc.extend(bytes.0);
          acc
        });

    // Assert that the decrypted bytes are equal to the original file bytes.
    let original_bytes = get_original_file().await;
    assert_eq!(decrypted_bytes, original_bytes);
  }

  #[tokio::test]
  async fn advance_past_end_stream_length_override() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut stream = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .with_stream_length(2598043)
      .build(src, vec![recipient_private_key]);

    let advance = stream.advance_encrypted(2598044).await.unwrap();

    assert_eq!(advance, 2598043);
    assert_eq!(stream.header_size(), Some(124));
    assert_eq!(stream.current_block_size(), None);

    let mut futures = vec![];
    while let Some(block) = stream.next().await {
      futures.push(block.unwrap());
    }

    let decrypted_bytes =
      join_all(futures)
        .await
        .into_iter()
        .fold(BytesMut::new(), |mut acc, bytes| {
          let (bytes, _) = bytes.unwrap().into_inner();
          acc.extend(bytes.0);
          acc
        });

    // Assert that the decrypted bytes are equal to the original file bytes.
    let original_bytes = get_original_file().await;
    assert_eq!(decrypted_bytes, original_bytes);
  }

  #[tokio::test]
  async fn seek_first_data_block_unencrypted() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut stream = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    let seek = stream.seek_unencrypted(0).await.unwrap();

    assert_eq!(seek, 124);
    assert_eq!(stream.header_size(), Some(124));
    assert_eq!(stream.current_block_size(), None);

    let mut futures = vec![];
    while let Some(block) = stream.next().await {
      futures.push(block.unwrap());
    }

    let decrypted_bytes =
      join_all(futures)
        .await
        .into_iter()
        .fold(BytesMut::new(), |mut acc, bytes| {
          let (bytes, _) = bytes.unwrap().into_inner();
          acc.extend(bytes.0);
          acc
        });

    // Assert that the decrypted bytes are equal to the original file bytes.
    let original_bytes = get_original_file().await;
    assert_eq!(decrypted_bytes, original_bytes);
  }

  #[tokio::test]
  async fn seek_second_data_block_unencrypted() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut stream = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    let seek = stream.seek_unencrypted(65537).await.unwrap();

    assert_eq!(seek, 124 + 65564);
    assert_eq!(stream.header_size(), Some(124));
    assert_eq!(stream.current_block_size(), None);

    let seek = stream.seek_unencrypted(65535).await.unwrap();

    assert_eq!(seek, 124);
    assert_eq!(stream.header_size(), Some(124));
    assert_eq!(stream.current_block_size(), None);

    let mut futures = vec![];
    while let Some(block) = stream.next().await {
      futures.push(block.unwrap());
    }

    let decrypted_bytes =
      join_all(futures)
        .await
        .into_iter()
        .fold(BytesMut::new(), |mut acc, bytes| {
          let (bytes, _) = bytes.unwrap().into_inner();
          acc.extend(bytes.0);
          acc
        });

    // Assert that the decrypted bytes are equal to the original file bytes.
    let original_bytes = get_original_file().await;
    assert_eq!(decrypted_bytes, original_bytes);
  }

  #[tokio::test]
  async fn seek_to_end_unencrypted() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut stream = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    let seek = stream.seek_unencrypted(2596799).await.unwrap();

    assert_eq!(seek, 2598043 - 40923);
    assert_eq!(stream.header_size(), Some(124));
    assert_eq!(stream.current_block_size(), None);

    let block = stream.next().await.unwrap().unwrap().await.unwrap();
    assert_last_data_block(block.bytes.to_vec()).await;
  }

  #[tokio::test]
  async fn seek_past_end_unencrypted() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut stream = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    let seek = stream.seek_unencrypted(2596800).await.unwrap();

    assert_eq!(seek, 2598043);
    assert_eq!(stream.header_size(), Some(124));
    assert_eq!(stream.current_block_size(), None);
    assert!(stream.next().await.is_none());
  }

  #[tokio::test]
  async fn seek_past_end_stream_unencrypted_length_override() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut stream = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .with_stream_length(2598043)
      .build(src, vec![recipient_private_key]);

    let seek = stream.seek_unencrypted(2596800).await.unwrap();

    assert_eq!(seek, 2598043);
    assert_eq!(stream.header_size(), Some(124));
    assert_eq!(stream.current_block_size(), None);
    assert!(stream.next().await.is_none());
  }

  #[tokio::test]
  async fn advance_first_data_block_unencrypted() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut stream = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    let advance = stream.advance_unencrypted(0).await.unwrap();

    assert_eq!(advance, 124);
    assert_eq!(stream.header_size(), Some(124));
    assert_eq!(stream.current_block_size(), None);

    let mut futures = vec![];
    while let Some(block) = stream.next().await {
      futures.push(block.unwrap());
    }

    let decrypted_bytes =
      join_all(futures)
        .await
        .into_iter()
        .fold(BytesMut::new(), |mut acc, bytes| {
          let (bytes, _) = bytes.unwrap().into_inner();
          acc.extend(bytes.0);
          acc
        });

    // Assert that the decrypted bytes are equal to the original file bytes.
    let original_bytes = get_original_file().await;
    assert_eq!(decrypted_bytes, original_bytes);
  }

  #[tokio::test]
  async fn advance_second_data_block_unencrypted() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut stream = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    let advance = stream.advance_unencrypted(65537).await.unwrap();

    assert_eq!(advance, 124 + 65564);
    assert_eq!(stream.header_size(), Some(124));
    assert_eq!(stream.current_block_size(), None);

    let mut futures = vec![];
    while let Some(block) = stream.next().await {
      futures.push(block.unwrap());
    }

    let decrypted_bytes =
      join_all(futures)
        .await
        .into_iter()
        .fold(BytesMut::new(), |mut acc, bytes| {
          let (bytes, _) = bytes.unwrap().into_inner();
          acc.extend(bytes.0);
          acc
        });

    // Assert that the decrypted bytes are equal to the original file bytes.
    let original_bytes = get_original_file().await;
    assert_eq!(decrypted_bytes, original_bytes);
  }

  #[tokio::test]
  async fn advance_to_end_unencrypted() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut stream = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    let advance = stream.advance_unencrypted(2596799).await.unwrap();

    assert_eq!(advance, 2598043 - 40923);
    assert_eq!(stream.header_size(), Some(124));
    assert_eq!(stream.current_block_size(), None);

    let mut futures = vec![];
    while let Some(block) = stream.next().await {
      futures.push(block.unwrap());
    }

    let decrypted_bytes =
      join_all(futures)
        .await
        .into_iter()
        .fold(BytesMut::new(), |mut acc, bytes| {
          let (bytes, _) = bytes.unwrap().into_inner();
          acc.extend(bytes.0);
          acc
        });

    // Assert that the decrypted bytes are equal to the original file bytes.
    let original_bytes = get_original_file().await;
    assert_eq!(decrypted_bytes, original_bytes);
  }

  #[tokio::test]
  async fn advance_past_end_unencrypted() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut stream = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .build_with_stream_length(src, vec![recipient_private_key])
      .await
      .unwrap();

    let advance = stream.advance_unencrypted(2596800).await.unwrap();

    assert_eq!(advance, 2598043);
    assert_eq!(stream.header_size(), Some(124));
    assert_eq!(stream.current_block_size(), None);

    let mut futures = vec![];
    while let Some(block) = stream.next().await {
      futures.push(block.unwrap());
    }

    let decrypted_bytes =
      join_all(futures)
        .await
        .into_iter()
        .fold(BytesMut::new(), |mut acc, bytes| {
          let (bytes, _) = bytes.unwrap().into_inner();
          acc.extend(bytes.0);
          acc
        });

    // Assert that the decrypted bytes are equal to the original file bytes.
    let original_bytes = get_original_file().await;
    assert_eq!(decrypted_bytes, original_bytes);
  }

  #[tokio::test]
  async fn advance_past_end_unencrypted_stream_length_override() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (recipient_private_key, sender_public_key) = get_decryption_keys().await;

    let mut stream = Builder::default()
      .with_sender_pubkey(PublicKey::new(sender_public_key))
      .with_stream_length(2598043)
      .build(src, vec![recipient_private_key]);

    let advance = stream.advance_unencrypted(2596800).await.unwrap();

    assert_eq!(advance, 2598043);
    assert_eq!(stream.header_size(), Some(124));
    assert_eq!(stream.current_block_size(), None);

    let mut futures = vec![];
    while let Some(block) = stream.next().await {
      futures.push(block.unwrap());
    }

    let decrypted_bytes =
      join_all(futures)
        .await
        .into_iter()
        .fold(BytesMut::new(), |mut acc, bytes| {
          let (bytes, _) = bytes.unwrap().into_inner();
          acc.extend(bytes.0);
          acc
        });

    // Assert that the decrypted bytes are equal to the original file bytes.
    let original_bytes = get_original_file().await;
    assert_eq!(decrypted_bytes, original_bytes);
  }
}