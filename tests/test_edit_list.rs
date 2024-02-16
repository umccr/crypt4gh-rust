#[cfg(test)]
mod tests {
  // use htsget_test::crypt4gh::{get_decryption_keys, get_encryption_keys};
  // use htsget_test::http_tests::get_test_file;

  use crate::reader::builder::Builder;

  use super::*;

  #[tokio::test]
  async fn test_append_edit_list() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (private_key_decrypt, public_key_decrypt) = get_decryption_keys().await;
    let (private_key_encrypt, public_key_encrypt) = get_encryption_keys().await;

    let mut reader = Builder::default()
      .with_sender_pubkey(PublicKey::new(public_key_decrypt.clone()))
      .with_stream_length(5485112)
      .build_with_reader(src, vec![private_key_decrypt.clone()]);
    reader.read_header().await.unwrap();

    let expected_data_packets = reader.session_keys().to_vec();

    let header = EditHeader::new(
      &reader,
      test_unencrypted_positions(),
      test_clamped_positions(),
      PrivateKey(private_key_encrypt.clone().privkey),
      PublicKey {
        bytes: public_key_encrypt.clone(),
      },
    )
    .edit_list()
    .unwrap()
    .unwrap();

    let header_slice = header.as_slice();
    let mut reader = Builder::default()
      .with_sender_pubkey(PublicKey::new(public_key_decrypt))
      .with_stream_length(5485112)
      .build_with_reader(header_slice.as_slice(), vec![private_key_decrypt]);
    reader.read_header().await.unwrap();

    let data_packets = reader.session_keys();
    assert_eq!(data_packets, expected_data_packets);

    let edit_lists = reader.edit_list_packet().unwrap();
    assert_eq!(edit_lists, expected_edit_list());
  }

  #[tokio::test]
  async fn test_create_edit_list() {
    let src = get_test_file("crypt4gh/htsnexus_test_NA12878.bam.c4gh").await;
    let (private_key_decrypt, public_key_decrypt) = get_decryption_keys().await;
    let (private_key_encrypt, public_key_encrypt) = get_encryption_keys().await;

    let mut reader = Builder::default()
      .with_sender_pubkey(PublicKey::new(public_key_decrypt.clone()))
      .with_stream_length(5485112)
      .build_with_reader(src, vec![private_key_decrypt.clone()]);
    reader.read_header().await.unwrap();

    let edit_list = EditHeader::new(
      &reader,
      test_unencrypted_positions(),
      test_clamped_positions(),
      PrivateKey(private_key_encrypt.clone().privkey),
      PublicKey {
        bytes: public_key_encrypt.clone(),
      },
    )
    .create_edit_list();

    assert_eq!(edit_list, expected_edit_list());
  }

  fn test_unencrypted_positions() -> Vec<UnencryptedPosition> {
    vec![
      UnencryptedPosition::new(0, 7853),
      UnencryptedPosition::new(145110, 453039),
      UnencryptedPosition::new(5485074, 5485112),
    ]
  }

  fn test_clamped_positions() -> Vec<ClampedPosition> {
    vec![
      ClampedPosition::new(0, 65536),
      ClampedPosition::new(131072, 458752),
      ClampedPosition::new(5439488, 5485112),
    ]
  }

  fn expected_edit_list() -> Vec<u64> {
    vec![0, 7853, 71721, 307929, 51299, 38]
  }
}