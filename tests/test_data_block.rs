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