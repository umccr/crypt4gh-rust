#[cfg(test)]
mod tests {
  use crate::util::{unencrypted_clamp, unencrypted_to_data_block, unencrypted_to_next_data_block};

  use super::*;

  #[test]
  fn test_to_encrypted() {
    let pos = 80000;
    let expected = 120 + 65536 + 12 + 16;
    let result = unencrypted_to_data_block(pos, 120, to_encrypted_file_size(100000, 120));
    assert_eq!(result, expected);
  }

  #[test]
  fn test_to_encrypted_file_size() {
    let pos = 110000;
    let expected = 60148;
    let result = unencrypted_to_data_block(pos, 120, to_encrypted_file_size(60000, 120));
    assert_eq!(result, expected);
  }

  #[test]
  fn test_to_encrypted_pos_greater_than_file_size() {
    let pos = 110000;
    let expected = 120 + 65536 + 12 + 16;
    let result = unencrypted_to_data_block(pos, 120, to_encrypted_file_size(100000, 120));
    assert_eq!(result, expected);
  }

  #[test]
  fn test_next_data_block() {
    let pos = 100000;
    let expected = 120 + (65536 + 12 + 16) * 2;
    let result = unencrypted_to_next_data_block(pos, 120, to_encrypted_file_size(150000, 120));
    assert_eq!(result, expected);
  }

  #[test]
  fn test_next_data_block_file_size() {
    let pos = 110000;
    let expected = 100176;
    let result = unencrypted_to_next_data_block(pos, 120, to_encrypted_file_size(100000, 120));
    assert_eq!(result, expected);
  }

  #[test]
  fn test_unencrypted_clamp() {
    let pos = 0;
    let expected = 0;
    let result = unencrypted_clamp(pos, to_encrypted_file_size(5485112, 0));
    assert_eq!(result, expected);

    let pos = 145110;
    let expected = 131072;
    let result = unencrypted_clamp(pos, to_encrypted_file_size(5485112, 0));
    assert_eq!(result, expected);

    let pos = 5485074;
    let expected = 5439488;
    let result = unencrypted_clamp(pos, to_encrypted_file_size(5485112, 0));
    assert_eq!(result, expected);
  }

  #[test]
  fn test_unencrypted_clamp_next() {
    let pos = 7853;
    let expected = 65536;
    let result = unencrypted_clamp_next(pos, to_encrypted_file_size(5485112, 0));
    assert_eq!(result, expected);

    let pos = 453039;
    let expected = 458752;
    let result = unencrypted_clamp_next(pos, to_encrypted_file_size(5485112, 0));
    assert_eq!(result, expected);

    let pos = 5485112;
    let expected = 5485112;
    let result = unencrypted_clamp_next(pos, to_encrypted_file_size(5485112, 0));
    assert_eq!(result, expected);
  }
}