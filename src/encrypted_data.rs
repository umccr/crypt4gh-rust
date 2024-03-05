use crate::keys::EncryptionMethod;

/// Size of the encrypted segments.
pub const SEGMENT_SIZE: usize = 65_536;
const CIPHER_DIFF: usize = 28;
const CIPHER_SEGMENT_SIZE: usize = SEGMENT_SIZE + CIPHER_DIFF;

struct Segment {
    pub data: Chacha20IetfPoly1305Segment<EncryptionMethod>
}

struct Chacha20IetfPoly1305Segment<EncryptionMethod> {
    nonce: u8,
    encrypted_data: Vec<u8>, // FIXME: Specific Nonce type preferred in Rust, prefer not following the spec types here
    mac: u8 // FIXME: Ditto above
}