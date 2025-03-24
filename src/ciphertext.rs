use crate::error::Crypt4GHError;
use crate::keys::KeyPair;
use crate::plaintext::PlainText;
use crate::{Crypt4GhBuilder, Segment};

pub struct Reader<R> {
	inner: R,
}

#[derive(Debug)]
pub struct DataBlocks {
	segments: Vec<Segment>,
}

impl DataBlocks {
	pub fn new() -> Self {
		DataBlocks { segments: Vec::new() }
	}

	pub fn append_segment(&mut self, segment: Segment) {
		self.segments.push(segment);
	}

	/// Convert the file to a little endian vector of bytes.
	pub fn to_bytes(self) -> Vec<u8> {
		let mut bytes = Vec::new();
		for segment in self.segments {
			bytes.extend_from_slice(&segment.to_bytes());
		}
		bytes
	}

	pub fn from_bytes(bytes: &[u8]) -> Result<Self, Crypt4GHError> {
		let mut segments = Vec::new();
		let mut offset = 0;

		while offset < bytes.len() {
			let segment = Segment::from_bytes(&bytes[offset..])?;
			offset += segment.length();
			segments.push(segment);
		}

		Ok(DataBlocks { segments })
	}
}
