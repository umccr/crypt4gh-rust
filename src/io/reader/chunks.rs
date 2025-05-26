use std::io::Read;

use crate::{error::Crypt4GHError, plaintext::PlainText, PLAINTEXT_SEGMENT_SIZE};

pub trait ChunkDataBlocks {
	fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, Crypt4GHError>;
}

impl<R> ChunkDataBlocks for PlainText<R> where R: Read {
	fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, Crypt4GHError> {
        let mut buf = vec![0u8; PLAINTEXT_SEGMENT_SIZE];
        let read = self.inner.read(&mut buf)?;

        if read == 0 {
            Ok(None)
        } else {
            Ok(Some(buf))
        }
	}
}

// impl ChunkDataBlocks for PlainText {
// 	fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, Crypt4GHError> {
// 		let previous = self.pos;
// 		self.pos += PLAINTEXT_SEGMENT_SIZE;

// 		if self.pos > self.inner.len() {
// 			Ok(None)
// 		} else {
// 			Ok(Some(self.inner[previous..self.pos].to_vec()))
// 		}
// 	}
// }