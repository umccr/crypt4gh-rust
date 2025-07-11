use crate::v2::data_block::DataBlock;
use crate::v2::error::Result;
use crate::v2::header::Header;
use crate::v2::header::packet::DecryptedPacket;
use std::io::Read;
use std::path::Path;
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};

#[derive(Debug)]
pub struct Reader<R> {
	inner: BufReader<R>,
}

impl<R> Reader<R> {
	pub fn new(inner: BufReader<R>) -> Self {
		Self { inner }
	}
}

impl<R: AsyncRead + Unpin> Reader<R> {
	pub async fn read_header(&mut self) -> Result<Header> {
		let mut buf = vec![];
		while let None = Header::decode(buf.as_slice())? {
			let _ = self.inner.read(&mut buf).await?;
		}

		Header::parse(buf.as_slice())
	}

	pub async fn read_data_block(&mut self, packets: Vec<DecryptedPacket>) -> Result<DataBlock> {
		todo!()
	}
}

#[derive(Default)]
pub struct Builder {
	key: Vec<u8>,
}

impl Builder {
	pub async fn build_from_path<P>(self, src: P) -> Result<Reader<File>>
	where
		P: AsRef<Path>,
	{
		Ok(File::open(src)
			.await
			.map(BufReader::new)
			.map(|inner| Reader::new(inner))?)
	}

	pub fn build_from_reader<R>(self, reader: R) -> Reader<R>
	where
		R: AsyncRead,
	{
		Reader::new(BufReader::new(reader))
	}
}
