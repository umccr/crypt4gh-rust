use std::io::{Read};
use std::path::Path;
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use crate::v2::data_block::DataBlock;
use crate::v2::error::Result;
use crate::v2::header::Header;
use crate::v2::header::packet::DecryptedPacket;

#[derive(Debug)]
pub struct Writer<W: AsyncWrite> {
    inner: BufWriter<W>,
}

impl<W: AsyncWrite> Writer<W> {
    pub fn new(inner: BufWriter<W>) -> Self {
        Self { inner }
    }
}

impl<W: AsyncWrite + Unpin> Writer<W> {
    pub async fn write_header(&mut self, header: Header) -> Result<()> {
        self.inner.write_all(&header.to_bytes()).await?;
        Ok(())
    }

    pub async fn write_data_block(&mut self, data_block: DataBlock) -> Result<()> {
        todo!()
    }
}

#[derive(Default)]
pub struct Builder {
    key: Vec<u8>,
}

impl Builder {
    pub async fn build_from_path<P>(self, src: P) -> Result<Writer<File>>
    where
        P: AsRef<Path>,
    {
        Ok(File::open(src).await.map(BufWriter::new).map(|inner| Writer::new(inner))?)
    }

    pub fn build_from_writer<W>(self, writer: W) -> Writer<W>
    where
        W: AsyncWrite,
    {
        Writer::new(BufWriter::new(writer))
    }
}