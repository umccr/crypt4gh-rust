use std::{
    fs::File,
    io::{self, BufReader, Read},
    path::Path,
};

use super::reader::Reader;

/// A reader builder.
#[derive(Default)]
pub struct Builder;

impl Builder {
    /// Builds a reader from a path.
    pub fn build_from_path<P>(self, src: P) -> io::Result<Reader<BufReader<File>>>
    where
        P: AsRef<Path>,
    {
        File::open(src).map(BufReader::new).map(Reader::new)
    }

    /// Builds reader from another reader.
    pub fn build_from_reader<R>(self, reader: R) -> Reader<BufReader<R>>
    where
        R: Read,
    {
        Reader::new(BufReader::new(reader))
    }
}