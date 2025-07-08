//! Sketch of the public API for Crypt4GH
//!
//! Generally each struct defined here should represent the "on-disk" version of the data in the spec.
//! For example, header packets are assumed to be encrypted, because that is how they would be represented
//! on disk.

pub mod header;
pub mod crypt;
pub mod data_block;
pub mod error;
pub mod io;
mod parsing;
