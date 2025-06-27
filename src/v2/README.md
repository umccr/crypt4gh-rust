# Crypt4GH public API sketch

(The implementation of all of this is incomplete in the code)

The public API should support the following:

* Easy and clear to use - names should make sense and match the Crypt4GH spec as closely as possible
   * In some cases I think it makes sense to shorten names when the spec is overly verbose, 
     e.g. `DataEditListPacket` -> `EditListPacket`, the data component is redundant.
   * I also think it makes sense to use Rust-based idioms rather than C-style idioms when writing enums. 
     E.g. `DecryptedPacket` enum doesn't needlessly store the packet type enum since it can just use a Rust enum.
* IO should be completely separate from the Crypt4GH parsing, decrypting/encrypting logic.
* Functions should be composable in clear tasks/blocks, e.g. it should be possible to read the header/individual data blocks
  without reading the whole data stream at once.

Considering this the library is split up into components according to the structs defined in the Crypt4GH spec.
E.g. there should a "header" module, with a "packet" sub-module, etc.
* There should also be an "io" module, or crate (if we decide to use a workspace) that handles IO reading/writing.
* As much of logic of Crypt4GH should be contained in the "core" library. "IO" parts should only be concerned with strictly IO operations. This enables writing sans-io style
  logic (we can even write a state machine to do the read/write loop generically, and just have different IO backends).

The following modules are defined:
* `crypt`: This handles all encryption/decryption logic, and is the only part of the code that should interact with RustCrypto.
  * This defines a shared `EncryptedData` struct that can be used to encrypt/decrypt both header packets and data blocks (as the logic is identical).
* `data_block`/`header`: defines the logic of parsing Crypt4GH files. Deals with `[u8]` slices mostly to avoid dependencies on any IO or external crates.
  * a `parse` function takes in the exact number of bytes and validates it/converts it into a well-defined type/struct.
  * a `decode` function determines the amount of bytes needed before the struct can be "parsed". This kind of separation is required because
    the size of the header is not known in advance until the `count` fields and the number of packets are read.
  * a `to_bytes` function serializes the struct into bytes.
  * a `decrypt` function converts a well-defined struct into decrypted bytes or another well-defined struct. E.g. when you `decrypt` a `Packet` it gets
    converted into a `DecryptedPacket`, which represents converting a "Header Packet" into the decrypted version of the "Encrypted Packet Data".
  * an `encrypt` function is the inverse of `decrypt`.
  * Not every struct needs to have all of the above functions, only the ones that make sense. For example, a `DecryptedPacket` doesn't have a `decrypt` function,
    as it's already decrypted. However, it does have an `encrypt` function to convert it back to a `Packet`.
  * In general, these modules prefer plain types, like `[u8]`, or structs that label what a slice represents, if it makes sense, such as definiting an encryption key (this hasn't been added yet).
* `io`: reader and writer definitions only - split up into `read_header`/`read_data_block` for composability and to avoid reading the whole stream into memory.