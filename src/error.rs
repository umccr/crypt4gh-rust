use thiserror::Error;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Debug, Error)]
pub enum Crypt4GHError {
	// User errors
	#[error("No Recipients' Public Key found")]
	NoRecipients,
	#[error("Invalid range span")]
	InvalidRangeSpan,
	#[error("The edit list is empty")]
	EmptyEditList,
	// Sodiumoxide errors
	#[error("Unable to create random nonce")]
	NoRandomNonce,
	#[error("Unable to extract nonce")]
	NoNonce,
	#[error("Unable to create random salt")]
	NoRandomSalt,
	#[error("Unable to create session key")]
	NoKey,
	#[error("Unable to wrap key")]
	BadKey,
	// #[error("Unable to decrypt key (ERROR = {0:?})")]
	// DecryptKeyError(SymmetricCipherError),
	#[error("Invalid key format")]
	InvalidKeyFormat,
	#[error("Invalid PEM file length. Not 3 lines long")]
	InvalidPEMFormatLength,
	#[error("Invalid PEM file header or footer: -----BEGIN or -----END")]
	InvalidPEMHeaderOrFooter,
	#[error("Invalid SSH key format")]
	InvalidSSHKey,
	#[error("Unable to wrap nonce")]
	UnableToWrapNonce,
	#[error("Could not decrypt block")]
	UnableToDecryptBlock,
	#[error("Unable to decode with base64 the key")]
	BadBase64Error,
	#[error("Unable to decode kdfname")]
	BadKdfName,
	#[error("Unsupported KDF")]
	UnsupportedKdf,
	#[error("Invalid Crypt4GH Key format")]
	InvalidCrypt4GHKey,
	#[error("Bad ciphername")]
	BadCiphername,
	#[error("Conversion from ed25519 to curve25519 failed")]
	ConversionFailed,
	#[error("Unsupported Header Encryption Method")]
	BadHeaderEncryptionMethod,
	#[error("Unable to encrypt packet: None of the keys were used")]
	UnableToEncryptPacket,
	#[error("Decryption failed -> Invalid data")]
	InvalidData,

	// Keys errors
	#[error("Unable to extract public server key")]
	BadServerPublicKey,
	#[error("Unable to extract private server key")]
	BadServerPrivateKey,
	#[error("Unable to extract public client key")]
	BadClientPublicKey,
	#[error("Unable to extract public client key")]
	BadClientPrivateKey,
	#[error("Unable to create shared key")]
	BadSharedKey,
	#[error("Invalid Peer's Public Key")]
	InvalidPeerPubPkey,
	#[error("Invalid paramenters passed to Scrypt")]
	ScryptParamsError,
	#[error("BcryptPBKDF error")]
	BcryptPBKDFError,

	// Reading errors
	#[error("Unable to read bytes from input")]
	NotEnoughInput,
	#[error("You shouldn't skip 0 bytes")]
	SkipZeroBytes,
	#[error("Unable to read header info")]
	ReadHeaderError,
	#[error("Unable to read header packet length")]
	ReadHeaderPacketLengthError,
	#[error("Unable to read header packet data")]
	ReadHeaderPacketDataError,
	#[error("Unable to skip to the beginning of the decryption")]
	BadStartRange,
	#[error("Unable to read block")]
	ReadBlockError,
	#[error("Error reading the remainder of the file")]
	ReadRemainderError,
	#[error("Unable to read lines")]
	ReadLinesError,
	#[error("Unable to deserialize rounds from private key")]
	ReadRoundsError,
	#[error("Unable to extract public key")]
	ReadPublicKeyError,
	#[error("Unable to deserialize N keys from private key")]
	ReadSSHKeys,
	#[error("Unable to deserialize check number 1 from private blob")]
	ReadCheckNumber1Error,
	#[error("Unable to deserialize check number 2 from private blob")]
	ReadCheckNumber2Error,
	#[error("Unable to read magic word from private key")]
	ReadMagicWord,
	#[error("Not a CRYPT4GH formatted file")]
	MagicStringError,
	#[error("Unsupported CRYPT4GH version")]
	InvalidCrypt4GHVersion,
	#[error("Empty public key")]
	EmptyPublicKey,
	#[error("Secret key not found")]
	ReadSecretKeyFileError,

	// Packets
	#[error("Unable to read packet encryption method")]
	ReadPacketEncryptionMethod,
	#[error("Invalid packet type")]
	InvalidPacketType,
	#[error("Invalid file: Too many edit list packets")]
	TooManyEditListPackets,
	#[error("Unsupported bulk encryption method")]
	UnsupportedEncryptionMethod,
	#[error("No supported encryption method")]
	NoSupportedEncryptionMethod,

	// Header
	#[error("No header packet could be decrypted")]
	NoValidHeaderPacket,

	// Edit list
	#[error("Edit list packet did not contain the length of the list")]
	NoEditListLength,
	#[error("Invalid edit list")]
	InvalidEditList,
	#[error("Unable to parse content of the edit list packet")]
	ReadEditListError,

	// Other
	#[error("Passphrase required")]
	NoPassphrase,
	#[error("Nothing to be done")]
	Done,

	// Write errors
	#[error("Unable to write to output")]
	UnableToWrite,

	// Parse errors
	#[error("Unable to parse header packet length")]
	ParseHeaderPacketLengthError,
	#[error("Unable to parse the start of the range")]
	ParseRangeError,

	// IO
	#[error("IO failed")]
	IoError,
}
