use std::error::Error;

use thiserror::Error as ThisError;
use tokio::task;

#[derive(Debug, ThisError)]
pub enum Crypt4GHError {
	// User errors
	#[error("No Recipients' Public Key found")]
	NoRecipients,
	#[error("Invalid range span: {0:?}")]
	InvalidRangeSpan(Option<usize>),
	#[error("The edit list is empty")]
	EmptyEditList,
	#[error("Unable to create random nonce")]
	NoRandomNonce,
	#[error("Unable to extract nonce")]
	NoNonce,
	#[error("Unable to create random salt")]
	NoRandomSalt,
	#[error("Unable to find or create session key")]
	NoKey,
	#[error("Unable to wrap key")]
	BadKey,
	// #[error("Unable to decrypt key (ERROR = {0:?})")]
	// DecryptKeyError(SymmetricCipherError),
	#[error("Invalid key format")]
	InvalidKeyFormat,
	#[error("Invalid PEM file length.")]
	InvalidPEMFormatLength,
	#[error("Invalid PEM file header or footer: -----BEGIN or -----END")]
	InvalidPEMHeaderOrFooter,
	#[error("Invalid SSH key format")]
	InvalidSSHKey,
	#[error("Invalid position: {0:?}")]
	InvalidPosition(String),
	#[error("Unable to wrap nonce")]
	UnableToWrapNonce,
	#[error("Could not decrypt block: {0:?}, {1:?}")]
	UnableToDecryptBlock(Vec<u8>, String),
	#[error("Unable to decode with base64 the key (ERROR = {0:?})")]
	BadBase64Error(Box<dyn Error + Send + Sync>),
	#[error("Unable to decode kdfname")]
	BadKdfName(Box<dyn Error + Send + Sync>),
	#[error("Unsupported KDF: {0}")]
	UnsupportedKdf(String),
	#[error("Invalid Crypt4GH Key format")]
	InvalidCrypt4GHKey,
	#[error("Bad ciphername ({0:?})")]
	BadCiphername(String),
	#[error("Conversion from ed25519 to curve25519 failed")]
	ConversionFailed,
	#[error("Unsupported Header Encryption Method: {0}")]
	BadHeaderEncryptionMethod(u32),
	#[error("Unable to encrypt packet: None of the keys were used in {0}")]
	UnableToEncryptPacket(String),
	#[error("Decryption failed -> Invalid data: {0}")]
	InvalidData(String),

	// Key errors
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
	#[error("Invalid Public Key")]
	InvalidPublicKey,
	#[error("Invalid Peer's Public Key")]
	InvalidPeerPubPkey,
	#[error("Invalid paramenters passed to Scrypt")]
	ScryptParamsError,
	#[error("BcryptPBKDF error")]
	BcryptPBKDFError,

	// Reading errors
	#[error("Unable to read {0} bytes from input (ERROR = {1:?})")]
	NotEnoughInput(usize, Box<dyn Error + Send + Sync>),
	#[error("You shouldn't skip 0 bytes")]
	SkipZeroBytes,
	#[error("Unable to read header info (ERROR = {0:?})")]
	ReadHeaderError(Box<dyn Error + Send + Sync>),
	#[error("Unable to read header packet length (ERROR = {0:?})")]
	ReadHeaderPacketLengthError(Box<dyn Error + Send + Sync>),
	#[error("Unable to read header packet data (ERROR = {0:?})")]
	ReadHeaderPacketDataError(Box<dyn Error + Send + Sync>),
	#[error("Unable to skip to the beginning of the decryption (ERROR = {0:?})")]
	BadStartRange(Box<dyn Error + Send + Sync>),
	#[error("Unable to read block (ERROR = {0:?})")]
	ReadBlockError(Box<dyn Error + Send + Sync>),
	#[error("Error reading the remainder of the file (ERROR = {0:?})")]
	ReadRemainderError(Box<dyn Error + Send + Sync>),
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
	#[error("Unable to read magic word from private key (ERROR = {0:?})")]
	ReadMagicWord(Box<dyn Error + Send + Sync>),
	#[error("Not a CRYPT4GH formatted file")]
	MagicStringError,
	#[error("Unsupported CRYPT4GH version (version = {0:?})")]
	InvalidCrypt4GHVersion(u32),
	#[error("Empty public key")]
	EmptyPublicKey,

	// Packets
	#[error("Unable to read packet encryption method")]
	ReadPacketEncryptionMethod,
	#[error("Invalid packet type")]
	InvalidPacketType,
	#[error("Invalid file: Too many edit list packets")]
	TooManyEditListPackets,
	#[error("Unsupported bulk encryption method: {0}")]
	UnsupportedEncryptionMethod(u32),
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
	#[error("Passphrase required (ERROR = {0:?})")]
	NoPassphrase(Box<dyn Error + Send + Sync>),
	#[error("Nothing to be done")]
	Done,

	// Write errors
	#[error("Unable to write to output (ERROR = {0:?})")]
	UnableToWrite(Box<dyn Error + Send + Sync>),

	// Parse errors
	#[error("Unable to parse header packet length (ERROR = {0:?})")]
	ParseHeaderPacketLengthError(Box<dyn Error + Send + Sync>),
	#[error("Unable to parse the start of the range")]
	ParseRangeError,

	// IO
	#[error("IO failed")]
	IoError(#[from] std::io::Error),
	#[error("End of stream: {0:?}")]
	EndOfStreamReached(String),

	// Conversion and decoding
	#[error("converting slice to fixed size array")]
	SliceConversionError,
	#[error("converting between numeric types")]
	NumericConversionError,
	#[error("Decoding header info error")]
	DecodingHeader,
	#[error("Decoding header packet error")]
	DecodingHeaderPacket,
	#[error("join handle error: `{0}`")]
	JoinHandleError(task::JoinError),
	#[error("maximum header size exceeded")]
	MaximumHeaderSize,
	#[error("crypt4gh error: `{0}`")]
	Crypt4GHError(String),
}

// impl From<io::Error> for Crypt4GHError {
//   fn from(error: io::Error) -> Self {
//     Self::IOError(error)
//   }
// }

// impl From<dyn Error> for Crypt4GHError {
//   fn from(error: dyn std::error::Error) -> Self {
//     if let std::error::Error::IOError(error) = error {
//       error
//     } else {
//       Self::new(io::ErrorKind::Other, error)
//     }
//   }
// }

// impl From<dyn Error> for Crypt4GHError {
//   fn from(error: Crypt4GHError) -> Self {
//     Self::Crypt4GHError(error.to_string())
//   }
//}
