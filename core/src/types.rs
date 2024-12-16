use core::{marker::PhantomData, ops::Deref};

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

pub use heapless_bytes::Bytes;
pub use littlefs2_core::{DirEntry, Metadata, PathBuf};

use crate::api::{reply, request};
use crate::config::{
    MAX_KEY_MATERIAL_LENGTH, MAX_MEDIUM_DATA_LENGTH, MAX_MESSAGE_LENGTH, MAX_SHORT_DATA_LENGTH,
    MAX_SIGNATURE_LENGTH, MAX_USER_ATTRIBUTE_LENGTH,
};

pub mod consent {
    #[derive(Copy, Clone, Eq, PartialEq, Debug)]
    pub enum Level {
        /// There is no user present
        None,

        /// Normal user presence check, currently implemented as "touch any of three buttons"
        Normal,

        /// Strong user intent check, currently implemented as "two-or-three finger squeeze"
        Strong,
    }

    #[derive(Copy, Clone, Eq, PartialEq, Debug)]
    pub enum Error {
        FailedToInterrupt,
        Interrupted,
        TimedOut,
        TimeoutNotImplemented,
    }

    pub type Result = core::result::Result<(), Error>;
}

pub mod reboot {
    #[derive(Copy, Clone, Eq, PartialEq, Debug)]
    pub enum To {
        Application,
        ApplicationUpdate,
    }
}

pub type Message = Bytes<MAX_MESSAGE_LENGTH>;
pub type MediumData = Bytes<MAX_MEDIUM_DATA_LENGTH>;
pub type ShortData = Bytes<MAX_SHORT_DATA_LENGTH>;
pub type SerializedKey = Bytes<MAX_KEY_MATERIAL_LENGTH>;
pub type Signature = Bytes<MAX_SIGNATURE_LENGTH>;
pub type UserAttribute = Bytes<MAX_USER_ATTRIBUTE_LENGTH>;

pub type SpecialId = u8;

/// The ID of a Trussed object.
///
/// Apart from the 256 "special" IDs, generated as a random 128-bit number,
/// hence globally unique without coordination or counters.
///
/// Specific object types have more specific IDs, e.g., currently: [`CertId`], [`CounterId`], [`KeyId`].
///
/// When serialized to the file system, the `hex` method is used, which
/// generates a big-endian hex representation with leading zero bytes trimmed.
///
/// Open question: Should `PublicKey` and `SecretKey` be distinguished?
#[derive(Copy, Clone, Eq, PartialEq, PartialOrd)]
pub struct Id(u128);

impl Id {
    /// Generate an ID, using a cryptographically secure random number generator.
    fn new(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        Self(u128::from_be_bytes(id))
    }

    /// Is a non-random, constructible u8 ID.
    pub fn is_special(&self) -> bool {
        self.0 < 256
    }

    /// See [`Id::legacy_hex_path`].
    #[deprecated = "use legacy_hex_path instead"]
    pub fn hex_path(&self) -> PathBuf {
        self.legacy_hex_path()
    }

    /// Hex path of this ID without non-trailing zero bytes.
    ///
    /// This implementation skips all leading bytes that are zero so that the resulting hex string
    /// always has an even number of characters and does not start with more than one zero.  For
    /// compatibility with old Trussed versions, this implementation also skips inner bytes that
    /// are zero, except for the trailing byte.  This means that for example 4096 and 1048576 both
    /// are formatted as `"1000"`.
    ///
    /// For new features that don’t need backwards-compatibility, use [`Id::clean_hex_path`][]
    /// instead.
    pub fn legacy_hex_path(&self) -> PathBuf {
        const HEX_CHARS: &[u8] = b"0123456789abcdef";
        let mut buffer = [0; PathBuf::MAX_SIZE_PLUS_ONE];
        let array = self.0.to_be_bytes();

        let mut j = 0;
        for i in 0..array.len() {
            if array[i] == 0 && i != (array.len() - 1) {
                // This actually skips all zeroes, not only leading ones
                // This is kept for backward compatibility with already serialized KeyIds
                continue;
            }

            buffer[j] = HEX_CHARS[(array[i] >> 4) as usize] as _;
            buffer[j + 1] = HEX_CHARS[(array[i] & 0xf) as usize] as _;
            j += 2;
        }

        // SAFETY:
        // 1. We only add characters from HEX_CHARS which only contains ASCII characters.
        // 2. We initialized the buffer with zeroes so there is still a trailing zero.
        unsafe {
            assert!(j < buffer.len());
            PathBuf::from_buffer_unchecked(buffer)
        }
    }

    /// Hex path of this ID without leading zero bytes.
    ///
    /// This uses the same format as [`Id::hex_clean`][].  Note that the first `hex_path`
    /// implementation, now available as [`Id::legacy_hex_path`][], skipped all non-trailing zero
    /// bytes and should only be used if backwards compatibility is required.
    pub fn clean_hex_path(&self) -> PathBuf {
        let mut buffer = [0; PathBuf::MAX_SIZE_PLUS_ONE];

        let array = self.0.to_be_bytes();
        for (i, c) in HexCleanBytes::new(&array).enumerate() {
            buffer[i] = c as _;
        }

        // SAFETY:
        // 1. We only add characters from HEX_CHARS which only contains ASCII characters.
        // 2. We initialized the buffer with zeroes so there is still a trailing zero.
        unsafe { PathBuf::from_buffer_unchecked(buffer) }
    }

    /// Hex representation of this ID without leading zeroes.
    ///
    /// This implementation skips all leading bytes that are zero so that the resulting hex string
    /// always has an even number of characters and does not start with more than one zero.  0 is
    /// formatted as `"00"`.
    pub fn hex_clean(&self) -> HexClean {
        HexClean(self.0)
    }
}

impl core::fmt::Debug for Id {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Id({})", self.hex_clean())
    }
}

impl Serialize for Id {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.to_be_bytes())
    }
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ValueVisitor<'de>(PhantomData<&'de ()>);

        impl<'de> serde::de::Visitor<'de> for ValueVisitor<'de> {
            type Value = Id;

            fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str("16 bytes")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() != 16 {
                    return Err(E::invalid_length(v.len(), &self));
                }
                Ok(Id(u128::from_be_bytes(v.try_into().unwrap())))
            }
        }

        deserializer.deserialize_bytes(ValueVisitor(PhantomData))
    }
}

/// Hex representation of an `u128` without leading zeroes.
///
/// This implementation skips all leading bytes that are zero so that the resulting hex string
/// always has an even number of characters and does not start with more than one zero.  0 is
/// formatted as `"00"`.
pub struct HexClean(pub u128);

impl core::fmt::Display for HexClean {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let array = self.0.to_be_bytes();
        for c in HexCleanBytes::new(&array) {
            write!(f, "{}", char::from(c))?;
        }
        Ok(())
    }
}

struct HexCleanBytes<'a> {
    array: &'a [u8],
    upper: bool,
}

impl<'a> HexCleanBytes<'a> {
    fn new(array: &'a [u8]) -> Self {
        if let Some(i) = array.iter().position(|&v| v != 0) {
            Self {
                array: &array[i..],
                upper: true,
            }
        } else {
            // Format 0 as "00"
            Self {
                array: &[0],
                upper: true,
            }
        }
    }
}

impl Iterator for HexCleanBytes<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        const HEX_CHARS: &[u8] = b"0123456789abcdef";
        if let Some((v, rest)) = self.array.split_first() {
            if self.upper {
                self.upper = false;
                Some(HEX_CHARS[(v >> 4) as usize])
            } else {
                self.upper = true;
                self.array = rest;
                Some(HEX_CHARS[(v & 0xf) as usize])
            }
        } else {
            None
        }
    }
}

pub trait ObjectId: Deref<Target = Id> {}

macro_rules! impl_id {
    ($Name:ident) => {
        #[derive(
            Copy, Clone, Debug, serde::Deserialize, PartialEq, PartialOrd, serde::Serialize,
        )]
        #[serde(transparent)]
        pub struct $Name(pub(crate) Id);
        impl Eq for $Name {}

        impl ObjectId for $Name {}

        /// TODO: Is this a good idea (motivation: save implementions...)
        impl Deref for $Name {
            type Target = Id;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl $Name {
            pub fn new(rng: &mut (impl CryptoRng + RngCore)) -> Self {
                Self(Id::new(rng))
            }

            pub const fn from_special(special_id: u8) -> Self {
                Self(Id(special_id as _))
            }
        }

        impl From<SpecialId> for $Name {
            fn from(id: u8) -> Self {
                Self(Id(id as _))
            }
        }
    };
}

impl_id!(CertId);
impl_id!(CounterId);
impl_id!(KeyId);

// TODO: decide whether this is good idea.
// It would allow using the same underlying u128 ID for the public key of the private
// key in a keypair. However, DeleteKey and others would need to be adjusted.
// impl_id!(PublicKeyId);
// impl_id!(SecretKeyId);

impl KeyId {
    /// Create a KeyId from a given value instead of at random.
    ///
    /// This can be useful for backends which can use it to encode additional information inside of the KeyId itself (128 bits is a lot)
    ///
    /// This is already possible to acheive through the serde implementation, so this doesn't really add any unavailable functionality.
    #[doc(hidden)]
    pub const fn from_value(value: u128) -> Self {
        Self(Id(value))
    }

    #[doc(hidden)]
    pub const fn value(&self) -> u128 {
        self.0 .0
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum Location {
    Volatile,
    Internal,
    External,
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[non_exhaustive]
pub struct StorageAttributes {
    // each object must have a unique ID
    // unique_id: UniqueId,

    // description of object
    // label: String<MAX_LABEL_LENGTH>,

    // // cryptoki: token (vs session) object
    // persistent: bool,
    pub persistence: Location,

    /// Wether a the result of an [`agree`](crate::client::CryptoClient::agree) can be serialized
    /// with [`serialize_key`](crate::client::CryptoClient::serialize_key)
    pub serializable: bool,
    // cryptoki: user must be logged in
    // private: bool,

    // modifiable: bool,
    // copyable: bool,
    // destroyable: bool,
}

impl StorageAttributes {
    pub fn set_persistence(mut self, persistence: Location) -> Self {
        self.persistence = persistence;
        self
    }

    pub fn set_serializable(mut self, serializable: bool) -> Self {
        self.serializable = serializable;
        self
    }
}

impl StorageAttributes {
    // pub fn new(unique_id: UniqueId) -> Self {
    pub fn new() -> Self {
        Self {
            // unique_id,
            // label: String::new(),
            // persistent: false,
            persistence: Location::Volatile,
            serializable: false,
            // modifiable: true,
            // copyable: true,
            // destroyable: true,
        }
    }
}

impl Default for StorageAttributes {
    fn default() -> Self {
        Self::new()
    }
}

/// Available client traits.
///
/// This enum does not provide access to the trait features.  It is only intended for backends to
/// use in constant assertions to ensure that the correct features are enabled.
#[non_exhaustive]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Client {
    AttestationClient,
    CertificateClient,
    CounterClient,
    CryptoClient,
    FilesystemClient,
    ManagementClient,
    UiClient,
}

impl Client {
    /// All enabled clients.
    ///
    /// The contents of this constant depends on the enabled features.
    pub const ENABLED: &[Self] = &[
        #[cfg(feature = "attestation-client")]
        Self::AttestationClient,
        #[cfg(feature = "certificate-client")]
        Self::CertificateClient,
        #[cfg(feature = "counter-client")]
        Self::CounterClient,
        #[cfg(feature = "crypto-client")]
        Self::CryptoClient,
        #[cfg(feature = "filesystem-client")]
        Self::FilesystemClient,
        #[cfg(feature = "management-client")]
        Self::ManagementClient,
        #[cfg(feature = "ui-client")]
        Self::UiClient,
    ];
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Mechanism {
    Aes256Cbc,
    Chacha8Poly1305,
    Ed255,
    HmacBlake2s,
    HmacSha1,
    HmacSha256,
    HmacSha512,
    // P256XSha256,
    P256,
    P256Prehashed,
    P384,
    P384Prehashed,
    P521,
    P521Prehashed,
    BrainpoolP256R1,
    BrainpoolP256R1Prehashed,
    BrainpoolP384R1,
    BrainpoolP384R1Prehashed,
    BrainpoolP512R1,
    BrainpoolP512R1Prehashed,
    Secp256k1,
    Secp256k1Prehashed,
    // clients can also do hashing by themselves
    Sha256,
    Tdes,
    Totp,
    Trng,
    X255,
    /// Used to serialize the output of a diffie-hellman
    SharedSecret,

    /// Exposes the Raw RSA encryption/decryption primitive. Be aware this is dangerous.
    /// Not having any padding can allow an attacker to obtain plaintexts and forge signatures.
    /// It should only be used if absolutely necessary.
    Rsa2048Raw,
    /// Exposes the Raw RSA encryption/decryption primitive. Be aware this is dangerous.
    /// Not having any padding can allow an attacker to obtain plaintexts and forge signatures.
    /// It should only be used if absolutely necessary.
    Rsa3072Raw,
    /// Exposes the Raw RSA encryption/decryption primitive. Be aware this is dangerous.
    /// Not having any padding can allow an attacker to obtain plaintexts and forge signatures.
    /// It should only be used if absolutely necessary.
    Rsa4096Raw,

    Rsa2048Pkcs1v15,
    Rsa3072Pkcs1v15,
    Rsa4096Pkcs1v15,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum KeySerialization {
    // Asn1Der,
    Cose,
    // Der,
    EcdhEsHkdf256,
    Raw,
    Sec1,
    /// Used by backends implementing RSA.
    ///
    /// Since RSA keys have multiple parts, and that the [`SerializeKey`](crate::api::Reply::SerializeKey) and
    /// [`UnsafeInjectKey`](crate::api::Request::UnsafeInjectKey) have only transfer one byte array, the RSA key is serialized with postcard
    RsaParts,
    Pkcs8Der,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum SignatureSerialization {
    Asn1Der,
    // Cose,
    Raw,
    // Sec1,
}

/// Serializable version of [`reply::Encrypt`][].
///
/// Sometimes it is necessary the result of an encryption together with the metadata required for
/// decryption, for example when wrapping keys.  This struct stores the data that is returned by
/// the [`request::Encrypt`][] syscall, see [`reply::Encrypt`][], in a serializable format.
#[derive(
    Clone, Debug, Eq, PartialEq, serde_indexed::DeserializeIndexed, serde_indexed::SerializeIndexed,
)]
#[non_exhaustive]
pub struct EncryptedData {
    pub ciphertext: Message,
    pub nonce: ShortData,
    pub tag: ShortData,
}

impl EncryptedData {
    /// Creates a decryption request to decrypt the stored data.
    #[cfg(feature = "crypto-client")]
    pub fn decrypt(
        self,
        mechanism: Mechanism,
        key: KeyId,
        associated_data: Message,
    ) -> request::Decrypt {
        request::Decrypt {
            mechanism,
            key,
            message: self.ciphertext,
            associated_data,
            nonce: self.nonce,
            tag: self.tag,
        }
    }
}

#[cfg(feature = "crypto-client")]
impl From<reply::Encrypt> for EncryptedData {
    fn from(reply: reply::Encrypt) -> Self {
        let reply::Encrypt {
            ciphertext,
            nonce,
            tag,
        } = reply;
        Self {
            ciphertext,
            nonce,
            tag,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Id;

    #[test]
    fn test_id_hex_path() {
        assert_eq!(Id(0).legacy_hex_path().as_str(), "00");
        assert_eq!(Id(1).legacy_hex_path().as_str(), "01");
        assert_eq!(Id(10).legacy_hex_path().as_str(), "0a");
        assert_eq!(Id(16).legacy_hex_path().as_str(), "10");
        assert_eq!(Id(256).legacy_hex_path().as_str(), "0100");
        assert_eq!(Id(4096).legacy_hex_path().as_str(), "1000");
        assert_eq!(Id(1048576).legacy_hex_path().as_str(), "1000");
        assert_eq!(
            Id(u128::MAX).legacy_hex_path().as_str(),
            "ffffffffffffffffffffffffffffffff"
        );
    }

    #[test]
    fn test_id_clean_hex_path() {
        assert_eq!(Id(0).clean_hex_path().as_str(), "00");
        assert_eq!(Id(1).clean_hex_path().as_str(), "01");
        assert_eq!(Id(10).clean_hex_path().as_str(), "0a");
        assert_eq!(Id(16).clean_hex_path().as_str(), "10");
        assert_eq!(Id(256).clean_hex_path().as_str(), "0100");
        assert_eq!(Id(4096).clean_hex_path().as_str(), "1000");
        assert_eq!(Id(1048576).clean_hex_path().as_str(), "100000");
        assert_eq!(
            Id(u128::MAX).clean_hex_path().as_str(),
            "ffffffffffffffffffffffffffffffff"
        );
    }

    #[test]
    fn test_id_hex_clean() {
        assert_eq!(Id(0).hex_clean().to_string(), "00");
        assert_eq!(Id(1).hex_clean().to_string(), "01");
        assert_eq!(Id(10).hex_clean().to_string(), "0a");
        assert_eq!(Id(16).hex_clean().to_string(), "10");
        assert_eq!(Id(256).hex_clean().to_string(), "0100");
        assert_eq!(Id(4096).hex_clean().to_string(), "1000");
        assert_eq!(Id(1048576).hex_clean().to_string(), "100000");
        assert_eq!(
            Id(u128::MAX).hex_clean().to_string(),
            "ffffffffffffffffffffffffffffffff"
        );
    }
}
