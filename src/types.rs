use core::convert::TryFrom;
use core::marker::PhantomData;
use core::ops::Deref;

pub use generic_array::GenericArray;

pub use heapless::{
    consts,
    String,
    Vec,
};

pub use crate::Bytes;

pub use littlefs2::{
    fs::{DirEntry, Filesystem},
    driver::Storage as LfsStorage,
    io::Result as LfsResult,
    path::PathBuf,
};

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::config::*;
use crate::key::Secrecy;

pub use crate::platform::Platform;
pub use crate::client::FutureResult;

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
#[derive(Copy, Clone, PartialEq, PartialOrd)]
pub struct Id(pub(crate) u128);
impl Eq for Id {}

impl core::fmt::Debug for Id {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Id(")?;
        for ch in &self.hex() {
            write!(f, "{}", &(*ch as char))?;
        }
        write!(f, ")")
    }
}


pub type SpecialId = u8;

pub trait ObjectId: Deref<Target = Id> {}

impl Id {
    /// Generate an ID, using a cryptographically secure random number generator.
    pub(crate) fn new(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        Self(u128::from_be_bytes(id))
    }

    /// Is a non-random, constructible u8 ID.
    pub fn is_special(&self) -> bool {
        self.0 < 256
    }

    /// skips leading zeros
    pub fn hex(&self) -> Bytes<consts::U32> {
        const HEX_CHARS: &[u8] = b"0123456789abcdef";
        let mut buffer = Bytes::new();
        let array = self.0.to_be_bytes();

        for i in 0 .. array.len() {
            if array[i] == 0 && i != (array.len() - 1) {
                // Skip leading zeros.
                continue;
            }

            buffer.push(HEX_CHARS[(array[i] >> 4) as usize]).unwrap();
            buffer.push(HEX_CHARS[(array[i] & 0xf) as usize]).unwrap();
        }

        buffer
    }

    // NOT IMPLEMENTED, as this would allow clients to create non-random (non-special) IDs.
    // For testing, can construct directly as the newtypes have pub(crate) access.
    // #[allow(clippy::result_unit_err)]
    // pub fn try_from_hex(hex: &[u8]) -> core::result::Result<Self, ()> {
    //     // https://stackoverflow.com/a/52992629
    //     // (0..hex.len())
    //     // use hex::FromHex;
    //     // let maybe_bytes = <[u8; 16]>::from_hex(hex).map_err(|e| ());
    //     // maybe_bytes.map(|bytes| Self(Bytes::try_from_slice(&bytes).unwrap()))
    //     if (hex.len() & 1) == 1 {
    //         // panic!("hex len & 1 =  {}", hex.len() & 1);
    //         return Err(());
    //     }
    //     if hex.len() > 32 {
    //         // panic!("hex len {}", hex.len());
    //         return Err(());
    //     }
    //     // let hex = core::str::from_utf8(hex).map_err(|e| ())?;
    //     let hex = core::str::from_utf8(hex).unwrap();
    //     // let hex = core::str::from_utf8_unchecked(hex);
    //     let mut bytes = [0u8; 16];
    //     for i in 0..(hex.len() >> 1) {
    //         // bytes[i] = u8::from_str_radix(&hex[i..][..2], 16).map_err(|e| ())?;
    //         bytes[i] = u8::from_str_radix(&hex[2*i..][..2], 16).unwrap();
    //     }
    //     Ok(Self(u128::from_be_bytes(bytes)))
    // }
}

macro_rules! impl_id { ($Name:ident) => {
    #[derive(Copy, Clone, Debug, serde::Deserialize, PartialEq, PartialOrd, serde::Serialize)]
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

}}

impl_id!(CertId);
impl_id!(CounterId);
impl_id!(KeyId);
// TODO: decide whether this is good idea.
// It would allow using the same underlying u128 ID for the public key of the private
// key in a keypair. However, DeleteKey and others would need to be adjusted.
// impl_id!(PublicKeyId);
// impl_id!(SecretKeyId);


pub mod ui {
    use super::*;

    // TODO: Consider whether a simple "language" to specify "patterns"
    // makes sense, vs. "semantic" indications with platform-specific implementation
    #[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
    pub enum Status {
        Idle,
        WaitingForUserPresence,
        Processing,
        Error,
    }
}

pub mod reboot {
    use super::*;

    #[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
    pub enum To {
        Application,
        ApplicationUpdate,
    }
}

pub mod consent {
    use super::*;

    #[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
    pub enum Level {
        /// There is no user present
        None,

        /// Normal user presence check, currently implemented as "touch any of three buttons"
        Normal,

        /// Strong user intent check, currently implemented as "two-or-three finger squeeze"
        Strong,
    }

    #[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
    pub enum Urgency {
        /// Pending other user consent requests will fail as interrupted.
        InterruptOthers,
        /// If other user consent requests are pending, fail this request.
        FailIfOthers,
    }

    #[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
    pub enum Error {
        FailedToInterrupt,
        Interrupted,
        TimedOut,
        TimeoutNotImplemented,
    }

    pub type Result = core::result::Result<(), Error>;
}

// for counters use the pkcs#11 idea of
// a monotonic incrementing counter that
// "increments on each read" --> save +=1 operation

// #[derive(Copy, Clone, Eq, PartialEq, Debug)]
// pub struct AeadUniqueId {
//     unique_id: [u8; 16],
//     nonce: [u8; 12],
//     tag: [u8; 16],
// }

// pub type AeadKey = [u8; 32];
// pub type AeadNonce = [u8; 12];
// pub type AeadTag = [u8; 16];

// pub type ClientId = heapless::Vec<u8, heapless::consts::U32>;
pub type ClientId = PathBuf;

// Object Hierarchy according to Cryptoki
// - Storage
//   - Domain parameters
//   - Key
//   - Certificate
//   - Data
// - Hardware feature
// - Mechanism
// - Profiles


#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum Attributes {
    Certificate,
    Counter,
    Data(DataAttributes),
    Key(KeyAttributes),
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum CertificateType {
    // "identity", issued by certificate authority
    // --> authentication
    PublicKey,
    // issued by attribute authority
    // --> authorization
    Attribute,
}

// pub enum CertificateCategory {
//     Authority,
//     Token,
//     Other,
// }

// #[derive(Clone, Default, Eq, PartialEq, Debug)]
// pub struct CertificateAttributes {
//     pub certificate_type CertificateType,
// }


#[derive(Clone, Default, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct DataAttributes {
    // application that manages the object
    // pub application: String<MAX_APPLICATION_NAME_LENGTH>,
    // DER-encoding of *type* of data object
    // pub object_id: Bytes<?>,
    pub kind: ShortData,
    pub value: LongData,
}

// TODO: In PKCS#11v3, this is a map (AttributeType: ulong -> (*void, len)).
// "An array of CK_ATTRIBUTEs is called a “template” and is used for creating, manipulating and searching for objects."
//
// Maybe we should put these attributes in an enum, and pass an `heapless::IndexSet` of attributes.
// How do we handle defaults?
//
// Lookup seems a bit painful, on the other hand a struct of options is wasteful.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct KeyAttributes {
    // secrecy: Secrecy,
    // object_id: Bytes,
    // derive: bool, // can other keys be derived
    // local: bool, // generated on token, or copied from such
    // key_gen_mechanism: Mechanism, // only for local, how was key generated
    // allowed_mechanisms: Vec<Mechanism>,

    // never return naked private key
    sensitive: bool,
    // always_sensitive: bool,

    // do not even return wrapped private key
    extractable: bool,
    // never_extractable: bool,

    // do not save to disk
    persistent: bool,
}

impl Default for KeyAttributes {
    fn default() -> Self {
        Self {
            sensitive: true,
            // always_sensitive: true,
            extractable: false,
            // never_extractable: true,
            // cryptoki: token (vs session) object
            // cryptoki: default false
            persistent: false,
        }
    }
}

impl KeyAttributes {
    pub fn new() -> Self {
        Default::default()
    }
}

/// Non-exhaustive to make it unconstructable
/// NB: Better to check in service that nothing snuck through!
#[derive(Clone, Default, Eq, PartialEq, Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub struct Letters(pub ShortData);

impl TryFrom<ShortData> for Letters {
    type Error = crate::error::Error;

    fn try_from(bytes: ShortData) -> Result<Self, Self::Error> {
        if !&bytes.iter().all(|b| *b >= b'a' && *b <= b'z') {
            return Err(Self::Error::NotJustLetters);
        }
        Ok(Letters(bytes))
    }
}

impl serde::Serialize for Id {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.to_be_bytes())
    }
}

impl<'de> serde::Deserialize<'de> for Id {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ValueVisitor<'de>(PhantomData<&'de ()>);

        impl<'de> serde::de::Visitor<'de> for ValueVisitor<'de>
        {
            type Value = Id;

            fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str("16 bytes")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> core::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                use core::convert::TryInto;
                if v.len() != 16 {
                    return Err(E::invalid_length(v.len(), &self));
                }
                Ok(Id(u128::from_be_bytes(v.try_into().unwrap())))
            }
        }

        deserializer.deserialize_bytes(ValueVisitor(PhantomData))
    }
}


#[derive(Clone, Eq, PartialEq, Debug)]
pub enum ObjectType {
    Certificate(CertificateType),
    // TODO: maybe group under Feature(FeautureType), with FeatureType = Counter, ...
    // But what else??
    Counter,
    Data,
    Key(Secrecy),
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct PublicKeyAttributes {
    // never return naked private key
    sensitive: bool,
    // always_sensitive: bool,

    // do not even return wrapped private key
    extractable: bool,
    // never_extractable: bool,

    // do not save to disk
    persistent: bool,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct PrivateKeyAttributes {
    // never return naked private key
    sensitive: bool,
    // always_sensitive: bool,

    // do not even return wrapped private key
    extractable: bool,
    // never_extractable: bool,

    // do not save to disk
    persistent: bool,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum Location {
    Volatile,
    Internal,
    External,
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct StorageAttributes {
    // each object must have a unique ID
    // unique_id: UniqueId,

    // description of object
    // label: String<MAX_LABEL_LENGTH>,

    // // cryptoki: token (vs session) object
    // persistent: bool,
    pub persistence: Location,

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
}

impl StorageAttributes {
    // pub fn new(unique_id: UniqueId) -> Self {
    pub fn new() -> Self {
        Self {
            // unique_id,
            // label: String::new(),
            // persistent: false,

            persistence: Location::Volatile,

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

#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
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
    // clients can also do hashing by themselves
    Sha256,
    Tdes,
    Totp,
    Trng,
    X255,
}

pub type LongData = Bytes<MAX_LONG_DATA_LENGTH>;
pub type MediumData = Bytes<MAX_MEDIUM_DATA_LENGTH>;
pub type ShortData = Bytes<MAX_SHORT_DATA_LENGTH>;

pub type Message = Bytes<MAX_MESSAGE_LENGTH>;

#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum KeySerialization {
    // Asn1Der,
    Cose,
    // Der,
    EcdhEsHkdf256,
    Raw,
    Sec1,
}

pub type Signature = Bytes<MAX_SIGNATURE_LENGTH>;

#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum SignatureSerialization {
    Asn1Der,
    // Cose,
    Raw,
    // Sec1,
}

pub type UserAttribute = Bytes<MAX_USER_ATTRIBUTE_LENGTH>;

