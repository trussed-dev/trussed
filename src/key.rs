use heapless::Vec;
use serde::{Deserialize, Serialize};
use serde_indexed::{DeserializeIndexed, SerializeIndexed};
use zeroize::Zeroize;

pub use crate::Bytes;
use crate::{
    config::{MAX_KEY_MATERIAL_LENGTH, MAX_SERIALIZED_KEY_LENGTH},
    Error,
};

pub type Material = Vec<u8, { MAX_KEY_MATERIAL_LENGTH }>;
pub type SerializedKeyBytes = Vec<u8, { MAX_SERIALIZED_KEY_LENGTH }>;

// We don't implement serde to make sure nobody inadvertently still uses it
// Should we use references here only?
// #[derive(Clone, Debug, DeserializeIndexed, Eq, PartialEq, SerializeIndexed)]
/// A key object in Trussed.
///
/// Follows Sophie Schmieg's [dictum][dictum] that
/// "A key should always be considered to be the raw key material alongside its parameter choices."
///
/// [dictum]: https://twitter.com/SchmiegSophie/status/1264567198091079681
#[derive(Clone, Debug, /*DeserializeIndexed,*/ Eq, PartialEq, /*SerializeIndexed,*/ Zeroize)]
pub struct Key {
    pub flags: Flags,
    pub kind: Kind,
    pub material: Material,
}

#[derive(Clone, Debug, /*DeserializeIndexed,*/ Eq, PartialEq, /*SerializeIndexed,*/ Zeroize)]
pub struct Info {
    pub flags: Flags,
    pub kind: Kind,
}

impl Info {
    pub fn with_local_flag(mut self) -> Self {
        self.flags |= Flags::LOCAL;
        self
    }
}

impl From<Kind> for Info {
    fn from(kind: Kind) -> Self {
        Self {
            flags: Default::default(),
            kind,
        }
    }
}

// TODO: How to store/check?
// TODO: Fix variant indices to keep storage stable!!
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Zeroize)]
#[repr(u16)]
pub enum Kind {
    /// some bytes of entropy, needs a KDF applied,
    /// the parameter is the length of the key
    Shared(usize),
    /// entropic bytes, suitable for use as symmetric secret (e.g., AES),
    /// the parameter is the length of the key (e.g. 16 for AES).
    Symmetric(usize),
    /// 32B symmetric key + nonce, the parameter is the length of the nonce in bytes
    Symmetric32Nonce(usize),
    Ed255,
    P256,
    X255,
    Rsa2k,
}

bitflags::bitflags! {
    #[derive(DeserializeIndexed, SerializeIndexed, Zeroize)]
    /// All non-used bits are RFU.
    ///
    /// In particular, top bit is intended to be used to accomodate breaking format changes,
    /// i.e., if `flags >> 32 != 0`, then the format is different.
    pub struct Flags: u16 {
        /// Set if the key has been generated on this device.
        const LOCAL = 1 << 0;
        /// Set if the key is a secret key.
        const SENSITIVE = 1 << 1;
        // Reserved for future use
        // const WRAPPABLE = 1 << 3;
        /// This flag currently only applies to `kind::Shared`
        const SERIALIZABLE = 1 << 4;
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// A key can either be public, of secret.
///
/// The secret case also applies to private keys for asymmetric algorithms.
pub enum Secrecy {
    // Private,
    Public,
    Secret,
}

impl Key {
    pub fn serialize(&self) -> SerializedKeyBytes {
        let mut buffer = SerializedKeyBytes::new();
        // big-endian here to ensure the first bit is enough to check compatibility
        // on breaking format change
        buffer
            .extend_from_slice(&self.flags.bits().to_be_bytes())
            .unwrap();
        buffer
            .extend_from_slice(&(self.kind.code()).to_be_bytes())
            .unwrap();
        // can't fail, since MAX_SERIALIZED_KEY_LENGTH is defined as MAX_KEY_MATERIAL_LENGTH + 4
        buffer.extend_from_slice(&self.material).unwrap();
        buffer
    }

    pub fn try_deserialize(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 4 {
            return Err(Error::InvalidSerializedKey);
        }
        let (info, material) = bytes.split_at(4);
        let flags_bits = u16::from_be_bytes([info[0], info[1]]);
        let flags = Flags::from_bits(flags_bits).ok_or(Error::InvalidSerializedKey)?;

        let kind_bits = u16::from_be_bytes([info[2], info[3]]);
        let kind =
            Kind::try_from(kind_bits, material.len()).map_err(|_| Error::InvalidSerializedKey)?;

        Ok(Key {
            flags,
            kind,
            material: Material::from_slice(material).map_err(|_| Error::InvalidSerializedKey)?,
        })
    }
}

impl Default for Flags {
    /// This implements "safe" defaults
    /// - no claim on local generation
    /// - default sensitive
    fn default() -> Self {
        Flags::SENSITIVE
    }
}

impl Kind {
    pub fn code(self) -> u16 {
        match self {
            Kind::Shared(_) => 1,
            Kind::Symmetric(_) => 2,
            Kind::Symmetric32Nonce(_) => 3,
            Kind::Ed255 => 4,
            Kind::P256 => 5,
            Kind::X255 => 6,
            Kind::Rsa2k => 0x7,
            //Kind::Rsa3k => 0xE0,
            //Kind::Rsa4k => 0xE1,
        }
    }

    pub fn try_from(code: u16, length: usize) -> Result<Self, Error> {
        Ok(match code {
            1 => Self::Shared(length),
            2 => Self::Symmetric(length),
            3 => Self::Symmetric32Nonce(length - 32),
            4 => Self::Ed255,
            5 => Self::P256,
            6 => Self::X255,

            0x7 => Self::Rsa2k,
            //0xE0 => Kind::Rsa3k,
            //0xE1 => Kind::Rsa4k,
            _ => return Err(Error::InvalidSerializedKey),
        })
    }
}
