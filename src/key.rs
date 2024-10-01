use core::ptr::write_volatile;
use core::sync::atomic;

use heapless::Vec;
use serde::{de::Visitor, ser::SerializeMap, Deserialize, Serialize};
use zeroize::Zeroize;

pub use crate::Bytes;
use crate::{config::MAX_SERIALIZED_KEY_LENGTH, Error};

// Keys are often stored in serialized format (e.g. PKCS#8 used by the RSA backend),
// so material max length must be serialized max length.
pub type Material = Vec<u8, { MAX_SERIALIZED_KEY_LENGTH }>;
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
    Rsa2048,
    Rsa3072,
    Rsa4096,
    Ed255,
    P256,
    P384,
    P521,
    BrainpoolP256R1,
    BrainpoolP384R1,
    BrainpoolP512R1,
    X255,

    // Post-quantum cryptography algorithms
    #[cfg(feature = "backend-dilithium2")]
    Dilithium2,
    #[cfg(feature = "backend-dilithium3")]
    Dilithium3,
    #[cfg(feature = "backend-dilithium5")]
    Dilithium5,
}

bitflags::bitflags! {
    #[derive(Debug, Eq, PartialEq, Clone, Copy)]
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

impl Zeroize for Flags {
    fn zeroize(&mut self) {
        // Safety: We have a mutable reference, and Flags is `Copy` and therefore does not need to be dropped
        unsafe {
            write_volatile(self, Flags::empty());
        }
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

/// Manual implementation to keep compatibility with version 0.1.0 that used `serde_indexed`
/// serde_indexed cannot be used anymore for compatiblity with bitflags 2.0
impl Serialize for Flags {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_key(&0usize)?;
        map.serialize_value(&self.bits())?;
        map.end()
    }
}

/// Manual implementation to keep compatibility with version 0.1.0 that used `serde_indexed`
impl<'de> Deserialize<'de> for Flags {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct FlagsVisitor;
        impl<'vis_de> Visitor<'vis_de> for FlagsVisitor {
            type Value = Flags;
            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(formatter, "A flag structure")
            }
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'vis_de>,
            {
                if !matches!(map.next_key()?, Some(0usize)) {
                    return Err(serde::de::Error::missing_field("bits"));
                }
                let bits = map.next_value()?;
                let flags = Flags::from_bits(bits)
                    .ok_or_else(|| serde::de::Error::custom("Wrong bit layout"))?;
                Ok(flags)
            }
        }
        deserializer.deserialize_map(FlagsVisitor)
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
            Kind::Rsa2048 => 7,
            Kind::Rsa3072 => 8,
            Kind::Rsa4096 => 9,
            Kind::P384 => 10,
            Kind::P521 => 11,
            Kind::BrainpoolP256R1 => 12,
            Kind::BrainpoolP384R1 => 13,
            Kind::BrainpoolP512R1 => 14,
            #[cfg(feature = "backend-dilithium2")]
            Kind::Dilithium2 => 15,
            #[cfg(feature = "backend-dilithium3")]
            Kind::Dilithium3 => 16,
            #[cfg(feature = "backend-dilithium5")]
            Kind::Dilithium5 => 17,
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
            7 => Kind::Rsa2048,
            8 => Kind::Rsa3072,
            9 => Kind::Rsa4096,
            10 => Kind::P384,
            11 => Kind::P521,
            12 => Kind::BrainpoolP256R1,
            13 => Kind::BrainpoolP384R1,
            14 => Kind::BrainpoolP512R1,
            #[cfg(feature = "backend-dilithium2")]
            15 => Kind::Dilithium2,
            #[cfg(feature = "backend-dilithium3")]
            16 => Kind::Dilithium3,
            #[cfg(feature = "backend-dilithium5")]
            17 => Kind::Dilithium5,
            _ => return Err(Error::InvalidSerializedKey),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_test::{assert_tokens, Token};

    #[test]
    fn keyflags_format() {
        assert_tokens(
            &Flags::empty(),
            &[
                Token::Map { len: Some(1) },
                Token::U64(0),
                Token::U16(0),
                Token::MapEnd,
            ],
        );
        assert_tokens(
            &Flags::LOCAL,
            &[
                Token::Map { len: Some(1) },
                Token::U64(0),
                Token::U16(0b1),
                Token::MapEnd,
            ],
        );
        assert_tokens(
            &(Flags::LOCAL | Flags::SENSITIVE),
            &[
                Token::Map { len: Some(1) },
                Token::U64(0),
                Token::U16(0b11),
                Token::MapEnd,
            ],
        );
        assert_tokens(
            &(Flags::LOCAL | Flags::SENSITIVE | Flags::SERIALIZABLE),
            &[
                Token::Map { len: Some(1) },
                Token::U64(0),
                Token::U16(0b10011),
                Token::MapEnd,
            ],
        );
        assert_tokens(
            &Flags::SENSITIVE,
            &[
                Token::Map { len: Some(1) },
                Token::U64(0),
                Token::U16(0b10),
                Token::MapEnd,
            ],
        );
        assert_tokens(
            &(Flags::SENSITIVE | Flags::SERIALIZABLE),
            &[
                Token::Map { len: Some(1) },
                Token::U64(0),
                Token::U16(0b10010),
                Token::MapEnd,
            ],
        );
        assert_tokens(
            &Flags::SERIALIZABLE,
            &[
                Token::Map { len: Some(1) },
                Token::U64(0),
                Token::U16(0b10000),
                Token::MapEnd,
            ],
        );
    }
}
