use core::convert::TryFrom;

pub use heapless_bytes::Bytes as ByteBuf;
use serde::{Deserialize, Serialize};
use serde_indexed::{DeserializeIndexed, SerializeIndexed};
use zeroize::Zeroize;

use crate::{
    Error,
    config::{MAX_KEY_MATERIAL_LENGTH, MAX_SERIALIZED_KEY_LENGTH},
};

pub type Material = ByteBuf<MAX_KEY_MATERIAL_LENGTH>;
pub type SerializedKeyBytes = ByteBuf<MAX_SERIALIZED_KEY_LENGTH>;

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

impl Key {
    pub fn serialize(&self) -> SerializedKeyBytes {
        let mut buffer = SerializedKeyBytes::new();
        // big-endian here to ensure the first bit is enough to check compatibility
        // on breaking format change
        buffer.extend_from_slice(&self.flags.bits().to_be_bytes()).unwrap();
        buffer.extend_from_slice(&(self.kind as u16).to_be_bytes()).unwrap();
        // can't fail, since MAX_SERIALIZED_KEY_LENGTH is defined as MAX_KEY_MATERIAL_LENGTH + 4
        buffer.extend_from_slice(&self.material).unwrap();
        buffer
    }

    pub fn try_deserialize(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 4 {
            return Err(Error::InvalidSerializedKey);
        }
        let flags_bits = u16::from_be_bytes([bytes[0], bytes[1]]);
        let flags = Flags::from_bits(flags_bits).ok_or(Error::InvalidSerializedKey)?;

        let kind_bits = u16::from_be_bytes([bytes[2], bytes[3]]);
        let kind = Kind::try_from(kind_bits).map_err(|_| Error::InvalidSerializedKey)?;

        Ok(Key {
            flags,
            kind,
            material: Material::try_from_slice(&bytes[4..]).map_err(|_| Error::InvalidSerializedKey)?,
        })
    }
}

bitflags::bitflags! {
    #[derive(DeserializeIndexed, SerializeIndexed, Zeroize)]
    /// All non-used bits are RFU.
    ///
    /// In particular, top bit is intended to be used to accomodate breaking format changes,
    /// i.e., if `flags >> 32 != 0`, then the format is different.
    pub struct Flags: u16 {
        const LOCAL = 1 << 0;
        const SENSITIVE = 1 << 1;
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
// #[derive(Clone,Debug,Eq,PartialEq,SerializeIndexed,DeserializeIndexed)]
// pub struct Flags {
//     // token (persistent) or session (volatile)
//     // pub token: bool,
//     // generated on device?
//     pub local: bool,
//     // // should always be: true for secret, false for public
//     // pub sensitive: bool,
//     // // meaning can be wrapped
//     // pub extractable: bool,
//     // // meaning needs pin
//     // pub private: bool,
// }

// impl Default for Flags {
//     fn default() -> Self {
//         Self {
//             local: false,
//             // sensitive: true,
//             // extractable: false,
//             // private: false,
//         }
//     }
// }

// TODO: How to store/check?
// TODO: Fix variant indices to keep storage stable!!
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Zeroize)]
#[repr(u16)]
pub enum Kind {
    // Aes256,
    Ed255 = 1,
    Entropy32 = 2, // output of TRNG
    P256 = 3,
    // a shared secret may not be suitable for use as a symmetric key,
    // and should pass through a key derivation function first.
    SharedSecret32 = 4,  // or 256 (in bits)?
    SymmetricKey16 = 5,
    SymmetricKey32 = 6, // or directly: SharedSecret32 —DeriveKey(HmacSha256)-> SymmetricKey32 —Encrypt(Aes256)-> ...
    Symmetric32Nonce12 = 7,
    Symmetric24 = 8,
    Symmetric20 = 9,
    // ThirtytwoByteBuf,
    X255 = 10
}

impl core::convert::TryFrom<u16> for Kind {
    type Error = Error;
    fn try_from(num: u16) -> Result<Self, Self::Error> {
        Ok(match num {
            1 => Kind::Ed255,
            2 => Kind::Entropy32,
            3 => Kind::P256,
            4 => Kind::SharedSecret32,
            5 => Kind::SymmetricKey16,
            6 => Kind::SymmetricKey32,
            7 => Kind::Symmetric32Nonce12,
            8 => Kind::Symmetric24,
            9 => Kind::Symmetric20,
            10 => Kind::X255,
            _ => { return Err(Error::CborError); }
        })
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

// impl<'a> TryFrom<(Kind, &'a [u8])> for Key {
//     type Error = Error;
//     fn try_from(from: (Kind, &'a [u8])) -> Result<Self, Error> {
//         Ok(Key {
//             flags: Default::default(),
//             kind: from.0,
//             material: ByteBuf::try_from_slice(from.1).map_err(|_| Error::InternalError)?,
//         })
//     }
// }

