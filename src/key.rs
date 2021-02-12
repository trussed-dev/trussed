use core::convert::TryFrom;

pub use heapless_bytes::Bytes as ByteBuf;
use serde::{Deserialize, Serialize};
use serde_indexed::{DeserializeIndexed, SerializeIndexed};

use crate::{
    Error,
    config::MAX_SERIALIZED_KEY_LENGTH,
};

pub type KeyMaterial = ByteBuf<MAX_SERIALIZED_KEY_LENGTH>;

#[derive(Clone,Debug,Eq,PartialEq,SerializeIndexed,DeserializeIndexed)]
pub struct KeyFlags {
    // token (persistent) or session (volatile)
    // pub token: bool,
    // generated on device?
    pub local: bool,
    // // should always be: true for secret, false for public
    // pub sensitive: bool,
    // // meaning can be wrapped
    // pub extractable: bool,
    // // meaning needs pin
    // pub private: bool,
}

impl Default for KeyFlags {
    fn default() -> Self {
        Self {
            local: false,
            // sensitive: true,
            // extractable: false,
            // private: false,
        }
    }
}

#[derive(Clone,Debug,Eq,PartialEq,SerializeIndexed,DeserializeIndexed)]
pub struct SerializedKey {
   // r#type: Secrecy,
   pub kind: KeyKind,
   pub flags: KeyFlags,
   pub value: ByteBuf<MAX_SERIALIZED_KEY_LENGTH>,
}

// TODO: How to store/check?
// TODO: Fix variant indices to keep storage stable!!
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum KeyKind {
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

impl core::convert::TryFrom<u8> for KeyKind {
    type Error = crate::error::Error;
    fn try_from(num: u8) -> Result<Self, Self::Error> {
        Ok(match num {
            1 => KeyKind::Ed255,
            2 => KeyKind::Entropy32,
            3 => KeyKind::P256,
            4 => KeyKind::SharedSecret32,
            5 => KeyKind::SymmetricKey16,
            6 => KeyKind::SymmetricKey32,
            7 => KeyKind::Symmetric32Nonce12,
            8 => KeyKind::Symmetric24,
            9 => KeyKind::Symmetric20,
            10 => KeyKind::X255,
            _ => { return Err(crate::error::Error::CborError); }
        })
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Secrecy {
    // Private,
    Public,
    Secret,
}

impl<'a> TryFrom<(KeyKind, &'a [u8])> for SerializedKey {
    type Error = Error;
    fn try_from(from: (KeyKind, &'a [u8])) -> Result<Self, Error> {
        Ok(SerializedKey {
            kind: from.0,
            flags: Default::default(),
            value: ByteBuf::try_from_slice(from.1).map_err(|_| Error::InternalError)?,
        })
    }
}

