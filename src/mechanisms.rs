// do we really need this
pub trait MechanismTrait {}

// TODO: rename to aes256-cbc-zero-iv
pub struct Aes256Cbc {}
mod aes256cbc;

pub struct Chacha8Poly1305 {}
mod chacha8poly1305;

pub struct Ed255 {}
mod ed255;

pub struct X255 {}
mod x255;

pub struct HmacSha256 {}
mod hmacsha256;

pub struct P256 {}
pub struct P256Prehashed {}
mod p256;

pub struct Sha256 {}
mod sha256;

pub struct Totp {}
mod totp;

pub struct Tdes {}
mod tdes;

pub struct Trng {}
mod trng;

// pub enum MechanismEnum {
//     NotImplemented,
//     Ed255(ed255::Ed255),
//     P256(p256::P256),
// }

// use crate::types::Mechanism;
// pub fn enum_to_type(mechanism: Mechanism) -> MechanismEnum {
//     match mechanism {
//         #[cfg(feature = "ed255")]
//         Mechanism::Ed255 => MechanismEnum::Ed255(ed255::Ed255 {} ),
//         #[cfg(feature = "p256")]
//         Mechanism::P256 => MechanismEnum::P256(p256::P256 {} ),
//         _ => MechanismEnum::NotImplemented,
//     }
// }

