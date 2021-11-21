// NOTE: The mechanism implementations are currently littered with `#[inline(never)]`,
// which is annoyingly explicit + manual (easy to forget).
// The underlying concern is that the stack use of `ServiceResources::reply_to` would be
// "too big" if they all get inlined.
//
// Removing these inlines (2021-03-12) changes the `text` code size of an entire solo-bee
// firmware from 350416 to 351376 (larger), so it's at least not obvious that these inlines
// happen.
//
// The question of breaking down `reply_to` into smaller, more globally understandable pieces,
// should be revisited.

// TODO: rename to aes256-cbc-zero-iv
pub struct Aes256Cbc {}
mod aes256cbc;

pub struct Chacha8Poly1305 {}
mod chacha8poly1305;

pub struct SharedSecret {}
mod shared_secret;

pub struct Ed255 {}
mod ed255;

pub struct HmacBlake2s {}
#[cfg(feature = "hmac-blake2s")]
mod hmacblake2s;
#[cfg(not(feature = "hmac-blake2s"))]
impl crate::service::DeriveKey for HmacBlake2s {}
#[cfg(not(feature = "hmac-blake2s"))]
impl crate::service::Sign for HmacBlake2s {}

pub struct HmacSha1 {}
mod hmacsha1;

pub struct HmacSha256 {}
mod hmacsha256;

pub struct HmacSha512 {}
#[cfg(feature = "hmac-sha512")]
mod hmacsha512;
#[cfg(not(feature = "hmac-sha512"))]
impl crate::service::DeriveKey for HmacSha512 {}
#[cfg(not(feature = "hmac-sha512"))]
impl crate::service::Sign for HmacSha512 {}

pub struct P256 {}
pub struct P256Prehashed {}
mod p256;

pub struct Rsa2kPkcs {}
mod rsa2kpkcs;

pub struct Sha256 {}
mod sha256;

pub struct Tdes {}
mod tdes;

pub struct Totp {}
mod totp;

pub struct Trng {}
mod trng;

pub struct X255 {}
mod x255;

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
