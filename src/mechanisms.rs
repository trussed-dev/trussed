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
#[cfg(feature = "aes256-cbc")]
pub struct Aes256Cbc;
#[cfg(feature = "aes256-cbc")]
mod aes256cbc;

#[cfg(feature = "chacha8-poly1305")]
pub struct Chacha8Poly1305;
#[cfg(feature = "chacha8-poly1305")]
mod chacha8poly1305;

#[cfg(feature = "shared-secret")]
pub struct SharedSecret;
#[cfg(feature = "shared-secret")]
mod shared_secret;

#[cfg(feature = "ed255")]
pub struct Ed255;
#[cfg(feature = "ed255")]
mod ed255;

#[cfg(feature = "hmac-blake2s")]
pub struct HmacBlake2s;
#[cfg(feature = "hmac-blake2s")]
mod hmacblake2s;

#[cfg(feature = "hmac-sha1")]
pub struct HmacSha1;
#[cfg(feature = "hmac-sha1")]
mod hmacsha1;

#[cfg(feature = "hmac-sha256")]
pub struct HmacSha256;
#[cfg(feature = "hmac-sha256")]
mod hmacsha256;

#[cfg(feature = "hmac-sha512")]
pub struct HmacSha512;
#[cfg(feature = "hmac-sha512")]
mod hmacsha512;

#[cfg(feature = "p256")]
pub struct P256;
#[cfg(feature = "p256")]
pub struct P256Prehashed;
#[cfg(feature = "p256")]
mod p256;

#[cfg(feature = "p384")]
pub struct P384;
#[cfg(feature = "p384")]
pub struct P384Prehashed;
#[cfg(feature = "p384")]
mod p384;

#[cfg(feature = "p521")]
pub struct P521;
#[cfg(feature = "p521")]
pub struct P521Prehashed;
#[cfg(feature = "p521")]
mod p521;

#[cfg(feature = "sha256")]
pub struct Sha256;
#[cfg(feature = "sha256")]
mod sha256;

#[cfg(feature = "tdes")]
pub struct Tdes;
#[cfg(feature = "tdes")]
mod tdes;

#[cfg(feature = "totp")]
pub struct Totp;
#[cfg(feature = "totp")]
mod totp;

#[cfg(feature = "trng")]
pub struct Trng;
#[cfg(feature = "trng")]
mod trng;

#[cfg(feature = "x255")]
pub struct X255;
#[cfg(feature = "x255")]
mod x255;
