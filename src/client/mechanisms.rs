use super::ClientImplementation;
use crate::platform::Syscall;

#[cfg(feature = "aes256-cbc")]
pub use trussed_core::client::Aes256Cbc;
#[cfg(feature = "chacha8-poly1305")]
pub use trussed_core::client::Chacha8Poly1305;
#[cfg(feature = "ed255")]
pub use trussed_core::client::Ed255;
#[cfg(feature = "hmac-blake2s")]
pub use trussed_core::client::HmacBlake2s;
#[cfg(feature = "hmac-sha1")]
pub use trussed_core::client::HmacSha1;
#[cfg(feature = "hmac-sha256")]
pub use trussed_core::client::HmacSha256;
#[cfg(feature = "hmac-sha512")]
pub use trussed_core::client::HmacSha512;
#[cfg(feature = "sha256")]
pub use trussed_core::client::Sha256;
#[cfg(feature = "tdes")]
pub use trussed_core::client::Tdes;
#[cfg(feature = "totp")]
pub use trussed_core::client::Totp;
#[cfg(feature = "p256")]
pub use trussed_core::client::P256;
#[cfg(feature = "p384")]
pub use trussed_core::client::P384;
#[cfg(feature = "p521")]
pub use trussed_core::client::P521;
#[cfg(feature = "x255")]
pub use trussed_core::client::X255;

#[cfg(feature = "aes256-cbc")]
impl<S: Syscall, E> Aes256Cbc for ClientImplementation<S, E> {}

#[cfg(feature = "chacha8-poly1305")]
impl<S: Syscall, E> Chacha8Poly1305 for ClientImplementation<S, E> {}

#[cfg(feature = "hmac-blake2s")]
impl<S: Syscall, E> HmacBlake2s for ClientImplementation<S, E> {}

#[cfg(feature = "hmac-sha1")]
impl<S: Syscall, E> HmacSha1 for ClientImplementation<S, E> {}

#[cfg(feature = "hmac-sha256")]
impl<S: Syscall, E> HmacSha256 for ClientImplementation<S, E> {}

#[cfg(feature = "hmac-sha512")]
impl<S: Syscall, E> HmacSha512 for ClientImplementation<S, E> {}

#[cfg(feature = "ed255")]
impl<S: Syscall, E> Ed255 for ClientImplementation<S, E> {}

#[cfg(feature = "p256")]
impl<S: Syscall, E> P256 for ClientImplementation<S, E> {}

#[cfg(feature = "p384")]
impl<S: Syscall, E> P384 for ClientImplementation<S, E> {}

#[cfg(feature = "p521")]
impl<S: Syscall, E> P521 for ClientImplementation<S, E> {}

#[cfg(feature = "sha256")]
impl<S: Syscall, E> Sha256 for ClientImplementation<S, E> {}

#[cfg(feature = "tdes")]
impl<S: Syscall, E> Tdes for ClientImplementation<S, E> {}

#[cfg(feature = "totp")]
impl<S: Syscall, E> Totp for ClientImplementation<S, E> {}

#[cfg(feature = "x255")]
impl<S: Syscall, E> X255 for ClientImplementation<S, E> {}
