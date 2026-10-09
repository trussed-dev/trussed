use super::{ClientImplementation, MultiplexedClient};
use crate::platform::Syscall;

use trussed_core::mechanisms::*;

/// Implements each mechanism trait for both client types, so the two can never
/// drift apart.
macro_rules! impl_mechanisms {
    ($($feature:literal => $name:ident,)*) => {$(
        #[cfg(feature = $feature)]
        impl<S: Syscall, E> $name for ClientImplementation<'_, S, E> {}
        #[cfg(feature = $feature)]
        impl<S: Syscall, E> $name for MultiplexedClient<S, E> {}
    )*};
}

impl_mechanisms! {
    "aes256-cbc" => Aes256Cbc,
    "aes256-gcm" => Aes256Gcm,
    "chacha8-poly1305" => Chacha8Poly1305,
    "hmac-blake2s" => HmacBlake2s,
    "hmac-sha1" => HmacSha1,
    "hmac-sha256" => HmacSha256,
    "hmac-sha512" => HmacSha512,
    "mldsa44" => MlDsa44,
    "ed255" => Ed255,
    "p256" => P256,
    "p384" => P384,
    "p521" => P521,
    "sha256" => Sha256,
    "tdes" => Tdes,
    "totp" => Totp,
    "x255" => X255,
}
