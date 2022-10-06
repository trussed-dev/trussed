use crate::api::*;
use crate::error::Error;
use crate::service::*;
use crate::types::*;

#[cfg(feature = "hmac-blake2s")]
impl DeriveKey for super::HmacBlake2s {
    #[inline(never)]
    fn derive_key(
        keystore: &mut impl Keystore,
        request: &request::DeriveKey,
    ) -> Result<reply::DeriveKey, Error> {
        use blake2::Blake2s256;
        use hmac::{Mac, SimpleHmac};
        type HmacBlake2s = SimpleHmac<Blake2s256>;

        let key = keystore.load_key(key::Secrecy::Secret, None, &request.base_key)?;
        if !matches!(key.kind, key::Kind::Symmetric(..) | key::Kind::Shared(..)) {
            return Err(Error::WrongKeyKind);
        }
        let shared_secret = key.material;

        let mut mac = HmacBlake2s::new_from_slice(shared_secret.as_ref())
            .map_err(|_| Error::InternalError)?;

        if let Some(additional_data) = &request.additional_data {
            mac.update(additional_data);
        }
        let derived_key: [u8; 32] = mac
            .finalize()
            .into_bytes()
            .try_into()
            .map_err(|_| Error::InternalError)?;
        let key = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret,
            key::Kind::Symmetric(32),
            &derived_key,
        )?;

        Ok(reply::DeriveKey { key })
    }
}

#[cfg(feature = "hmac-blake2s")]
impl Sign for super::HmacBlake2s {
    #[inline(never)]
    fn sign(keystore: &mut impl Keystore, request: &request::Sign) -> Result<reply::Sign, Error> {
        use blake2::Blake2s256;
        use hmac::{Mac, SimpleHmac};
        type HmacBlake2s = SimpleHmac<Blake2s256>;

        let key = keystore.load_key(key::Secrecy::Secret, None, &request.key)?;
        if !matches!(key.kind, key::Kind::Symmetric(..) | key::Kind::Shared(..)) {
            return Err(Error::WrongKeyKind);
        }
        let shared_secret = key.material;

        let mut mac = HmacBlake2s::new_from_slice(shared_secret.as_ref())
            .map_err(|_| Error::InternalError)?;

        mac.update(&request.message);
        let result = mac.finalize();
        let signature = Signature::from_slice(&result.into_bytes()).unwrap();

        Ok(reply::Sign { signature })
    }
}

#[cfg(not(feature = "hmac-blake2s"))]
impl DeriveKey for super::HmacBlake2s {}
#[cfg(not(feature = "hmac-blake2s"))]
impl Sign for super::HmacBlake2s {}
