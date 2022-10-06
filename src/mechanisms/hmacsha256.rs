use crate::api::*;
use crate::error::Error;
use crate::service::*;
use crate::types::*;

#[cfg(feature = "hmac-sha256")]
impl DeriveKey for super::HmacSha256 {
    #[inline(never)]
    fn derive_key(
        keystore: &mut impl Keystore,
        request: &request::DeriveKey,
    ) -> Result<reply::DeriveKey, Error> {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<sha2::Sha256>;

        let key_id = request.base_key;
        let key = keystore.load_key(key::Secrecy::Secret, None, &key_id)?;
        if !matches!(key.kind, key::Kind::Symmetric(..) | key::Kind::Shared(..)) {
            return Err(Error::WrongKeyKind);
        }
        let shared_secret = key.material;

        let mut mac =
            HmacSha256::new_from_slice(shared_secret.as_ref()).map_err(|_| Error::InternalError)?;

        if let Some(additional_data) = &request.additional_data {
            mac.update(additional_data);
        }
        let derived_key: [u8; 32] = mac
            .finalize()
            .into_bytes()
            .try_into()
            .map_err(|_| Error::InternalError)?;
        let key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret,
            key::Kind::Symmetric(32),
            &derived_key,
        )?;

        Ok(reply::DeriveKey { key: key_id })
    }
}

#[cfg(feature = "hmac-sha256")]
impl Sign for super::HmacSha256 {
    #[inline(never)]
    fn sign(keystore: &mut impl Keystore, request: &request::Sign) -> Result<reply::Sign, Error> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let key_id = request.key;
        let key = keystore.load_key(key::Secrecy::Secret, None, &key_id)?;
        if !matches!(key.kind, key::Kind::Symmetric(..) | key::Kind::Shared(..)) {
            return Err(Error::WrongKeyKind);
        }
        let shared_secret = key.material;

        let mut mac =
            HmacSha256::new_from_slice(shared_secret.as_ref()).map_err(|_| Error::InternalError)?;

        mac.update(&request.message);
        let result = mac.finalize();
        let signature = Signature::from_slice(&result.into_bytes()).unwrap();

        Ok(reply::Sign { signature })
    }
}

#[cfg(not(feature = "hmac-sha256"))]
impl DeriveKey for super::HmacSha256 {}
#[cfg(not(feature = "hmac-sha256"))]
impl Sign for super::HmacSha256 {}
