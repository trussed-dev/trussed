use core::convert::TryInto;

use crate::api::*;
use crate::error::Error;
use crate::service::*;
use crate::types::*;

#[cfg(feature = "hmac-blake2s")]
impl DeriveKey for super::HmacBlake2s
{
    #[inline(never)]
    fn derive_key(keystore: &mut impl Keystore, request: &request::DeriveKey)
        -> Result<reply::DeriveKey, Error>
    {
        use hmac::{Hmac, Mac, NewMac};
        type HmacBlake2s = Hmac<blake2::Blake2s>;

        let key_id = request.base_key.object_id;
        let shared_secret = keystore.load_key(key::Secrecy::Secret, None, &key_id)?.material;

        let mut mac = HmacBlake2s::new_from_slice(&shared_secret.as_ref())
            .map_err(|_| Error::InternalError)?;

        if let Some(additional_data) = &request.additional_data {
            mac.update(&additional_data);
        }
        let derived_key: [u8; 32] = mac.finalize().into_bytes().try_into().map_err(|_| Error::InternalError)?;
        let key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret, key::Kind::Symmetric(32),
            &derived_key)?;

        Ok(reply::DeriveKey { key: ObjectHandle { object_id: key_id } })

    }
}

#[cfg(feature = "hmac-blake2s")]
impl Sign for super::HmacBlake2s
{
    #[inline(never)]
    fn sign(keystore: &mut impl Keystore, request: &request::Sign)
        -> Result<reply::Sign, Error>
    {
        use blake2::Blake2s;
        use hmac::{Hmac, Mac, NewMac};
        type HmacBlake2s = Hmac<Blake2s>;

        let key_id = request.key.object_id;
        let shared_secret = keystore.load_key(key::Secrecy::Secret, None, &key_id)?.material;

        let mut mac = HmacBlake2s::new_from_slice(&shared_secret.as_ref())
            .map_err(|_| Error::InternalError)?;

        mac.update(&request.message);
        let result = mac.finalize();
        let signature = Signature::try_from_slice(&result.into_bytes()).unwrap();

        Ok(reply::Sign { signature })

    }
}

#[cfg(not(feature = "hmac-blake2s"))]
impl DeriveKey for super::HmacBlake2s {}
#[cfg(not(feature = "hmac-blake2s"))]
impl Sign for super::HmacBlake2s {}
