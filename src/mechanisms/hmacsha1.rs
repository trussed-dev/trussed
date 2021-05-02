use core::convert::TryInto;

use crate::api::*;
use crate::error::Error;
use crate::service::*;
use crate::types::*;

#[cfg(feature = "hmac-sha1")]
impl DeriveKey for super::HmacSha1
{
    #[inline(never)]
    fn derive_key(keystore: &mut impl Keystore, request: &request::DeriveKey)
        -> Result<reply::DeriveKey, Error>
    {
        use hmac::{Hmac, Mac, NewMac};
        type HmacSha1 = Hmac<sha1::Sha1>;

        let key_id = request.base_key.object_id;
        let shared_secret = keystore.load_key(key::Secrecy::Secret, None, &key_id)?.material;

        let mut mac = HmacSha1::new_from_slice(&shared_secret.as_ref())
            .map_err(|_| Error::InternalError)?;

        if let Some(additional_data) = &request.additional_data {
            mac.update(&additional_data);
        }
        let derived_key: [u8; 20] = mac.finalize().into_bytes().try_into().map_err(|_| Error::InternalError)?;
        let key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret, key::Kind::Symmetric(20),
            &derived_key)?;

        Ok(reply::DeriveKey { key: ObjectHandle { object_id: key_id } })

    }
}

#[cfg(feature = "hmac-sha1")]
impl Sign for super::HmacSha1
{
    #[inline(never)]
    fn sign(keystore: &mut impl Keystore, request: &request::Sign)
        -> Result<reply::Sign, Error>
    {
        use sha1::Sha1;
        use hmac::{Hmac, Mac, NewMac};
        type HmacSha1 = Hmac<Sha1>;

        let key_id = request.key.object_id;
        let shared_secret = keystore.load_key(key::Secrecy::Secret, None, &key_id)?.material;

        let mut mac = HmacSha1::new_from_slice(&shared_secret.as_ref())
            .map_err(|_| Error::InternalError)?;

        mac.update(&request.message);
        let result = mac.finalize();
        let signature = Signature::try_from_slice(&result.into_bytes()).unwrap();

        Ok(reply::Sign { signature })

    }
}

#[cfg(not(feature = "hmac-sha1"))]
impl DeriveKey for super::HmacSha1 {}
#[cfg(not(feature = "hmac-sha1"))]
impl Sign for super::HmacSha1 {}
