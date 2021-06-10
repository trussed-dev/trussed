use crate::api::*;
use crate::error::Error;
use crate::service::*;
use crate::types::*;

#[cfg(feature = "hmac-sha512")]
impl DeriveKey for super::HmacSha512
{
    #[inline(never)]
    fn derive_key(keystore: &mut impl Keystore, request: &request::DeriveKey)
        -> Result<reply::DeriveKey, Error>
    {
        use hmac::{Hmac, Mac, NewMac};
        type HmacSha512 = Hmac<sha2::Sha512>;

        let key_id = request.base_key.object_id;
        let shared_secret = keystore.load_key(key::Secrecy::Secret, None, &key_id)?.material;

        let mut mac = HmacSha512::new_varkey(&shared_secret.as_ref())
            .map_err(|_| Error::InternalError)?;

        if let Some(additional_data) = &request.additional_data {
            mac.update(&additional_data);
        }
        let mut derived_key = [0u8; 64];
        derived_key.copy_from_slice(&mac.finalize().into_bytes());//.try_into().map_err(|_| Error::InternalError)?;
        let key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret, key::Kind::Symmetric(64),
            &derived_key)?;

        Ok(reply::DeriveKey { key: ObjectHandle { object_id: key_id } })
    }
}

#[cfg(feature = "hmac-sha512")]
impl Sign for super::HmacSha512
{
    #[inline(never)]
    fn sign(keystore: &mut impl Keystore, request: &request::Sign)
        -> Result<reply::Sign, Error>
    {
        use sha2::Sha512;
        use hmac::{Hmac, Mac, NewMac};
        type HmacSha512 = Hmac<Sha512>;

        let key_id = request.key.object_id;
        let shared_secret = keystore.load_key(key::Secrecy::Secret, None, &key_id)?.material;

        let mut mac = HmacSha512::new_varkey(&shared_secret.as_ref())
            .map_err(|_| Error::InternalError)?;

        mac.update(&request.message);
        let result = mac.finalize();
        let signature = Signature::from_slice(&result.into_bytes()).unwrap();

        Ok(reply::Sign { signature })

    }
}


#[cfg(not(feature = "hmac-sha512"))]
impl DeriveKey for super::HmacSha512 {}
#[cfg(not(feature = "hmac-sha512"))]
impl Sign for super::HmacSha512 {}
