use crate::api::{reply, request};
use crate::error::Error;
use crate::key;
use crate::service::{DeriveKey, Sign};
use crate::store::keystore::Keystore;
use crate::types::Signature;

impl DeriveKey for super::HmacSha1 {
    #[inline(never)]
    fn derive_key(
        keystore: &mut impl Keystore,
        request: &request::DeriveKey,
    ) -> Result<reply::DeriveKey, Error> {
        use hmac::{Hmac, Mac};
        type HmacSha1 = Hmac<sha1::Sha1>;

        let key_id = request.base_key;
        let key = keystore.load_key(key::Secrecy::Secret, None, &key_id)?;
        if !matches!(key.kind, key::Kind::Symmetric(..) | key::Kind::Shared(..)) {
            return Err(Error::WrongKeyKind);
        }
        let shared_secret = key.material;

        let mut mac =
            HmacSha1::new_from_slice(shared_secret.as_ref()).map_err(|_| Error::InternalError)?;

        if let Some(additional_data) = &request.additional_data {
            mac.update(additional_data);
        }
        let derived_key: [u8; 20] = mac.finalize().into_bytes().into();
        let key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret,
            key::Kind::Symmetric(20),
            &derived_key,
        )?;

        Ok(reply::DeriveKey { key: key_id })
    }
}

impl Sign for super::HmacSha1 {
    #[inline(never)]
    fn sign(keystore: &mut impl Keystore, request: &request::Sign) -> Result<reply::Sign, Error> {
        use hmac::{Hmac, Mac};
        use sha1::Sha1;
        type HmacSha1 = Hmac<Sha1>;

        let key_id = request.key;
        let key = keystore.load_key(key::Secrecy::Secret, None, &key_id)?;
        if !matches!(key.kind, key::Kind::Symmetric(..) | key::Kind::Shared(..)) {
            return Err(Error::WrongKeyKind);
        }
        let shared_secret = key.material;

        let mut mac =
            HmacSha1::new_from_slice(shared_secret.as_ref()).map_err(|_| Error::InternalError)?;

        mac.update(&request.message);
        let result = mac.finalize();
        let signature = Signature::from_slice(&result.into_bytes()).unwrap();

        Ok(reply::Sign { signature })
    }
}
