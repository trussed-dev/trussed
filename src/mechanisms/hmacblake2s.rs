use crate::api::{reply, request};
use crate::error::Error;
use crate::key;
use crate::service::MechanismImpl;
use crate::store::keystore::Keystore;
use crate::types::Signature;

#[cfg(feature = "hmac-blake2s")]
impl MechanismImpl for super::HmacBlake2s {
    #[inline(never)]
    fn derive_key(
        &self,
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
        let derived_key: [u8; 32] = mac.finalize().into_bytes().into();
        let key = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret,
            key::Kind::Symmetric(32).into(),
            &derived_key,
        )?;

        Ok(reply::DeriveKey { key })
    }

    #[inline(never)]
    fn sign(
        &self,
        keystore: &mut impl Keystore,
        request: &request::Sign,
    ) -> Result<reply::Sign, Error> {
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
impl MechanismImpl for super::HmacBlake2s {}
