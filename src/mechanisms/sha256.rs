use crate::api::*;
use crate::error::Error;
use crate::service::*;
use crate::types::*;

#[cfg(feature = "sha256")]
impl DeriveKey for super::Sha256 {
    #[inline(never)]
    fn derive_key(
        keystore: &mut impl Keystore,
        request: &request::DeriveKey,
    ) -> Result<reply::DeriveKey, Error> {
        let base_id = &request.base_key;

        let shared_secret = keystore
            .load_key(key::Secrecy::Secret, None, base_id)?
            .material;

        // hash it
        use sha2::digest::Digest;
        let mut hash = sha2::Sha256::new();
        hash.update(&shared_secret);
        let symmetric_key: [u8; 32] = hash.finalize().into();

        let key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret,
            key::Kind::Symmetric(32),
            &symmetric_key,
        )?;

        Ok(reply::DeriveKey { key: key_id })
    }
}

#[cfg(feature = "sha256")]
impl Hash for super::Sha256 {
    #[inline(never)]
    fn hash(_keystore: &mut impl Keystore, request: &request::Hash) -> Result<reply::Hash, Error> {
        use sha2::digest::Digest;
        let mut hash = sha2::Sha256::new();
        hash.update(&request.message);

        let mut hashed = ShortData::new();
        hashed.extend_from_slice(&hash.finalize()).unwrap();

        Ok(reply::Hash { hash: hashed })
    }
}

#[cfg(not(feature = "sha256"))]
impl DeriveKey for super::Sha256 {}
#[cfg(not(feature = "sha256"))]
impl Hash for super::Sha256 {}
