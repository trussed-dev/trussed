use core::convert::TryInto;

use crate::api::*;
// use crate::config::*;
use crate::error::Error;
use crate::service::*;
use crate::types::*;

#[cfg(feature = "sha256")]
impl DeriveKey for super::Sha256
{
    fn derive_key(keystore: &mut impl Keystore, request: request::DeriveKey)
        -> Result<reply::DeriveKey, Error>
    {
        let base_id = &request.base_key.object_id;

        let shared_secret: [u8; 32] = keystore
            .load_key(key::Secrecy::Secret, Some(key::Kind::SharedSecret32), base_id)?
            .material.as_ref()
            .try_into()
            .map_err(|_| Error::InternalError)?;

        // hash it
        use sha2::digest::Digest;
        let mut hash = sha2::Sha256::new();
        hash.update(&shared_secret);
        let symmetric_key: [u8; 32] = hash.finalize().into();

        let key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret, key::Kind::SymmetricKey32,
            &symmetric_key)?;
            // keystore.generate_unique_id()?;

        Ok(reply::DeriveKey {
            key: ObjectHandle { object_id: key_id },
        })
    }
}

#[cfg(feature = "sha256")]
impl Hash for super::Sha256
{
    fn hash(_keystore: &mut impl Keystore, request: request::Hash)
        -> Result<reply::Hash, Error>
    {
        use sha2::digest::Digest;
        let mut hash = sha2::Sha256::new();
        hash.update(&request.message);

        let mut hashed = ShortData::new();
        hashed.extend_from_slice(&hash.finalize()).unwrap();

        Ok(reply::Hash { hash: hashed } )
    }
}

// impl // Agree for super::P256 {}
#[cfg(not(feature = "sha256"))]
impl DeriveKey for super::Sha256 {}
// impl // GenerateKey for super::P256 {}
// impl // Sign for super::P256 {}
// impl // Verify for super::P256 {}
