use crate::api::{reply, request};
use crate::error::Error;
use crate::key;
use crate::service::MechanismImpl;
use crate::store::keystore::Keystore;
use crate::types::ShortData;

impl MechanismImpl for super::Sha256 {
    #[inline(never)]
    fn derive_key(
        &self,
        keystore: &mut impl Keystore,
        request: &request::DeriveKey,
    ) -> Result<reply::DeriveKey, Error> {
        let key = keystore.load_key(key::Secrecy::Secret, None, &request.base_key)?;
        if !matches!(key.kind, key::Kind::Symmetric(..) | key::Kind::Shared(..)) {
            return Err(Error::NoSuchKey);
        }
        let shared_secret = key.material;

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

    #[inline(never)]
    fn hash(
        &self,
        _keystore: &mut impl Keystore,
        request: &request::Hash,
    ) -> Result<reply::Hash, Error> {
        use sha2::digest::Digest;
        let mut hash = sha2::Sha256::new();
        hash.update(&request.message);

        let mut hashed = ShortData::new();
        hashed.extend_from_slice(&hash.finalize()).unwrap();

        Ok(reply::Hash { hash: hashed })
    }
}
