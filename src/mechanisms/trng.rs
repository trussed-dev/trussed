use rand_core::RngCore;

use crate::api::{reply, request};
use crate::error::Error;
use crate::key;
use crate::service::GenerateKey;
use crate::store::keystore::Keystore;

#[cfg(feature = "trng")]
impl GenerateKey for super::Trng {
    fn generate_key(
        keystore: &mut impl Keystore,
        request: &request::GenerateKey,
    ) -> Result<reply::GenerateKey, Error> {
        // generate entropy
        let mut entropy = [0u8; 32];
        keystore.rng().fill_bytes(&mut entropy);

        // store keys
        let key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret,
            key::Kind::Symmetric(32),
            &entropy,
        )?;

        Ok(reply::GenerateKey { key: key_id })
    }
}
