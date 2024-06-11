use rand_core::RngCore;

use crate::api::{reply, request};
use crate::error::Error;
use crate::key;
use crate::service::MechanismImpl;
use crate::store::keystore::Keystore;

#[cfg(feature = "trng")]
impl MechanismImpl for super::Trng {
    fn generate_key(
        &self,
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
            key::Kind::Symmetric(32).into(),
            &entropy,
        )?;

        Ok(reply::GenerateKey { key: key_id })
    }
}
