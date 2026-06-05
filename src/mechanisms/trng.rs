use rand_core::RngCore;
use trussed_core::{
    api::{reply, request},
    Error,
};

use crate::key;
use crate::service::MechanismImpl;
use crate::store::Keystore;

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
            key::Kind::Symmetric(32),
            &entropy,
        )?;

        Ok(reply::GenerateKey { key: key_id })
    }
}
