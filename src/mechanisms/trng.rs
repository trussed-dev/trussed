use crate::api::*;
// use crate::config::*;
use crate::error::Error;
use crate::service::*;
use crate::types::*;

#[cfg(feature = "trng")]
impl GenerateKey for super::Trng
{
    fn generate_key(keystore: &mut impl Keystore, request: request::GenerateKey)
        -> Result<reply::GenerateKey, Error>
    {
        // generate entropy
        let mut entropy = [0u8; 32];
        keystore.drbg().fill_bytes(&mut entropy);

        // store keys
        let key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret,
            key::Kind::Symmetric(32),
            &entropy)?;

        Ok(reply::GenerateKey { key: ObjectHandle { object_id: key_id } })
    }
}

