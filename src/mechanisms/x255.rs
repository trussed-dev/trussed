use rand_core::RngCore;
use salty::agreement;

use crate::api::{reply, request};
use crate::error::Error;
use crate::key;
use crate::service::MechanismImpl;
use crate::store::keystore::Keystore;
use crate::types::{KeyId, KeySerialization, SerializedKey};

fn load_public_key(
    keystore: &mut impl Keystore,
    key_id: &KeyId,
) -> Result<agreement::PublicKey, Error> {
    let public_bytes: [u8; 32] = keystore
        .load_key(key::Secrecy::Public, Some(key::Kind::X255), key_id)?
        .material
        .as_slice()
        .try_into()
        .map_err(|_| Error::InternalError)?;

    let public_key = public_bytes.into();

    Ok(public_key)
}

fn load_secret_key(
    keystore: &mut impl Keystore,
    key_id: &KeyId,
) -> Result<agreement::SecretKey, Error> {
    let seed: [u8; 32] = keystore
        .load_key(key::Secrecy::Secret, Some(key::Kind::X255), key_id)?
        .material
        .as_slice()
        .try_into()
        .map_err(|_| Error::InternalError)?;

    let keypair = agreement::SecretKey::from_seed(&seed);
    Ok(keypair)
}

#[cfg(feature = "x255")]
impl MechanismImpl for super::X255 {
    // #[inline(never)]
    fn agree(
        &self,
        keystore: &mut impl Keystore,
        request: &request::Agree,
    ) -> Result<reply::Agree, Error> {
        let secret_key = load_secret_key(keystore, &request.private_key)?;

        let public_key = load_public_key(keystore, &request.public_key)?;

        let shared_secret = secret_key.agree(&public_key).to_bytes();

        let flags = if request.attributes.serializable {
            key::Flags::SERIALIZABLE
        } else {
            key::Flags::empty()
        };
        let info = key::Info {
            kind: key::Kind::Shared(shared_secret.len()),
            flags,
        };

        let key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret,
            info,
            &shared_secret,
        )?;

        // return handle
        Ok(reply::Agree {
            shared_secret: key_id,
        })
    }

    // #[inline(never)]
    fn generate_key(
        &self,
        keystore: &mut impl Keystore,
        request: &request::GenerateKey,
    ) -> Result<reply::GenerateKey, Error> {
        // generate keypair
        let mut seed = [0u8; 32];
        keystore.rng().fill_bytes(&mut seed);

        // store keys
        let key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret,
            key::Info::from(key::Kind::X255).with_local_flag(),
            &seed,
        )?;

        // return handle
        Ok(reply::GenerateKey { key: key_id })
    }

    // #[inline(never)]
    fn exists(
        &self,
        keystore: &mut impl Keystore,
        request: &request::Exists,
    ) -> Result<reply::Exists, Error> {
        let key_id = request.key;
        let exists = keystore.exists_key(key::Secrecy::Secret, Some(key::Kind::X255), &key_id);
        Ok(reply::Exists { exists })
    }

    // #[inline(never)]
    fn derive_key(
        &self,
        keystore: &mut impl Keystore,
        request: &request::DeriveKey,
    ) -> Result<reply::DeriveKey, Error> {
        let base_id = request.base_key;

        let secret_key = load_secret_key(keystore, &base_id)?;
        let public_key = agreement::PublicKey::from(&secret_key);

        let public_key_bytes = public_key.to_bytes();
        let public_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Public,
            key::Kind::X255.into(),
            &public_key_bytes,
        )?;

        Ok(reply::DeriveKey { key: public_id })
    }

    // #[inline(never)]
    fn serialize_key(
        &self,
        keystore: &mut impl Keystore,
        request: &request::SerializeKey,
    ) -> Result<reply::SerializeKey, Error> {
        let key_id = request.key;
        let public_key = load_public_key(keystore, &key_id)?;

        let mut serialized_key = SerializedKey::new();
        match request.format {
            KeySerialization::Raw => {
                serialized_key
                    .extend_from_slice(&public_key.to_bytes())
                    .map_err(|_| Error::InternalError)?;
            }

            _ => {
                return Err(Error::InternalError);
            }
        }

        Ok(reply::SerializeKey { serialized_key })
    }

    // #[inline(never)]
    fn deserialize_key(
        &self,
        keystore: &mut impl Keystore,
        request: &request::DeserializeKey,
    ) -> Result<reply::DeserializeKey, Error> {
        // - mechanism: Mechanism
        // - serialized_key: Message
        // - attributes: StorageAttributes

        if request.format != KeySerialization::Raw {
            return Err(Error::InternalError);
        }

        if request.serialized_key.len() != 32 {
            return Err(Error::InvalidSerializedKey);
        }

        let serialized_key: [u8; 32] = request.serialized_key[..32].try_into().unwrap();
        // This will make it store the canonical encoding
        let public_key: agreement::PublicKey = serialized_key.into();

        let public_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Public,
            key::Kind::X255.into(),
            &public_key.to_bytes(),
        )?;

        Ok(reply::DeserializeKey { key: public_id })
    }

    fn unsafe_inject_key(
        &self,
        keystore: &mut impl Keystore,
        request: &request::UnsafeInjectKey,
    ) -> Result<reply::UnsafeInjectKey, Error> {
        if request.format != KeySerialization::Raw {
            return Err(Error::InvalidSerializationFormat);
        }
        let seed = (**request.raw_key)
            .try_into()
            .map_err(|_| Error::InvalidSerializedKey)?;
        let sk = agreement::SecretKey::from_seed(&seed);
        let info = key::Info {
            flags: key::Flags::SENSITIVE,
            kind: key::Kind::X255,
        };

        keystore
            .store_key(
                request.attributes.persistence,
                key::Secrecy::Secret,
                info,
                &sk.to_bytes(),
            )
            .map(|key| reply::UnsafeInjectKey { key })
    }
}

#[cfg(not(feature = "x255"))]
impl MechanismImpl for super::X255 {}
