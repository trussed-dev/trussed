use core::convert::{TryFrom, TryInto};

use crate::api::*;
// use crate::config::*;
// use crate::debug;
use crate::error::Error;
use crate::service::*;
use crate::types::*;

use salty::agreement;

fn load_public_key(keystore: &mut impl Keystore, key_id: &UniqueId)
    -> Result<agreement::PublicKey, Error> {

    let public_bytes: [u8; 32] = keystore
        .load_key(key::Secrecy::Public, Some(key::Kind::X255), &key_id)?
        .material.as_ref()
        .try_into()
        .map_err(|_| Error::InternalError)?;

    let public_key = agreement::PublicKey::try_from(public_bytes).map_err(|_| Error::InternalError)?;

    Ok(public_key)
}

fn load_secret_key(keystore: &mut impl Keystore, key_id: &UniqueId)
    -> Result<agreement::SecretKey, Error> {

    let seed: [u8; 32] = keystore
        .load_key(key::Secrecy::Secret, Some(key::Kind::X255), &key_id)?
        .material.as_ref()
        .try_into()
        .map_err(|_| Error::InternalError)?;

    let keypair = agreement::SecretKey::from_seed(&seed);
    Ok(keypair)
}

#[cfg(feature = "x255")]
impl Agree for super::X255
{
    fn agree(keystore: &mut impl Keystore, request: request::Agree)
        -> Result<reply::Agree, Error>
    {
        let secret_key = load_secret_key(
            keystore,
            &request.private_key.object_id,
        )?;

        let public_key = load_public_key(
            keystore,
            &request.public_key.object_id,
        )?;

        let shared_secret = secret_key.agree(&public_key).to_bytes();

        let key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret, key::Kind::Shared(32),
            &shared_secret)?;

        // return handle
        Ok(reply::Agree { shared_secret: ObjectHandle { object_id: key_id } })
    }
}

#[cfg(feature = "x255")]
impl GenerateKey for super::X255
{
    fn generate_key(keystore: &mut impl Keystore, request: request::GenerateKey)
        -> Result<reply::GenerateKey, Error>
    {
        // generate keypair
        let mut seed = [0u8; 32];
        keystore.drbg().fill_bytes(&mut seed);

        // store keys
        let key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret, key::Kind::X255,
            &seed)?;

        // return handle
        Ok(reply::GenerateKey { key: ObjectHandle { object_id: key_id } })
    }
}

#[cfg(feature = "x255")]
impl Exists for super::X255
{
    fn exists(keystore: &mut impl Keystore, request: request::Exists)
        -> Result<reply::Exists, Error>
    {
        let key_id = request.key.object_id;
        let exists = keystore.exists_key(key::Secrecy::Secret, Some(key::Kind::X255), &key_id);
        Ok(reply::Exists { exists })
    }
}

#[cfg(feature = "x255")]
impl DeriveKey for super::X255
{
    fn derive_key(keystore: &mut impl Keystore, request: request::DeriveKey)
        -> Result<reply::DeriveKey, Error>
    {
        let base_id = request.base_key.object_id;

        let secret_key = load_secret_key(keystore, &base_id)?;
        let public_key = agreement::PublicKey::from(&secret_key);

        let public_key_bytes = public_key.to_bytes();
        let public_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Public, key::Kind::X255,
            &public_key_bytes)?;

        Ok(reply::DeriveKey {
            key: ObjectHandle { object_id: public_id },
        })
    }
}

#[cfg(feature = "x255")]
impl SerializeKey for super::X255
{
    fn serialize_key(keystore: &mut impl Keystore, request: request::SerializeKey)
        -> Result<reply::SerializeKey, Error>
    {
        let key_id = request.key.object_id;
        let public_key = load_public_key(keystore, &key_id)?;

        let mut serialized_key = Message::new();
        match request.format {
            KeySerialization::Raw => {
                serialized_key.extend_from_slice(&public_key.to_bytes()).map_err(|_| Error::InternalError)?;
            }

            _ => { return Err(Error::InternalError); }
        }

        Ok(reply::SerializeKey { serialized_key })
    }
}

#[cfg(feature = "x255")]
impl DeserializeKey for super::X255
{
    fn deserialize_key(keystore: &mut impl Keystore, request: request::DeserializeKey)
        -> Result<reply::DeserializeKey, Error>
    {
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
        let public_key = salty::agreement::PublicKey::try_from(serialized_key)
            .map_err(|_| Error::InvalidSerializedKey)?;

        let public_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Public, key::Kind::X255,
            &public_key.to_bytes())?;

        Ok(reply::DeserializeKey {
            key: ObjectHandle { object_id: public_id },
        })
    }
}


#[cfg(not(feature = "x255"))]
impl Agree for super::X255 {}
#[cfg(not(feature = "x255"))]
impl GenerateKey for super::X255 {}
#[cfg(not(feature = "x255"))]
impl Exists for super::X255 {}
#[cfg(not(feature = "x255"))]
impl Derive for super::X255 {}
#[cfg(not(feature = "x255"))]
impl SerializeKey for super::X255 {}
#[cfg(not(feature = "x255"))]
impl DeserializeKey for super::X255 {}
