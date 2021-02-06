use core::convert::{TryFrom, TryInto};

use crate::api::*;
// use crate::config::*;
// use crate::debug;
use crate::error::Error;
use crate::service::*;
use crate::types::*;

use salty::agreement;

fn load_public_key<P: Platform>(resources: &mut ServiceResources<P>, key_id: &UniqueId)
    -> Result<agreement::PublicKey, Error> {

    let public_bytes: [u8; 32] = resources
        .load_key(KeyType::Public, Some(KeyKind::X255), &key_id)?
        .value.as_ref()
        .try_into()
        .map_err(|_| Error::InternalError)?;

    let public_key = agreement::PublicKey::try_from(public_bytes).map_err(|_| Error::InternalError)?;

    Ok(public_key)
}

fn load_secret_key<P: Platform>(resources: &mut ServiceResources<P>, key_id: &UniqueId)
    -> Result<agreement::SecretKey, Error> {

    let seed: [u8; 32] = resources
        .load_key(KeyType::Secret, Some(KeyKind::X255), &key_id)?
        .value.as_ref()
        .try_into()
        .map_err(|_| Error::InternalError)?;

    let keypair = agreement::SecretKey::from_seed(&seed);
    Ok(keypair)
}

#[cfg(feature = "x255")]
impl<P: Platform>
Agree<P> for super::X255
{
    fn agree(resources: &mut ServiceResources<P>, request: request::Agree)
        -> Result<reply::Agree, Error>
    {
        let secret_key = load_secret_key(
            resources,
            &request.private_key.object_id,
        )?;

        let public_key = load_public_key(
            resources,
            &request.public_key.object_id,
        )?;

        let shared_secret = secret_key.agree(&public_key).to_bytes();

        let key_id = resources.store_key(
            request.attributes.persistence,
            KeyType::Secret, KeyKind::SharedSecret32,
            &shared_secret)?;

        // return handle
        Ok(reply::Agree { shared_secret: ObjectHandle { object_id: key_id } })
    }
}

#[cfg(feature = "x255")]
impl<P: Platform>
GenerateKey<P> for super::X255
{
    fn generate_key(resources: &mut ServiceResources<P>, request: request::GenerateKey)
        -> Result<reply::GenerateKey, Error>
    {
        // generate keypair
        let mut seed = [0u8; 32];
        resources.fill_random_bytes(&mut seed)
            .map_err(|_| Error::EntropyMalfunction)?;

        // store keys
        let key_id = resources.store_key(
            request.attributes.persistence,
            KeyType::Secret, KeyKind::X255,
            &seed)?;

        // return handle
        Ok(reply::GenerateKey { key: ObjectHandle { object_id: key_id } })
    }
}

#[cfg(feature = "x255")]
impl<P: Platform>
Exists<P> for super::X255
{
    fn exists(resources: &mut ServiceResources<P>, request: request::Exists)
        -> Result<reply::Exists, Error>
    {
        let key_id = request.key.object_id;
        let exists = resources.exists_key(KeyType::Secret, Some(KeyKind::X255), &key_id);
        Ok(reply::Exists { exists })
    }
}

#[cfg(feature = "x255")]
impl<P: Platform>
DeriveKey<P> for super::X255
{
    fn derive_key(resources: &mut ServiceResources<P>, request: request::DeriveKey)
        -> Result<reply::DeriveKey, Error>
    {
        let base_id = request.base_key.object_id;

        let secret_key = load_secret_key(resources, &base_id)?;
        let public_key = agreement::PublicKey::from(&secret_key);

        let public_key_bytes = public_key.to_bytes();
        let public_id = resources.store_key(
            request.attributes.persistence,
            KeyType::Public, KeyKind::X255,
            &public_key_bytes)?;

        Ok(reply::DeriveKey {
            key: ObjectHandle { object_id: public_id },
        })
    }
}

#[cfg(feature = "x255")]
impl<P: Platform>
SerializeKey<P> for super::X255
{
    fn serialize_key(resources: &mut ServiceResources<P>, request: request::SerializeKey)
        -> Result<reply::SerializeKey, Error>
    {
        let key_id = request.key.object_id;
        let public_key = load_public_key(resources, &key_id)?;

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
impl<P: Platform>
DeserializeKey<P> for super::X255
{
    fn deserialize_key(resources: &mut ServiceResources<P>, request: request::DeserializeKey)
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

        let public_id = resources.store_key(
            request.attributes.persistence,
            KeyType::Public, KeyKind::X255,
            &public_key.to_bytes())?;

        Ok(reply::DeserializeKey {
            key: ObjectHandle { object_id: public_id },
        })
    }
}


#[cfg(not(feature = "x255"))]
impl<P: Platform>
Agree<P> for super::X255 {}
#[cfg(not(feature = "x255"))]
impl<P: Platform>
GenerateKey<P> for super::X255 {}
#[cfg(not(feature = "x255"))]
impl<P: Platform>
Exists<P> for super::X255 {}
#[cfg(not(feature = "x255"))]
impl<P: Platform>
Derive<P> for super::X255 {}
#[cfg(not(feature = "x255"))]
impl<P: Platform>
SerializeKey<P> for super::X255 {}
#[cfg(not(feature = "x255"))]
impl<P: Platform>
DeserializeKey<P> for super::X255 {}
