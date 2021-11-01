use core::convert::{TryFrom, TryInto};

use crate::api::*;
// use crate::config::*;
// use crate::debug;
use crate::error::Error;
use crate::service::*;
use crate::types::*;

#[inline(never)]
fn load_public_key(
    keystore: &mut impl Keystore,
    key_id: &KeyId,
) -> Result<salty::PublicKey, Error> {
    let public_bytes: [u8; 256] = keystore
        .load_key(key::Secrecy::Public, Some(key::Kind::Rsa2k), &key_id)?
        .material
        .as_slice()
        .try_into()
        .map_err(|_| Error::InternalError)?;

    let public_key =
        salty::signature::PublicKey::try_from(&public_bytes).map_err(|_| Error::InternalError)?;

    Ok(public_key)
}

#[inline(never)]
fn load_keypair(keystore: &mut impl Keystore, key_id: &KeyId) -> Result<salty::Keypair, Error> {
    let seed: [u8; 32] = keystore
        .load_key(key::Secrecy::Secret, Some(key::Kind::Ed255), &key_id)?
        .material
        .as_slice()
        .try_into()
        .map_err(|_| Error::InternalError)?;

    let keypair = salty::signature::Keypair::from(&seed);
    // hprintln!("seed: {:?}", &seed).ok();
    Ok(keypair)
}

#[cfg(feature = "ed255")]
impl DeriveKey for super::Ed255 {
    #[inline(never)]
    fn derive_key(
        keystore: &mut impl Keystore,
        request: &request::DeriveKey,
    ) -> Result<reply::DeriveKey, Error> {
        let base_id = &request.base_key;
        let keypair = load_keypair(keystore, base_id)?;

        let public_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Public,
            key::Kind::Ed255,
            keypair.public.as_bytes(),
        )?;

        Ok(reply::DeriveKey { key: public_id })
    }
}

#[cfg(feature = "ed255")]
impl DeserializeKey for super::Ed255 {
    #[inline(never)]
    fn deserialize_key(
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
        let public_key = salty::signature::PublicKey::try_from(&serialized_key)
            .map_err(|_| Error::InvalidSerializedKey)?;

        let public_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Public,
            key::Kind::Ed255,
            public_key.as_bytes(),
        )?;

        Ok(reply::DeserializeKey { key: public_id })
    }
}

#[cfg(feature = "ed255")]
impl GenerateKey for super::Ed255 {
    #[inline(never)]
    fn generate_key(
        keystore: &mut impl Keystore,
        request: &request::GenerateKey,
    ) -> Result<reply::GenerateKey, Error> {
        let mut seed = [0u8; 32];
        keystore.rng().fill_bytes(&mut seed);

        // let keypair = salty::signature::Keypair::from(&seed);
        // #[cfg(all(test, feature = "verbose-tests"))]
        // println!("ed255 keypair with public key = {:?}", &keypair.public);

        // store keys
        let key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret,
            key::Info::from(key::Kind::Ed255).with_local_flag(),
            &seed,
        )?;

        // return handle
        Ok(reply::GenerateKey { key: key_id })
    }
}

#[cfg(feature = "ed255")]
impl SerializeKey for super::Ed255 {
    #[inline(never)]
    fn serialize_key(
        keystore: &mut impl Keystore,
        request: &request::SerializeKey,
    ) -> Result<reply::SerializeKey, Error> {
        let key_id = request.key;
        let public_key = load_public_key(keystore, &key_id)?;

        let serialized_key = match request.format {
            KeySerialization::Cose => {
                let cose_pk = cosey::Ed25519PublicKey {
                    // x: Bytes::from_slice(public_key.x_coordinate()).unwrap(),
                    // x: Bytes::from_slice(&buf).unwrap(),
                    x: Bytes::from_slice(public_key.as_bytes()).unwrap(),
                };
                crate::cbor_serialize_bytes(&cose_pk).map_err(|_| Error::CborError)?
            }

            KeySerialization::Raw => {
                let mut serialized_key = Message::new();
                serialized_key
                    .extend_from_slice(public_key.as_bytes())
                    .map_err(|_| Error::InternalError)?;
                // serialized_key.extend_from_slice(&buf).map_err(|_| Error::InternalError)?;
                serialized_key
            }

            _ => {
                return Err(Error::InternalError);
            }
        };

        Ok(reply::SerializeKey { serialized_key })
    }
}

#[cfg(feature = "ed255")]
impl Exists for super::Ed255 {
    #[inline(never)]
    fn exists(
        keystore: &mut impl Keystore,
        request: &request::Exists,
    ) -> Result<reply::Exists, Error> {
        let key_id = request.key;

        let exists = keystore.exists_key(key::Secrecy::Secret, Some(key::Kind::Ed255), &key_id);
        Ok(reply::Exists { exists })
    }
}

#[cfg(feature = "ed255")]
impl Sign for super::Ed255 {
    #[inline(never)]
    fn sign(keystore: &mut impl Keystore, request: &request::Sign) -> Result<reply::Sign, Error> {
        // Not so nice, expands to
        // `trussed::/home/nicolas/projects/solo-bee/components/trussed/src/mechanisms/ed255.rs:151
        // Ed255::Sign`, i.e. VEERY long
        // debug!("trussed::{}:{} Ed255::Sign", file!(), line!()).ok();
        // debug!("trussed: Ed255::Sign").ok();
        // if let SignatureSerialization::Raw = request.format {
        // } else {
        //     return Err(Error::InvalidSerializationFormat);
        // }

        let key_id = request.key;

        let keypair = load_keypair(keystore, &key_id)?;

        let native_signature = keypair.sign(&request.message);
        let our_signature = Signature::from_slice(&native_signature.to_bytes()).unwrap();

        // hprintln!("Ed255 signature:").ok();
        // hprintln!("msg: {:?}", &request.message).ok();
        // hprintln!("pk:  {:?}", &keypair.public.as_bytes()).ok();
        // hprintln!("sig: {:?}", &our_signature).ok();

        // return signature
        Ok(reply::Sign {
            signature: our_signature,
        })
    }
}

#[cfg(feature = "ed255")]
impl Verify for super::Ed255 {
    #[inline(never)]
    fn verify(
        keystore: &mut impl Keystore,
        request: &request::Verify,
    ) -> Result<reply::Verify, Error> {
        if let SignatureSerialization::Raw = request.format {
        } else {
            return Err(Error::InvalidSerializationFormat);
        }

        if request.signature.len() != salty::constants::SIGNATURE_SERIALIZED_LENGTH {
            return Err(Error::WrongSignatureLength);
        }

        let key_id = request.key;
        let public_key = load_public_key(keystore, &key_id)?;

        let mut signature_array = [0u8; salty::constants::SIGNATURE_SERIALIZED_LENGTH];
        signature_array.copy_from_slice(request.signature.as_ref());
        let salty_signature = salty::signature::Signature::from(&signature_array);

        Ok(reply::Verify {
            valid: public_key
                .verify(&request.message, &salty_signature)
                .is_ok(),
        })
    }
}

#[cfg(not(feature = "ed255"))]
impl DeriveKey for super::Ed255 {}
#[cfg(not(feature = "ed255"))]
impl GenerateKey for super::Ed255 {}
#[cfg(not(feature = "ed255"))]
impl Sign for super::Ed255 {}
#[cfg(not(feature = "ed255"))]
impl Verify for super::Ed255 {}
