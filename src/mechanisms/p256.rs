use core::convert::{TryFrom, TryInto};

use crate::api::*;
use crate::error::Error;
use crate::service::*;
use crate::types::*;

    #[inline(never)]
fn load_keypair(keystore: &mut impl Keystore, key_id: &UniqueId)
    -> Result<nisty::Keypair, Error> {

    // info_now!("loading keypair");
    let seed: [u8; 32] = keystore
        .load_key(key::Secrecy::Secret, Some(key::Kind::P256), &key_id)?
        .material.as_ref()
        .try_into()
        .map_err(|_| Error::InternalError)?;

    let keypair = nisty::Keypair::generate_patiently(&seed);
    // info_now!("seed: {:?}", &seed);
    Ok(keypair)
}

    #[inline(never)]
fn load_public_key(keystore: &mut impl Keystore, key_id: &UniqueId)
    -> Result<nisty::PublicKey, Error> {

    let public_bytes = keystore
        .load_key(key::Secrecy::Public, Some(key::Kind::P256), &key_id)?
        .material;

    let public_bytes = match public_bytes.as_ref().len() {
        64 => {
            let mut public_bytes_ = [0u8; 64];
            public_bytes_.copy_from_slice(&public_bytes.as_ref());
            public_bytes_
        }
        _ => {
            return Err(Error::InternalError);
        }
    };

    let public_key = nisty::PublicKey::try_from(&public_bytes).map_err(|_| Error::InternalError)?;

    Ok(public_key)
}


#[cfg(feature = "p256")]
impl Agree for super::P256
{
    #[inline(never)]
    fn agree(keystore: &mut impl Keystore, request: &request::Agree)
        -> Result<reply::Agree, Error>
    {
        let private_id = request.private_key.object_id;
        let public_id = request.public_key.object_id;

        let keypair = load_keypair(keystore, &private_id)?;
        let public_key = load_public_key(keystore, &public_id)?;

        // THIS IS THE CORE
        let shared_secret = keypair.secret.agree(&public_key).map_err(|_| Error::InternalError)?.to_bytes();

        let key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret, key::Kind::Shared(32),
            &shared_secret)?;

        // return handle
        Ok(reply::Agree { shared_secret: ObjectHandle { object_id: key_id } })
    }
}

#[cfg(feature = "p256")]
impl DeriveKey for super::P256
{
    #[inline(never)]
    fn derive_key(keystore: &mut impl Keystore, request: &request::DeriveKey)
        -> Result<reply::DeriveKey, Error>
    {
        let base_id = request.base_key.object_id;

        let keypair = load_keypair(keystore, &base_id)?;

        let public_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Public, key::Kind::P256,
            &keypair.public.to_bytes())?;

        Ok(reply::DeriveKey {
            key: ObjectHandle { object_id: public_id },
        })
    }
}

#[cfg(feature = "p256")]
impl DeserializeKey for super::P256
{
    #[inline(never)]
    fn deserialize_key(keystore: &mut impl Keystore, request: &request::DeserializeKey)
        -> Result<reply::DeserializeKey, Error>
    {
          // - mechanism: Mechanism
          // - serialized_key: Message
          // - attributes: StorageAttributes

        let public_key = match request.format {
            KeySerialization::Cose => {
                // TODO: this should all be done upstream
                let cose_public_key: cosey::P256PublicKey = crate::cbor_deserialize(
                    &request.serialized_key).map_err(|_| Error::CborError)?;
                let mut serialized_key = [0u8; 64];
                if cose_public_key.x.len() != 32 || cose_public_key.y.len() != 32 {
                    return Err(Error::InvalidSerializedKey);
                }

                serialized_key[..32].copy_from_slice(&cose_public_key.x);
                serialized_key[32..].copy_from_slice(&cose_public_key.y);

                nisty::PublicKey::try_from(&serialized_key)
                    .map_err(|_| Error::InvalidSerializedKey)?
            }

            KeySerialization::EcdhEsHkdf256 => {
                // TODO: this should all be done upstream
                let cose_public_key: cosey::EcdhEsHkdf256PublicKey = crate::cbor_deserialize(
                    &request.serialized_key).map_err(|_| Error::CborError)?;
                let mut serialized_key = [0u8; 64];
                if cose_public_key.x.len() != 32 || cose_public_key.y.len() != 32 {
                    return Err(Error::InvalidSerializedKey);
                }

                serialized_key[..32].copy_from_slice(&cose_public_key.x);
                serialized_key[32..].copy_from_slice(&cose_public_key.y);

                nisty::PublicKey::try_from(&serialized_key)
                    .map_err(|_| Error::InvalidSerializedKey)?
            }

            KeySerialization::Raw => {
                if request.serialized_key.len() != 64 {
                    return Err(Error::InvalidSerializedKey);
                }

                let mut serialized_key = [0u8; 64];
                serialized_key.copy_from_slice(&request.serialized_key[..64]);

                nisty::PublicKey::try_from(&serialized_key)
                    .map_err(|_| Error::InvalidSerializedKey)?
            }

            _ => { return Err(Error::InternalError); }
        };

        let public_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Public, key::Kind::P256,
            public_key.as_bytes())?;


        Ok(reply::DeserializeKey {
            key: ObjectHandle { object_id: public_id },
        })
    }
}

#[cfg(feature = "p256")]
impl GenerateKey for super::P256
{
    #[inline(never)]
    fn generate_key(keystore: &mut impl Keystore, request: &request::GenerateKey)
        -> Result<reply::GenerateKey, Error>
    {
        // generate keypair
        let mut seed = [0u8; 32];
        keystore.drbg().fill_bytes(&mut seed);

        // let keypair = nisty::Keypair::generate_patiently(&seed);
        // #[cfg(all(test, feature = "verbose-tests"))]
        // println!("p256 keypair with public key = {:?}", &keypair.public);

        // store keys
        let key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret, key::Kind::P256,
            &seed)?;

        // return handle
        Ok(reply::GenerateKey { key: ObjectHandle { object_id: key_id } })
    }
}

#[cfg(feature = "p256")]
impl SerializeKey for super::P256
{
    #[inline(never)]
    fn serialize_key(keystore: &mut impl Keystore, request: &request::SerializeKey)
        -> Result<reply::SerializeKey, Error>
    {

        let key_id = request.key.object_id;

        let public_key = load_public_key(keystore, &key_id)?;

        let serialized_key = match request.format {
            KeySerialization::EcdhEsHkdf256 => {
                let cose_pk = cosey::EcdhEsHkdf256PublicKey {
                    x: Bytes::try_from_slice(&public_key.x_coordinate()).unwrap(),
                    y: Bytes::try_from_slice(&public_key.y_coordinate()).unwrap(),
                };
                crate::cbor_serialize_bytes(&cose_pk).map_err(|_| Error::CborError)?
            }
            KeySerialization::Cose => {
                let cose_pk = cosey::P256PublicKey {
                    x: Bytes::try_from_slice(&public_key.x_coordinate()).unwrap(),
                    y: Bytes::try_from_slice(&public_key.y_coordinate()).unwrap(),
                };
                crate::cbor_serialize_bytes(&cose_pk).map_err(|_| Error::CborError)?
            }
            KeySerialization::Raw => {
                let mut serialized_key = Message::new();
                serialized_key.extend_from_slice(public_key.as_bytes()).map_err(|_| Error::InternalError)?;
                serialized_key
            }
            KeySerialization::Sec1 => {
                let mut serialized_key = Message::new();
                serialized_key.extend_from_slice(
                    &public_key.compress()
                ).map_err(|_| Error::InternalError)?;
                serialized_key
            }
            // _ => {
            //     return Err(Error::InternalError);
            // }
        };

        Ok(reply::SerializeKey { serialized_key })
    }
}

#[cfg(feature = "p256")]
impl Exists for super::P256
{
    #[inline(never)]
    fn exists(keystore: &mut impl Keystore, request: &request::Exists)
        -> Result<reply::Exists, Error>
    {
        let key_id = request.key.object_id;
        let exists = keystore.exists_key(key::Secrecy::Secret, Some(key::Kind::P256), &key_id);
        Ok(reply::Exists { exists })
    }
}

#[cfg(feature = "p256")]
impl Sign for super::P256
{
    #[inline(never)]
    fn sign(keystore: &mut impl Keystore, request: &request::Sign)
        -> Result<reply::Sign, Error>
    {
        let key_id = request.key.object_id;

        // debug_now!("loading seed");
        let seed: [u8; 32] = keystore
            .load_key(key::Secrecy::Secret, Some(key::Kind::P256), &key_id)?
            .material.as_ref()
            .try_into()
            .map_err(|_| Error::InternalError)?;

        // debug_now!("signing {} of length {} with {}", &hex_str!(&request.message[..10]), request.message.len(), hex_str!(&seed));
        let native_signature = nisty::SecretKey::sign_with(seed, &request.message);

        // debug_now!("making signature");
        let our_signature = match request.format {
            SignatureSerialization::Asn1Der => {
                Signature::try_from_slice(&native_signature.to_der()).unwrap()
            }
            SignatureSerialization::Raw => {
                Signature::try_from_slice(&native_signature.to_bytes()).unwrap()
            }
        };
        // #[cfg(all(test, feature = "verbose-tests"))]
        // println!("p256 sig = {:?}", &native_signature);

        info_now!("P256 signature:");
        // info_now!("msg: {:?}", &request.message).ok();
        // info_now!("sig: {:?}", &our_signature).ok();

        // return signature
        Ok(reply::Sign { signature: our_signature })
    }
}

#[cfg(feature = "p256")]
impl Sign for super::P256Prehashed
{
    #[inline(never)]
    fn sign(keystore: &mut impl Keystore, request: &request::Sign)
        -> Result<reply::Sign, Error>
    {
        let key_id = request.key.object_id;

        let keypair = load_keypair(keystore, &key_id).map_err(|e| {
            info_now!("load keypair error {:?}", e);
            e
        })?;

        // info_now!("keypair loaded");

        if request.message.len() != nisty::DIGEST_LENGTH {
            info_now!("wrong length");
            return Err(Error::WrongMessageLength);
        }
        let message: [u8; 32] = request.message.as_ref().try_into().unwrap();
        info_now!("cast to 32B array");

        let native_signature = keypair.sign_prehashed(&message);
        info_now!("signed");

        let our_signature = match request.format {
            SignatureSerialization::Asn1Der => {
                Signature::try_from_slice(&native_signature.to_der()).unwrap()
            }
            SignatureSerialization::Raw => {
                Signature::try_from_slice(&native_signature.to_bytes()).unwrap()
            }
        };
        // #[cfg(all(test, feature = "verbose-tests"))]
        // println!("p256 sig = {:?}", &native_signature);
        // info_now!("p256 sig = {:?}", &our_signature).ok();

        info_now!("P256 ph signature:");
        // info_now!("msg: {:?}", &request.message).ok();
        // info_now!("sig: {:?}", &our_signature).ok();

        // return signature
        Ok(reply::Sign { signature: our_signature })
    }
}

#[cfg(feature = "p256")]
impl Verify for super::P256
{
    #[inline(never)]
    fn verify(keystore: &mut impl Keystore, request: &request::Verify)
        -> Result<reply::Verify, Error>
    {
        let key_id = request.key.object_id;

        let public_key = load_public_key(keystore, &key_id)?;

        if request.signature.len() != nisty::SIGNATURE_LENGTH {
            return Err(Error::WrongSignatureLength);
        }

        let mut signature_array = [0u8; nisty::SIGNATURE_LENGTH];
        signature_array.copy_from_slice(&request.signature);

        if let SignatureSerialization::Raw = request.format {
        } else {
            // well more TODO
            return Err(Error::InvalidSerializationFormat);
        }

        let valid = public_key.verify(&request.message, &signature_array);
        Ok(reply::Verify { valid } )
    }
}

#[cfg(not(feature = "p256"))]
impl Agree for super::P256 {}
#[cfg(not(feature = "p256"))]
impl DeriveKey for super::P256 {}
#[cfg(not(feature = "p256"))]
impl GenerateKey for super::P256 {}
#[cfg(not(feature = "p256"))]
impl Sign for super::P256 {}
#[cfg(not(feature = "p256"))]
impl Verify for super::P256 {}
