use core::convert::{TryFrom, TryInto};

use rsa::{RsaPrivateKey, pkcs8::ToPrivateKey};

use crate::api::*;
// use crate::config::*;
// use crate::debug;
use crate::error::Error;
use crate::service::*;
use crate::types::*;

// #[inline(never)]
// fn load_public_key(keystore: &mut impl Keystore, key_id: &KeyId)
//     -> Result<rsa::RsaPublicKey, Error> {

//     //TODO: The key size should better be defined somewhere instead of hardcoding
//     let public_bytes: [u8; 512] = keystore
//         .load_key(key::Secrecy::Public, Some(key::Kind::Rsa2k), &key_id)?
//         .material.as_slice()
//         .try_into()
//         .map_err(|_| Error::InternalError)?;

//     // let public_key = salty::signature::PublicKey::try_from(&public_bytes).map_err(|_| Error::InternalError)?;
//     let public_key = rsa::RsaPublicKey::try_from(&public_bytes).map_err(|_| Error::InternalError)?;

//     Ok(public_key)
// }

// #[inline(never)]
// fn load_keypair(keystore: &mut impl Keystore, key_id: &KeyId)
//     -> Result<salty::Keypair, Error> {

//     let seed: [u8; 32] = keystore
//         .load_key(key::Secrecy::Secret, Some(key::Kind::Rsa2k), &key_id)?
//         .material.as_slice()
//         .try_into()
//         .map_err(|_| Error::InternalError)?;

//     let keypair = salty::signature::Keypair::from(&seed);
//     // hprintln!("seed: {:?}", &seed).ok();
//     Ok(keypair)
// }

#[cfg(feature = "rsa2k-pkcs")]
impl DeriveKey for super::Rsa2kPkcs
{
    // #[inline(never)]
    // fn derive_key(keystore: &mut impl Keystore, request: &request::DeriveKey)
    //     -> Result<reply::DeriveKey, Error>
    // {
    //     let base_id = &request.base_key;
    //     let keypair = load_keypair(keystore, base_id)?;

    //     let public_id = keystore.store_key(
    //         request.attributes.persistence,
    //         key::Secrecy::Public, key::Kind::Rsa2k,
    //         keypair.public.as_bytes())?;

    //     Ok(reply::DeriveKey {
    //         key: public_id,
    //     })
    // }
}

#[cfg(feature = "rsa2k-pkcs")]
impl DeserializeKey for super::Rsa2kPkcs
{
    #[inline(never)]
    fn deserialize_key(keystore: &mut impl Keystore, request: &request::DeserializeKey)
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
        let public_key = salty::signature::PublicKey::try_from(&serialized_key)
            .map_err(|_| Error::InvalidSerializedKey)?;

        let public_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Public, key::Kind::Rsa2k,
            public_key.as_bytes())?;

        Ok(reply::DeserializeKey {
            key: public_id
        })
    }
}

#[cfg(feature = "rsa2k-pkcs")]
impl GenerateKey for super::Rsa2kPkcs
{
    #[inline(never)]
    fn generate_key(keystore: &mut impl Keystore, request: &request::GenerateKey)
        -> Result<reply::GenerateKey, Error>
    {
        // We want an RSA 2K key
        let bits = 2048;

        let private_key = RsaPrivateKey::new(keystore.rng(), bits).expect("Failed to generate the RSA 2K private key");
        let pk_der = ToPrivateKey::to_pkcs8_der(&private_key).expect("Failed to serialize the RSA 2K private key to PKCS#8 DER");

        // #[cfg(all(test, feature = "verbose-tests"))]
        // std::println!("rsa2k-pkcs private key = {:?}", &private_key);

        // store the key
        let key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret,
            key::Info::from(key::Kind::Rsa2k).with_local_flag(),
            pk_der.as_ref())?;

        // return handle
        Ok(reply::GenerateKey { key: key_id })
    }
}

#[cfg(feature = "rsa2k-pkcs")]
impl SerializeKey for super::Rsa2kPkcs
{
    // #[inline(never)]
    // fn serialize_key(keystore: &mut impl Keystore, request: &request::SerializeKey)
    //     -> Result<reply::SerializeKey, Error>
    // {
    //     let key_id = request.key;
    //     let public_key = load_public_key(keystore, &key_id)?;

    //     let serialized_key = match request.format {
    //         KeySerialization::Cose => {
    //             let cose_pk = cosey::Ed25519PublicKey {
    //                 // x: Bytes::from_slice(public_key.x_coordinate()).unwrap(),
    //                 // x: Bytes::from_slice(&buf).unwrap(),
    //                 x: Bytes::from_slice(public_key.as_bytes()).unwrap(),
    //             };
    //             crate::cbor_serialize_bytes(&cose_pk).map_err(|_| Error::CborError)?
    //         }

    //         KeySerialization::Raw => {
    //             let mut serialized_key = Message::new();
    //             serialized_key.extend_from_slice(public_key.as_bytes()).map_err(|_| Error::InternalError)?;
    //             // serialized_key.extend_from_slice(&buf).map_err(|_| Error::InternalError)?;
    //             serialized_key
    //         }

    //         _ => { return Err(Error::InternalError); }
    //     };

    //     Ok(reply::SerializeKey { serialized_key })
    // }
}

#[cfg(feature = "rsa2k-pkcs")]
impl Exists for super::Rsa2kPkcs
{
    #[inline(never)]
    fn exists(keystore: &mut impl Keystore, request: &request::Exists)
        -> Result<reply::Exists, Error>
    {
        let key_id = request.key;

        let exists = keystore.exists_key(key::Secrecy::Secret, Some(key::Kind::Rsa2k), &key_id);
        Ok(reply::Exists { exists })
    }
}

#[cfg(feature = "rsa2k-pkcs")]
impl Sign for super::Rsa2kPkcs
{
    // #[inline(never)]
    // fn sign(keystore: &mut impl Keystore, request: &request::Sign)
    //     -> Result<reply::Sign, Error>
    // {

    //     let key_id = request.key;

    //     let keypair = load_keypair(keystore, &key_id)?;

    //     let native_signature = keypair.sign(&request.message);
    //     let our_signature = Signature::from_slice(&native_signature.to_bytes()).unwrap();

    //     // hprintln!("RSA2K-PKCS_v1.5 signature:").ok();
    //     // hprintln!("msg: {:?}", &request.message).ok();
    //     // hprintln!("pk:  {:?}", &keypair.public.as_bytes()).ok();
    //     // hprintln!("sig: {:?}", &our_signature).ok();

    //     // return signature
    //     Ok(reply::Sign { signature: our_signature })
    // }
}

#[cfg(feature = "rsa2k-pkcs")]
impl Verify for super::Rsa2kPkcs
{
    // #[inline(never)]
    // fn verify(keystore: &mut impl Keystore, request: &request::Verify)
    //     -> Result<reply::Verify, Error>
    // {
    //     if let SignatureSerialization::Raw = request.format {
    //     } else {
    //         return Err(Error::InvalidSerializationFormat);
    //     }

    //     if request.signature.len() != salty::constants::SIGNATURE_SERIALIZED_LENGTH {
    //         return Err(Error::WrongSignatureLength);
    //     }

    //     let key_id = request.key;
    //     let public_key = load_public_key(keystore, &key_id)?;

    //     let mut signature_array = [0u8; salty::constants::SIGNATURE_SERIALIZED_LENGTH];
    //     signature_array.copy_from_slice(request.signature.as_ref());
    //     let salty_signature = salty::signature::Signature::from(&signature_array);

    //     Ok(reply::Verify { valid:
    //         public_key.verify(&request.message, &salty_signature).is_ok()
    //     })
    // }
}

#[cfg(not(feature = "rsa2k-pkcs"))]
impl DeriveKey for super::Rsa2kPkcs {}
#[cfg(not(feature = "rsa2k-pkcs"))]
impl GenerateKey for super::Rsa2kPkcs {}
#[cfg(not(feature = "rsa2k-pkcs"))]
impl Sign for super::Rsa2kPkcs {}
#[cfg(not(feature = "rsa2k-pkcs"))]
impl Verify for super::Rsa2kPkcs {}