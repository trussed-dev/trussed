// use core::convert::{TryFrom, TryInto};

use crate::api::*;
use crate::error::Error;
use crate::service::*;
use crate::types::*;

#[inline(never)]
fn load_secret_key(
    keystore: &mut impl Keystore,
    key_id: &KeyId,
) -> Result<p256_cortex_m4::SecretKey, Error> {
    // info_now!("loading keypair");
    let secret_scalar: [u8; 32] = keystore
        .load_key(key::Secrecy::Secret, Some(key::Kind::P256), key_id)?
        .material
        .as_slice()
        .try_into()
        .map_err(|_| Error::InternalError)?;

    let secret_key =
        p256_cortex_m4::SecretKey::from_bytes(secret_scalar).map_err(|_| Error::InternalError)?;
    Ok(secret_key)
}

#[inline(never)]
fn load_public_key(
    keystore: &mut impl Keystore,
    key_id: &KeyId,
) -> Result<p256_cortex_m4::PublicKey, Error> {
    let compressed_public_key: [u8; 33] = keystore
        .load_key(key::Secrecy::Public, Some(key::Kind::P256), key_id)?
        .material
        .as_slice()
        .try_into()
        .map_err(|_| Error::InternalError)?;

    p256_cortex_m4::PublicKey::from_sec1_bytes(&compressed_public_key)
        .map_err(|_| Error::InternalError)
}

#[cfg(feature = "p256")]
impl Agree for super::P256 {
    #[inline(never)]
    fn agree(
        keystore: &mut impl Keystore,
        request: &request::Agree,
    ) -> Result<reply::Agree, Error> {
        let private_id = request.private_key;
        let public_id = request.public_key;

        let secret_key = load_secret_key(keystore, &private_id)?;
        let public_key = load_public_key(keystore, &public_id)?;

        let shared_secret = secret_key.agree(&public_key);

        let flags = if request.attributes.serializable {
            key::Flags::SERIALIZABLE
        } else {
            key::Flags::empty()
        };
        let info = key::Info {
            kind: key::Kind::Shared(shared_secret.as_bytes().len()),
            flags,
        };

        let key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret,
            info,
            shared_secret.as_bytes(),
        )?;

        // return handle
        Ok(reply::Agree {
            shared_secret: key_id,
        })
    }
}

#[cfg(feature = "p256")]
impl DeriveKey for super::P256 {
    #[inline(never)]
    fn derive_key(
        keystore: &mut impl Keystore,
        request: &request::DeriveKey,
    ) -> Result<reply::DeriveKey, Error> {
        let base_id = request.base_key;

        let secret_key = load_secret_key(keystore, &base_id)?;
        let public_key = secret_key.public_key();

        let public_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Public,
            key::Kind::P256,
            &public_key.to_compressed_sec1_bytes(),
        )?;

        Ok(reply::DeriveKey { key: public_id })
    }
}

#[cfg(feature = "p256")]
impl DeserializeKey for super::P256 {
    #[inline(never)]
    fn deserialize_key(
        keystore: &mut impl Keystore,
        request: &request::DeserializeKey,
    ) -> Result<reply::DeserializeKey, Error> {
        // - mechanism: Mechanism
        // - serialized_key: Message
        // - attributes: StorageAttributes

        let public_key = match request.format {
            KeySerialization::Cose => {
                // TODO: this should all be done upstream
                let cose_public_key: cosey::P256PublicKey =
                    crate::cbor_deserialize(&request.serialized_key)
                        .map_err(|_| Error::CborError)?;
                let mut serialized_key = [0u8; 64];
                if cose_public_key.x.len() != 32 || cose_public_key.y.len() != 32 {
                    return Err(Error::InvalidSerializedKey);
                }

                serialized_key[..32].copy_from_slice(&cose_public_key.x);
                serialized_key[32..].copy_from_slice(&cose_public_key.y);

                p256_cortex_m4::PublicKey::from_untagged_bytes(&serialized_key)
                    .map_err(|_| Error::InvalidSerializedKey)?
            }

            KeySerialization::EcdhEsHkdf256 => {
                // TODO: this should all be done upstream
                let cose_public_key: cosey::EcdhEsHkdf256PublicKey =
                    crate::cbor_deserialize(&request.serialized_key)
                        .map_err(|_| Error::CborError)?;
                let mut serialized_key = [0u8; 64];
                if cose_public_key.x.len() != 32 || cose_public_key.y.len() != 32 {
                    return Err(Error::InvalidSerializedKey);
                }

                serialized_key[..32].copy_from_slice(&cose_public_key.x);
                serialized_key[32..].copy_from_slice(&cose_public_key.y);

                p256_cortex_m4::PublicKey::from_untagged_bytes(&serialized_key)
                    .map_err(|_| Error::InvalidSerializedKey)?
            }

            KeySerialization::Raw => {
                if request.serialized_key.len() != 64 {
                    return Err(Error::InvalidSerializedKey);
                }

                let mut serialized_key = [0u8; 64];
                serialized_key.copy_from_slice(&request.serialized_key[..64]);

                p256_cortex_m4::PublicKey::from_untagged_bytes(&serialized_key)
                    .map_err(|_| Error::InvalidSerializedKey)?
            }

            _ => {
                return Err(Error::InternalError);
            }
        };

        let public_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Public,
            key::Kind::P256,
            &public_key.to_compressed_sec1_bytes(),
        )?;

        Ok(reply::DeserializeKey { key: public_id })
    }
}

#[cfg(feature = "p256")]
impl GenerateKey for super::P256 {
    #[inline(never)]
    fn generate_key(
        keystore: &mut impl Keystore,
        request: &request::GenerateKey,
    ) -> Result<reply::GenerateKey, Error> {
        let keypair = p256_cortex_m4::Keypair::random(keystore.rng());

        // store keys
        let key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret,
            key::Info::from(key::Kind::P256).with_local_flag(),
            &unsafe { keypair.secret.to_bytes() },
        )?;

        // return handle
        Ok(reply::GenerateKey { key: key_id })
    }
}

#[cfg(feature = "p256")]
impl SerializeKey for super::P256 {
    #[inline(never)]
    fn serialize_key(
        keystore: &mut impl Keystore,
        request: &request::SerializeKey,
    ) -> Result<reply::SerializeKey, Error> {
        let key_id = request.key;

        let public_key = load_public_key(keystore, &key_id)?;

        let serialized_key = match request.format {
            KeySerialization::EcdhEsHkdf256 => {
                let cose_pk = cosey::EcdhEsHkdf256PublicKey {
                    x: Bytes::from_slice(&public_key.x()).unwrap(),
                    y: Bytes::from_slice(&public_key.y()).unwrap(),
                };
                crate::cbor_serialize_bytes(&cose_pk).map_err(|_| Error::CborError)?
            }
            KeySerialization::Cose => {
                let cose_pk = cosey::P256PublicKey {
                    x: Bytes::from_slice(&public_key.x()).unwrap(),
                    y: Bytes::from_slice(&public_key.y()).unwrap(),
                };
                crate::cbor_serialize_bytes(&cose_pk).map_err(|_| Error::CborError)?
            }
            KeySerialization::Raw => {
                let mut serialized_key = SerializedKey::new();
                serialized_key
                    .extend_from_slice(&public_key.x())
                    .map_err(|_| Error::InternalError)?;
                serialized_key
                    .extend_from_slice(&public_key.y())
                    .map_err(|_| Error::InternalError)?;
                serialized_key
            }
            KeySerialization::Sec1 => {
                let mut serialized_key = SerializedKey::new();
                serialized_key
                    .extend_from_slice(&public_key.to_compressed_sec1_bytes())
                    .map_err(|_| Error::InternalError)?;
                serialized_key
            }
            _ => return Err(Error::InvalidSerializationFormat),
        };

        Ok(reply::SerializeKey { serialized_key })
    }
}

#[cfg(feature = "p256")]
impl Exists for super::P256 {
    #[inline(never)]
    fn exists(
        keystore: &mut impl Keystore,
        request: &request::Exists,
    ) -> Result<reply::Exists, Error> {
        let key_id = request.key;
        let exists = keystore.exists_key(key::Secrecy::Secret, Some(key::Kind::P256), &key_id);
        Ok(reply::Exists { exists })
    }
}

#[cfg(feature = "p256")]
impl Sign for super::P256 {
    #[inline(never)]
    fn sign(keystore: &mut impl Keystore, request: &request::Sign) -> Result<reply::Sign, Error> {
        let key_id = request.key;

        let secret_key = load_secret_key(keystore, &key_id)?;
        let signature = secret_key.sign(&request.message, keystore.rng());

        // debug_now!("making signature");
        let serialized_signature = match request.format {
            SignatureSerialization::Asn1Der => {
                let mut buffer = [0u8; 72];
                let l = signature.to_sec1_bytes(&mut buffer);
                Signature::from_slice(&buffer[..l]).unwrap()
            }
            SignatureSerialization::Raw => {
                Signature::from_slice(&signature.to_untagged_bytes()).unwrap()
            }
        };

        // return signature
        Ok(reply::Sign {
            signature: serialized_signature,
        })
    }
}

#[cfg(feature = "p256")]
impl Sign for super::P256Prehashed {
    #[inline(never)]
    fn sign(keystore: &mut impl Keystore, request: &request::Sign) -> Result<reply::Sign, Error> {
        let key_id = request.key;

        let secret_key = load_secret_key(keystore, &key_id)?;
        let signature = secret_key.sign_prehashed(&request.message, keystore.rng());

        // debug_now!("making signature");
        let serialized_signature = match request.format {
            SignatureSerialization::Asn1Der => {
                let mut buffer = [0u8; 72];
                let l = signature.to_sec1_bytes(&mut buffer);
                Signature::from_slice(&buffer[..l]).unwrap()
            }
            SignatureSerialization::Raw => {
                Signature::from_slice(&signature.to_untagged_bytes()).unwrap()
            }
        };

        // return signature
        Ok(reply::Sign {
            signature: serialized_signature,
        })
    }
}

#[cfg(feature = "p256")]
impl Verify for super::P256 {
    #[inline(never)]
    fn verify(
        keystore: &mut impl Keystore,
        request: &request::Verify,
    ) -> Result<reply::Verify, Error> {
        let key_id = request.key;

        let public_key = load_public_key(keystore, &key_id)?;

        let signature = p256_cortex_m4::Signature::from_untagged_bytes(&request.signature)
            // well... or wrong encoding, need r,s in range 1..=n-1
            .map_err(|_| Error::WrongSignatureLength)?;

        if let SignatureSerialization::Raw = request.format {
        } else {
            // well more TODO
            return Err(Error::InvalidSerializationFormat);
        }

        let valid = public_key.verify(&request.message, &signature);
        Ok(reply::Verify { valid })
    }
}

impl UnsafeInjectKey for super::P256 {
    fn unsafe_inject_key(
        keystore: &mut impl Keystore,
        request: &request::UnsafeInjectKey,
    ) -> Result<reply::UnsafeInjectKey, Error> {
        if request.format != KeySerialization::Raw {
            return Err(Error::InvalidSerializationFormat);
        }

        let sk = p256_cortex_m4::SecretKey::from_bytes(&request.raw_key)
            .map_err(|_| Error::InvalidSerializedKey)?;

        let info = key::Info {
            flags: key::Flags::SENSITIVE,
            kind: key::Kind::P256,
        };

        keystore
            .store_key(
                request.attributes.persistence,
                key::Secrecy::Secret,
                info,
                unsafe { &sk.to_bytes() },
            )
            .map(|key| reply::UnsafeInjectKey { key })
    }
}

#[cfg(not(feature = "p256"))]
impl Agree for super::P256 {}
#[cfg(not(feature = "p256"))]
impl Exists for super::P256 {}
#[cfg(not(feature = "p256"))]
impl DeriveKey for super::P256 {}
#[cfg(not(feature = "p256"))]
impl GenerateKey for super::P256 {}
#[cfg(not(feature = "p256"))]
impl DeserializeKey for super::P256 {}
#[cfg(not(feature = "p256"))]
impl SerializeKey for super::P256 {}
#[cfg(not(feature = "p256"))]
impl Sign for super::P256 {}
#[cfg(not(feature = "p256"))]
impl Sign for super::P256Prehashed {}
#[cfg(not(feature = "p256"))]
impl Verify for super::P256 {}
