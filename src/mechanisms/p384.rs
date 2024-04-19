#[cfg(feature = "p384")]
mod impls {
    use p384::{
        ecdh::diffie_hellman,
        ecdsa::{
            signature::{hazmat::RandomizedPrehashSigner, RandomizedSigner, Verifier},
            SigningKey, VerifyingKey,
        },
        elliptic_curve::sec1::ToEncodedPoint,
        SecretKey,
    };

    use super::super::{P384Prehashed, P384};
    use crate::{
        api::{reply, request},
        key,
        service::{
            Agree, DeriveKey, DeserializeKey, Exists, GenerateKey, SerializeKey, Sign,
            UnsafeInjectKey, Verify,
        },
        store::keystore::Keystore,
        types::{KeyId, KeySerialization, SerializedKey, Signature, SignatureSerialization},
        Error,
    };

    const SCALAR_SIZE: usize = 48;

    #[inline(never)]
    fn load_secret_key(
        keystore: &mut impl Keystore,
        key_id: &KeyId,
    ) -> Result<p384::SecretKey, Error> {
        // info_now!("loading keypair");
        let secret_scalar: [u8; SCALAR_SIZE] = keystore
            .load_key(key::Secrecy::Secret, Some(key::Kind::P384), key_id)?
            .material
            .as_slice()
            .try_into()
            .map_err(|_| Error::InternalError)?;

        let secret_key = p384::SecretKey::from_bytes((&secret_scalar).into())
            .map_err(|_| Error::InternalError)?;
        Ok(secret_key)
    }

    #[inline(never)]
    fn load_public_key(
        keystore: &mut impl Keystore,
        key_id: &KeyId,
    ) -> Result<p384::PublicKey, Error> {
        let compressed_public_key = keystore
            .load_key(key::Secrecy::Public, Some(key::Kind::P384), key_id)?
            .material;

        p384::PublicKey::from_sec1_bytes(&compressed_public_key).map_err(|_| Error::InternalError)
    }

    fn to_sec1_bytes(public_key: &p384::PublicKey) -> heapless::Vec<u8, { SCALAR_SIZE * 2 + 1 }> {
        let encoded_point: p384::EncodedPoint = public_key.into();
        encoded_point.as_bytes().try_into().unwrap()
    }

    impl Agree for P384 {
        fn agree(
            keystore: &mut impl Keystore,
            request: &request::Agree,
        ) -> Result<reply::Agree, Error> {
            let secret_key = load_secret_key(keystore, &request.private_key)?;
            let public_key = load_public_key(keystore, &request.public_key)?;
            let shared_secret: [u8; SCALAR_SIZE] =
                (*diffie_hellman(secret_key.to_nonzero_scalar(), public_key.as_affine())
                    .raw_secret_bytes())
                .into();
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
    }
    impl DeriveKey for P384 {
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
                key::Kind::P384,
                &to_sec1_bytes(&public_key),
            )?;

            Ok(reply::DeriveKey { key: public_id })
        }
    }
    impl DeserializeKey for P384 {
        #[inline(never)]
        fn deserialize_key(
            keystore: &mut impl Keystore,
            request: &request::DeserializeKey,
        ) -> Result<reply::DeserializeKey, Error> {
            // - mechanism: Mechanism
            // - serialized_key: Message
            // - attributes: StorageAttributes

            let public_key = match request.format {
                KeySerialization::Raw => {
                    if request.serialized_key.len() != 2 * SCALAR_SIZE {
                        return Err(Error::InvalidSerializedKey);
                    }

                    let mut serialized_key = [4; 2 * SCALAR_SIZE + 1];
                    serialized_key[1..].copy_from_slice(&request.serialized_key[..2 * SCALAR_SIZE]);

                    p384::PublicKey::from_sec1_bytes(&serialized_key)
                        .map_err(|_| Error::InvalidSerializedKey)?
                }

                _ => {
                    return Err(Error::InternalError);
                }
            };

            let public_id = keystore.store_key(
                request.attributes.persistence,
                key::Secrecy::Public,
                key::Kind::P384,
                &to_sec1_bytes(&public_key),
            )?;

            Ok(reply::DeserializeKey { key: public_id })
        }
    }
    impl SerializeKey for P384 {
        #[inline(never)]
        fn serialize_key(
            keystore: &mut impl Keystore,
            request: &request::SerializeKey,
        ) -> Result<reply::SerializeKey, Error> {
            let key_id = request.key;

            let public_key = load_public_key(keystore, &key_id)?;

            let serialized_key = match request.format {
                KeySerialization::Raw => {
                    let mut serialized_key = SerializedKey::new();
                    let affine_point = public_key.as_affine().to_encoded_point(false);
                    serialized_key
                        .extend_from_slice(affine_point.x().ok_or(Error::InternalError)?)
                        .map_err(|_| Error::InternalError)?;
                    serialized_key
                        .extend_from_slice(affine_point.y().ok_or(Error::InternalError)?)
                        .map_err(|_| Error::InternalError)?;
                    serialized_key
                }
                KeySerialization::Sec1 => {
                    let mut serialized_key = SerializedKey::new();
                    serialized_key
                        .extend_from_slice(&to_sec1_bytes(&public_key))
                        .map_err(|_| Error::InternalError)?;
                    serialized_key
                }
                _ => return Err(Error::InvalidSerializationFormat),
            };

            Ok(reply::SerializeKey { serialized_key })
        }
    }
    impl Exists for P384 {
        #[inline(never)]
        fn exists(
            keystore: &mut impl Keystore,
            request: &request::Exists,
        ) -> Result<reply::Exists, Error> {
            let key_id = request.key;
            let exists = keystore.exists_key(key::Secrecy::Secret, Some(key::Kind::P384), &key_id);
            Ok(reply::Exists { exists })
        }
    }

    impl Sign for P384 {
        #[inline(never)]
        fn sign(
            keystore: &mut impl Keystore,
            request: &request::Sign,
        ) -> Result<reply::Sign, Error> {
            let key_id = request.key;

            let secret_key = load_secret_key(keystore, &key_id)?;
            let signing_key = SigningKey::from(secret_key);
            let signature: p384::ecdsa::Signature =
                signing_key.sign_with_rng(keystore.rng(), &request.message);

            // debug_now!("making signature");
            let serialized_signature = match request.format {
                SignatureSerialization::Asn1Der => {
                    let der = signature.to_der();
                    Signature::from_slice(der.as_bytes()).unwrap()
                }
                SignatureSerialization::Raw => {
                    Signature::from_slice(&signature.to_bytes()).unwrap()
                }
            };

            // return signature
            Ok(reply::Sign {
                signature: serialized_signature,
            })
        }
    }
    impl Sign for P384Prehashed {
        #[inline(never)]
        fn sign(
            keystore: &mut impl Keystore,
            request: &request::Sign,
        ) -> Result<reply::Sign, Error> {
            let key_id = request.key;

            let secret_key = load_secret_key(keystore, &key_id)?;
            let signing_key = SigningKey::from(secret_key);
            let signature: p384::ecdsa::Signature = signing_key
                .sign_prehash_with_rng(keystore.rng(), &request.message)
                .map_err(|_| Error::InvalidSerializedRequest)?;

            // debug_now!("making signature");
            let serialized_signature = match request.format {
                SignatureSerialization::Asn1Der => {
                    let der = signature.to_der();
                    Signature::from_slice(der.as_bytes()).unwrap()
                }
                SignatureSerialization::Raw => {
                    Signature::from_slice(&signature.to_bytes()).unwrap()
                }
            };

            // return signature
            Ok(reply::Sign {
                signature: serialized_signature,
            })
        }
    }

    impl UnsafeInjectKey for P384 {
        fn unsafe_inject_key(
            keystore: &mut impl Keystore,
            request: &request::UnsafeInjectKey,
        ) -> Result<reply::UnsafeInjectKey, Error> {
            if request.format != KeySerialization::Raw {
                return Err(Error::InvalidSerializationFormat);
            }

            let sk = p384::SecretKey::from_bytes((&**request.raw_key).into())
                .map_err(|_| Error::InvalidSerializedKey)?;

            let info = key::Info {
                flags: key::Flags::SENSITIVE,
                kind: key::Kind::P384,
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

    impl Verify for P384 {
        #[inline(never)]
        fn verify(
            keystore: &mut impl Keystore,
            request: &request::Verify,
        ) -> Result<reply::Verify, Error> {
            let key_id = request.key;

            let public_key = load_public_key(keystore, &key_id)?;
            let verifying_key: VerifyingKey = public_key.into();

            if let SignatureSerialization::Raw = request.format {
            } else {
                // well more TODO
                return Err(Error::InvalidSerializationFormat);
            }

            let signature_bytes = (&**request.signature).into();

            let signature = p384::ecdsa::Signature::from_bytes(signature_bytes)
                .map_err(|_| Error::InvalidSerializedRequest)?;

            let valid = verifying_key.verify(&request.message, &signature).is_ok();
            Ok(reply::Verify { valid })
        }
    }
    impl GenerateKey for P384 {
        fn generate_key(
            keystore: &mut impl Keystore,
            request: &request::GenerateKey,
        ) -> Result<reply::GenerateKey, Error> {
            let private_key = SecretKey::random(keystore.rng());
            // store keys
            let key_id = keystore.store_key(
                request.attributes.persistence,
                key::Secrecy::Secret,
                key::Info::from(key::Kind::P384).with_local_flag(),
                &private_key.to_bytes(),
            )?;

            // return handle
            Ok(reply::GenerateKey { key: key_id })
        }
    }
}

#[cfg(not(feature = "p384"))]
mod impls {
    use super::super::{P384Prehashed, P384};
    use crate::service::{
        Agree, DeriveKey, DeserializeKey, Exists, GenerateKey, SerializeKey, Sign, UnsafeInjectKey,
        Verify,
    };

    impl UnsafeInjectKey for P384 {}
    impl Agree for P384 {}
    impl Exists for P384 {}
    impl DeriveKey for P384 {}
    impl GenerateKey for P384 {}
    impl DeserializeKey for P384 {}
    impl SerializeKey for P384 {}
    impl Sign for P384 {}
    impl Sign for P384Prehashed {}
    impl Verify for P384 {}
}
