use core::convert::TryInto;
use chacha20::ChaCha8Rng;
use rand_core::RngCore;

use crate::{
    api::{request, reply},
    Error,
    key,
    service::{Agree, DeriveKey, DeserializeKey, Exists, GenerateKey, SerializeKey, Sign, Verify},
    store::keystore::Keystore,
    types::{KeyId, KeySerialization, Message, Signature, SignatureSerialization},
};

const SIZE: usize = 48;
type SecretKey = [u8; SIZE];
type PublicKey = [u8; 2*SIZE + 1];
type SharedSecret = [u8; SIZE];

#[inline(never)]
fn load_secret_key(keystore: &mut impl Keystore, key_id: &KeyId) -> Result<SecretKey, Error>
{

    let secret_key: SecretKey = keystore
        .load_key(key::Secrecy::Secret, Some(key::Kind::P384), &key_id)?
        .material.as_slice()
        .try_into()
        .map_err(|_| Error::InternalError)?;

    Ok(secret_key)
}

#[inline(never)]
fn load_public_key(keystore: &mut impl Keystore, key_id: &KeyId) -> Result<PublicKey, Error>
{
    let public_key: PublicKey = keystore
        .load_key(key::Secrecy::Public, Some(key::Kind::P384), &key_id)?
        .material.as_slice()
        .try_into()
        .map_err(|_| Error::InternalError)?;

    Ok(public_key)
}


#[cfg(feature = "p384")]
impl GenerateKey for super::P384
{
    #[inline(never)]
    fn generate_key(keystore: &mut impl Keystore, request: &request::GenerateKey)
        -> Result<reply::GenerateKey, Error>
    {
        // secret key
        // I dunno, Rust... in this day and age, no Default?!
        let mut secret_key: SecretKey = [0u8; SIZE];
        keystore.rng().fill_bytes(&mut secret_key);

        // store keys
        let key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret,
            key::Info::from(key::Kind::P384).with_local_flag(),
            &secret_key,
        )?;

        // return handle
        Ok(reply::GenerateKey { key: key_id })
    }
}

#[cfg(feature = "p384")]
impl Agree for super::P384
{
    #[inline(never)]
    fn agree(keystore: &mut impl Keystore, request: &request::Agree)
        -> Result<reply::Agree, Error>
    {
        let private_id = request.private_key;
        let public_id = request.public_key;

        let secret_key = load_secret_key(keystore, &private_id)?;
        let public_key = load_public_key(keystore, &public_id)?;

        let mut shared_secret: SharedSecret = [0u8; SIZE];
        miracl32::nist384::ecdh::ecpsvdp_dh(&secret_key, &public_key, &mut shared_secret, 0);

        let key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret, key::Kind::Shared(SIZE),
            &shared_secret)?;

        // return handle
        Ok(reply::Agree { shared_secret: key_id })
    }
}

#[cfg(feature = "p384")]
impl DeriveKey for super::P384
{
    #[inline(never)]
    fn derive_key(keystore: &mut impl Keystore, request: &request::DeriveKey)
        -> Result<reply::DeriveKey, Error>
    {
        let base_id = request.base_key;

        // secret_key is not actually mutated as None is passed as rng.
        let mut secret_key = load_secret_key(keystore, &base_id)?;

        // public key
        let mut public_key: PublicKey = [0u8; 2*SIZE + 1];
        miracl32::nist384::ecdh::key_pair_generate(None::<&mut miracl32::rand::RAND_impl>, &mut secret_key, &mut public_key);

        let public_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Public, key::Kind::P384,
            &public_key)?;

        Ok(reply::DeriveKey {
            key: public_id
        })
    }
}

#[cfg(feature = "p384")]
impl DeserializeKey for super::P384
{
    #[inline(never)]
    fn deserialize_key(keystore: &mut impl Keystore, request: &request::DeserializeKey)
        -> Result<reply::DeserializeKey, Error>
    {
        // deserialize to miracl format
        let public_key = match request.format {
            KeySerialization::Raw => {
                if request.serialized_key.len() != 2*SIZE {
                    return Err(Error::InvalidSerializedKey);
                }

                &request.serialized_key
            }

            _ => { return Err(Error::FunctionNotSupported); }
        };

        // validate public key
        if 0 != miracl32::nist384::ecdh::public_key_validate(public_key) {
            return Err(Error::InvalidSerializedKey);
        }

        // store it
        let public_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Public, key::Kind::P384,
            &public_key)?;

        Ok(reply::DeserializeKey { key: public_id })
    }
}

#[cfg(feature = "p384")]
impl SerializeKey for super::P384
{
    #[inline(never)]
    fn serialize_key(keystore: &mut impl Keystore, request: &request::SerializeKey)
        -> Result<reply::SerializeKey, Error>
    {
        let key_id = request.key;
        let public_key = load_public_key(keystore, &key_id)?;

        let serialized_key = match request.format {
            KeySerialization::Raw => {
                let mut serialized_key = Message::new();
                serialized_key.extend_from_slice(&public_key).unwrap();
                serialized_key
            }
            _ => return Err(Error::FunctionNotSupported),
        };

        Ok(reply::SerializeKey { serialized_key })
    }
}

#[cfg(feature = "p384")]
impl Exists for super::P384
{
    #[inline(never)]
    fn exists(keystore: &mut impl Keystore, request: &request::Exists)
        -> Result<reply::Exists, Error>
    {
        let key_id = request.key;
        let exists = keystore.exists_key(key::Secrecy::Secret, Some(key::Kind::P384), &key_id);
        Ok(reply::Exists { exists })
    }
}

struct MiraclRng<'rng>(&'rng mut ChaCha8Rng);

impl miracl32::rand::RAND for MiraclRng<'_> {
    // we're already "seeded"
    fn seed(&mut self, _rawlen: usize, _raw: &[u8]) {}

    fn getbyte(&mut self) -> u8 {
        let mut wrapped_byte = [0u8; 1];
        self.0.fill_bytes(&mut wrapped_byte);
        wrapped_byte[0]
    }
}

#[cfg(feature = "p384")]
impl Sign for super::P384
{
    #[inline(never)]
    fn sign(keystore: &mut impl Keystore, request: &request::Sign)
        -> Result<reply::Sign, Error>
    {
        let key_id = request.key;

        let secret_key = load_secret_key(keystore, &key_id)?;

        let mut rng = MiraclRng(keystore.rng());

        let sha = SIZE;
        let mut c = [0u8; SIZE];
        let mut d = [0u8; SIZE];

        // "IEEE ECDSA Signature, C and D are signature on F using private key S"
        if miracl32::nist384::ecdh::ecpsp_dsa(
            sha,
            &mut rng,
            // secret key
            &secret_key,
            // message
            &request.message,
            &mut c,
            &mut d,
        ) != 0 {
            info!("signing with P384 key failed!");
            return Err(Error::InternalError);
        }

        // debug_now!("making signature");
        let serialized_signature = match request.format {
            SignatureSerialization::Asn1Der => {
                // let mut buffer = [0u8; 72];
                // let l = signature.to_sec1_bytes(&mut buffer);
                // Signature::from_slice(&buffer[..l]).unwrap()
                return Err(Error::FunctionNotSupported);
            }
            SignatureSerialization::Raw => {
                let mut sig: Signature = Default::default();
                sig.extend_from_slice(&c).unwrap();
                sig.extend_from_slice(&d).unwrap();
                sig
            }
        };

        // return signature
        Ok(reply::Sign { signature: serialized_signature })
    }

}

#[cfg(feature = "p384")]
impl Verify for super::P384
{
    #[inline(never)]
    fn verify(keystore: &mut impl Keystore, request: &request::Verify)
        -> Result<reply::Verify, Error>
    {
        let key_id = request.key;

        let public_key = load_public_key(keystore, &key_id)?;

        let (c, d) = match request.format {
            SignatureSerialization::Raw => {
                if request.signature.len() != 2*SIZE {
                    return Err(Error::InvalidSerializationFormat);
                }
                request.signature.split_at(SIZE)
            }
            SignatureSerialization::Asn1Der => return Err(Error::FunctionNotSupported),
        };

        let sha = SIZE;
        // "IEEE1363 ECDSA Signature Verification. Signature C and D on F is verified using public key W"
        let result = miracl32::nist384::ecdh::ecpvp_dsa(
            sha,
            &public_key,
            &request.message,
            c,
            d,
        );

        let valid = result == 0;
        Ok(reply::Verify { valid } )
    }
}

#[cfg(not(feature = "p384"))]
impl Agree for super::P384 {}
#[cfg(not(feature = "p384"))]
impl DeriveKey for super::P384 {}
#[cfg(not(feature = "p384"))]
impl GenerateKey for super::P384 {}
#[cfg(not(feature = "p384"))]
impl Sign for super::P384 {}
#[cfg(not(feature = "p384"))]
impl Verify for super::P384 {}
