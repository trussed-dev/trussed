use crate::api::*;
// use crate::config::*;
use crate::error::Error;
use crate::key;
use crate::service::*;
use crate::types::*;

// TODO: The non-detached versions seem better.
// This needs a bit of additional type gymnastics.
// Maybe start a discussion on the `aead` crate's GitHub about usability concerns...

const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const TOTAL_LEN: usize = KEY_LEN + NONCE_LEN;
const TAG_LEN: usize = 16;
const KIND: key::Kind = key::Kind::Symmetric(KEY_LEN);
const KIND_NONCE: key::Kind = key::Kind::Symmetric32Nonce(NONCE_LEN);

#[cfg(feature = "chacha8-poly1305")]
impl GenerateKey for super::Chacha8Poly1305 {
    #[inline(never)]
    fn generate_key(
        keystore: &mut impl Keystore,
        request: &request::GenerateKey,
    ) -> Result<reply::GenerateKey, Error> {
        use rand_core::RngCore as _;

        // 32 bytes entropy
        // 12 bytes nonce
        let mut serialized = [0u8; TOTAL_LEN];

        let entropy = &mut serialized[..KEY_LEN];
        keystore.rng().fill_bytes(entropy);

        // store keys
        let key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret,
            KIND_NONCE,
            &serialized,
        )?;

        Ok(reply::GenerateKey { key: key_id })
    }
}

#[inline(never)]
fn increment_nonce(nonce: &mut [u8]) -> Result<(), Error> {
    assert_eq!(nonce.len(), NONCE_LEN);
    let mut carry: u16 = 1;
    for digit in nonce.iter_mut() {
        let x = (*digit as u16) + carry;
        *digit = x as u8;
        carry = x >> 8;
    }
    if carry == 0 {
        Ok(())
    } else {
        Err(Error::NonceOverflow)
    }
}

#[cfg(feature = "chacha8-poly1305")]
impl Decrypt for super::Chacha8Poly1305 {
    #[inline(never)]
    fn decrypt(
        keystore: &mut impl Keystore,
        request: &request::Decrypt,
    ) -> Result<reply::Decrypt, Error> {
        use chacha20poly1305::aead::{AeadMutInPlace, KeyInit};
        use chacha20poly1305::ChaCha8Poly1305;

        let key = keystore.load_key(key::Secrecy::Secret, None, &request.key)?;
        if !matches!(key.kind, KIND | KIND_NONCE) {
            return Err(Error::WrongKeyKind);
        }
        let serialized = key.material.as_slice();

        assert!(serialized.len() == TOTAL_LEN || serialized.len() == KEY_LEN);

        let symmetric_key = &serialized[..KEY_LEN];

        let mut aead = ChaCha8Poly1305::new(&GenericArray::clone_from_slice(symmetric_key));

        let mut plaintext = request.message.clone();
        let nonce = GenericArray::from_slice(&request.nonce);
        let tag = GenericArray::from_slice(&request.tag);

        let outcome =
            aead.decrypt_in_place_detached(nonce, &request.associated_data, &mut plaintext, tag);

        // outcome.map_err(|_| Error::AeadError)?;

        Ok(reply::Decrypt {
            plaintext: {
                if outcome.is_ok() {
                    Some(plaintext)
                } else {
                    None
                }
            },
        })
    }
}

#[cfg(feature = "chacha8-poly1305")]
impl Encrypt for super::Chacha8Poly1305 {
    #[inline(never)]
    fn encrypt(
        keystore: &mut impl Keystore,
        request: &request::Encrypt,
    ) -> Result<reply::Encrypt, Error> {
        use chacha20poly1305::aead::{AeadMutInPlace, KeyInit};
        use chacha20poly1305::ChaCha8Poly1305;

        // load key and nonce
        let secrecy = key::Secrecy::Secret;
        let key_id = &request.key;
        let mut key = keystore.load_key(secrecy, None, key_id)?;

        let serialized: &mut [u8] = key.material.as_mut();
        let symmetric_key: [u8; KEY_LEN] = serialized[..KEY_LEN].try_into().unwrap();
        let mut nonce = [0; NONCE_LEN];
        match (&request.nonce, key.kind) {
            (Some(n), KIND | KIND_NONCE) if n.len() == NONCE_LEN => {
                nonce.copy_from_slice(n);
            }
            (None, KIND) => {
                keystore.rng().fill_bytes(&mut nonce);
            }
            (None, KIND_NONCE) => {
                increment_nonce(&mut serialized[KEY_LEN..])?;
                nonce.copy_from_slice(&serialized[KEY_LEN..]);
                let location = keystore.location(secrecy, key_id).unwrap();
                keystore.overwrite_key(location, secrecy, KIND_NONCE, key_id, serialized)?;
            }
            (Some(_), KIND | KIND_NONCE) => return Err(Error::MechanismParamInvalid),
            _ => return Err(Error::WrongKeyKind),
        }

        let mut aead = ChaCha8Poly1305::new(&GenericArray::from(symmetric_key));

        let mut ciphertext = request.message.clone();
        let tag: [u8; TAG_LEN] = aead
            .encrypt_in_place_detached(
                &GenericArray::from(nonce),
                &request.associated_data,
                &mut ciphertext,
            )
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();

        let nonce = ShortData::from_slice(&nonce).unwrap();
        let tag = ShortData::from_slice(&tag).unwrap();

        // let ciphertext = Message::from_slice(&ciphertext).unwrap();
        Ok(reply::Encrypt {
            ciphertext,
            nonce,
            tag,
        })
    }
}

#[cfg(feature = "chacha8-poly1305")]
impl WrapKey for super::Chacha8Poly1305 {
    #[inline(never)]
    fn wrap_key(
        keystore: &mut impl Keystore,
        request: &request::WrapKey,
    ) -> Result<reply::WrapKey, Error> {
        debug!("trussed: Chacha8Poly1305::WrapKey");

        // TODO: need to check both secret and private keys
        let serialized_key = keystore.load_key(key::Secrecy::Secret, None, &request.key)?;

        let message = Message::from_slice(&serialized_key.serialize()).unwrap();

        let encryption_request = request::Encrypt {
            mechanism: Mechanism::Chacha8Poly1305,
            key: request.wrapping_key,
            message,
            associated_data: request.associated_data.clone(),
            nonce: None,
        };
        let encryption_reply = <super::Chacha8Poly1305>::encrypt(keystore, &encryption_request)?;

        let wrapped_key =
            crate::postcard_serialize_bytes(&encryption_reply).map_err(|_| Error::CborError)?;

        Ok(reply::WrapKey { wrapped_key })
    }
}

#[cfg(feature = "chacha8-poly1305")]
impl UnwrapKey for super::Chacha8Poly1305 {
    #[inline(never)]
    fn unwrap_key(
        keystore: &mut impl Keystore,
        request: &request::UnwrapKey,
    ) -> Result<reply::UnwrapKey, Error> {
        let reply::Encrypt {
            ciphertext,
            nonce,
            tag,
        } = crate::postcard_deserialize(&request.wrapped_key).map_err(|_| Error::CborError)?;

        let decryption_request = request::Decrypt {
            mechanism: Mechanism::Chacha8Poly1305,
            key: request.wrapping_key,
            message: ciphertext,
            associated_data: request.associated_data.clone(),
            nonce,
            tag,
        };

        let serialized_key = if let Some(serialized_key) =
            <super::Chacha8Poly1305>::decrypt(keystore, &decryption_request)?.plaintext
        {
            serialized_key
        } else {
            return Ok(reply::UnwrapKey { key: None });
        };

        // TODO: probably change this to returning Option<key> too
        let key::Key {
            flags: _,
            kind,
            material,
        } = key::Key::try_deserialize(&serialized_key)?;

        // TODO: need to check both secret and private keys
        let key_id = keystore.store_key(
            request.attributes.persistence,
            // using for signing keys... we need to know
            key::Secrecy::Secret,
            kind,
            &material,
        )?;

        Ok(reply::UnwrapKey { key: Some(key_id) })
    }
}

#[cfg(not(feature = "chacha8-poly1305"))]
impl Decrypt for super::Chacha8Poly1305 {}
#[cfg(not(feature = "chacha8-poly1305"))]
impl Encrypt for super::Chacha8Poly1305 {}
#[cfg(not(feature = "chacha8-poly1305"))]
impl WrapKey for super::Chacha8Poly1305 {}
#[cfg(not(feature = "chacha8-poly1305"))]
impl UnwrapKey for super::Chacha8Poly1305 {}
#[cfg(not(feature = "chacha8-poly1305"))]
impl GenerateKey for super::Chacha8Poly1305 {}
