use core::marker::PhantomData;

use aead::{generic_array::GenericArray, AeadCore, AeadMutInPlace};
use cipher::{typenum::U32, ArrayLength, KeyInit, KeySizeUser, Unsigned as _};
use rand_core::RngCore as _;
use trussed_core::{
    api::{reply, request},
    types::{EncryptedData, Mechanism, Message, ShortData},
    Error,
};

use crate::{key, store::keystore::Keystore};

pub struct Aead<T, KeyNonceSize> {
    mechanism: Mechanism,
    _marker: PhantomData<(T, KeyNonceSize)>,
}

impl<
        T: AeadCore + AeadMutInPlace + KeyInit + KeySizeUser<KeySize = U32>,
        KeyNonceSize: ArrayLength<u8>,
    > Aead<T, KeyNonceSize>
{
    const KEY_LEN: usize = T::KeySize::USIZE;
    const NONCE_LEN: usize = T::NonceSize::USIZE;
    const TOTAL_LEN: usize = KeyNonceSize::USIZE;

    const KIND: key::Kind = key::Kind::Symmetric(Self::KEY_LEN);
    const KIND_NONCE: key::Kind = key::Kind::Symmetric32Nonce(Self::NONCE_LEN);

    pub fn new(mechanism: Mechanism) -> Self {
        const {
            assert!(Self::KEY_LEN + Self::NONCE_LEN == Self::TOTAL_LEN);
        }
        Self {
            mechanism,
            _marker: PhantomData,
        }
    }

    pub fn generate_key(
        &self,
        keystore: &mut impl Keystore,
        request: &request::GenerateKey,
    ) -> Result<reply::GenerateKey, Error> {
        let mut serialized: GenericArray<u8, KeyNonceSize> = GenericArray::default();
        let entropy = &mut serialized[..Self::KEY_LEN];
        keystore.rng().fill_bytes(entropy);

        // store keys
        let key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret,
            Self::KIND_NONCE,
            &serialized,
        )?;

        Ok(reply::GenerateKey { key: key_id })
    }

    pub fn decrypt(
        &self,
        keystore: &mut impl Keystore,
        request: &request::Decrypt,
    ) -> Result<reply::Decrypt, Error> {
        let key = keystore.load_key(key::Secrecy::Secret, None, &request.key)?;
        if key.kind != Self::KIND && key.kind != Self::KIND_NONCE {
            return Err(Error::WrongKeyKind);
        }
        let serialized = key.material.as_slice();

        assert!(serialized.len() == Self::TOTAL_LEN || serialized.len() == Self::KEY_LEN);

        let symmetric_key = &serialized[..Self::KEY_LEN];

        let mut aead = T::new(&GenericArray::clone_from_slice(symmetric_key));

        let mut plaintext = request.message.clone();
        let nonce = GenericArray::from_slice(&request.nonce);
        let tag = GenericArray::from_slice(&request.tag);

        let outcome =
            aead.decrypt_in_place_detached(nonce, &request.associated_data, &mut plaintext, tag);

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

    pub fn encrypt(
        &self,
        keystore: &mut impl Keystore,
        request: &request::Encrypt,
    ) -> Result<reply::Encrypt, Error> {
        // load key and nonce
        let secrecy = key::Secrecy::Secret;
        let key_id = &request.key;
        let mut key = keystore.load_key(secrecy, None, key_id)?;
        if key.kind != Self::KIND && key.kind != Self::KIND_NONCE {
            return Err(Error::WrongKeyKind);
        }

        let serialized: &mut [u8] = key.material.as_mut();
        let symmetric_key = GenericArray::clone_from_slice(&serialized[..Self::KEY_LEN]);
        let mut nonce: GenericArray<u8, T::NonceSize> = GenericArray::default();
        if let Some(n) = &request.nonce {
            if n.len() == Self::NONCE_LEN {
                nonce.copy_from_slice(n);
            } else {
                return Err(Error::MechanismParamInvalid);
            }
        } else if key.kind == Self::KIND {
            keystore.rng().fill_bytes(&mut nonce);
        } else if key.kind == Self::KIND_NONCE {
            self.increment_nonce(&mut serialized[Self::KEY_LEN..])?;
            nonce.copy_from_slice(&serialized[Self::KEY_LEN..]);
            let location = keystore.location(secrecy, key_id).unwrap();
            keystore.overwrite_key(location, secrecy, Self::KIND_NONCE, key_id, serialized)?;
        } else {
            return Err(Error::WrongKeyKind);
        }

        let mut aead = T::new(&symmetric_key);

        let mut ciphertext = request.message.clone();
        let tag = aead
            .encrypt_in_place_detached(&nonce, &request.associated_data, &mut ciphertext)
            .unwrap();

        let nonce = ShortData::try_from(nonce.as_slice()).unwrap();
        let tag = ShortData::try_from(tag.as_slice()).unwrap();

        Ok(reply::Encrypt {
            ciphertext,
            nonce,
            tag,
        })
    }

    pub fn wrap_key(
        &self,
        keystore: &mut impl Keystore,
        request: &request::WrapKey,
    ) -> Result<reply::WrapKey, Error> {
        debug!("trussed: Aead::WrapKey");

        // TODO: need to check both secret and private keys
        let serialized_key = keystore.load_key(key::Secrecy::Secret, None, &request.key)?;

        let message = Message::try_from(&*serialized_key.serialize()).unwrap();

        let encryption_request = request::Encrypt {
            mechanism: self.mechanism,
            key: request.wrapping_key,
            message,
            associated_data: request.associated_data.clone(),
            nonce: request.nonce.clone(),
        };
        let encryption_reply = self.encrypt(keystore, &encryption_request)?;

        let wrapped_key = EncryptedData::from(encryption_reply);
        let wrapped_key =
            crate::postcard_serialize_bytes(&wrapped_key).map_err(|_| Error::CborError)?;

        Ok(reply::WrapKey { wrapped_key })
    }

    pub fn unwrap_key(
        &self,
        keystore: &mut impl Keystore,
        request: &request::UnwrapKey,
    ) -> Result<reply::UnwrapKey, Error> {
        let encrypted_data: EncryptedData =
            crate::postcard_deserialize(&request.wrapped_key).map_err(|_| Error::CborError)?;

        let decryption_request = encrypted_data.decrypt(
            self.mechanism,
            request.wrapping_key,
            request.associated_data.clone(),
        );

        let serialized_key =
            if let Some(serialized_key) = self.decrypt(keystore, &decryption_request)?.plaintext {
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

    #[inline(never)]
    fn increment_nonce(&self, nonce: &mut [u8]) -> Result<(), Error> {
        assert_eq!(nonce.len(), Self::NONCE_LEN);
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
}
