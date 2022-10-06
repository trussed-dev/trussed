//! This is so nasty!
//!
//! We need to support 3DES to provide compatibility with Yubico's braindead
//! implementation of key management...

// use cortex_m_semihosting::{dbg, hprintln};

// needed to even get ::new() from des...
use des::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

use crate::api::*;
use crate::error::Error;
use crate::service::*;
use crate::types::*;

const TDES_KEY_SIZE: usize = 24;

#[cfg(feature = "tdes")]
impl Encrypt for super::Tdes {
    /// Encrypts a single block. Let's hope we don't have to support ECB!!
    #[inline(never)]
    fn encrypt(
        keystore: &mut impl Keystore,
        request: &request::Encrypt,
    ) -> Result<reply::Encrypt, Error> {
        if request.message.len() != 8 {
            return Err(Error::WrongMessageLength);
        }

        let key_id = request.key;

        let key = keystore.load_key(key::Secrecy::Secret, None, &key_id)?;
        // FIXME: Symmetric keys of the correct size can't currently be obtained with without using
        // `unsafe_inject_shared_key` so tdes needs to accept "shared" keys
        if !matches!(
            key.kind,
            key::Kind::Symmetric(TDES_KEY_SIZE) | key::Kind::Shared(TDES_KEY_SIZE)
        ) {
            return Err(Error::WrongKeyKind);
        }

        let symmetric_key: [u8; TDES_KEY_SIZE] = key
            .material
            .as_slice()
            .try_into()
            .map_err(|_| Error::InternalError)?;

        let cipher = des::TdesEde3::new(GenericArray::from_slice(&symmetric_key));

        let mut message = request.message.clone();
        cipher.encrypt_block(GenericArray::from_mut_slice(&mut message));

        Ok(reply::Encrypt {
            ciphertext: message,
            nonce: Default::default(),
            tag: Default::default(),
        })
    }
}

#[cfg(feature = "tdes")]
impl Decrypt for super::Tdes {
    /// Decrypts a single block. Let's hope we don't have to support ECB!!
    #[inline(never)]
    fn decrypt(
        keystore: &mut impl Keystore,
        request: &request::Decrypt,
    ) -> Result<reply::Decrypt, Error> {
        if request.message.len() != 8 {
            return Err(Error::WrongMessageLength);
        }

        let key_id = request.key;

        let symmetric_key: [u8; TDES_KEY_SIZE] = keystore
            .load_key(key::Secrecy::Secret, None, &key_id)?
            .material
            .as_slice()
            .try_into()
            .map_err(|_| Error::InternalError)?;

        let cipher = des::TdesEde3::new(GenericArray::from_slice(&symmetric_key));

        let mut message = request.message.clone();
        cipher.decrypt_block(GenericArray::from_mut_slice(&mut message));

        Ok(reply::Decrypt {
            plaintext: Some(message),
        })
    }
}

impl UnsafeInjectKey for super::Tdes {
    fn unsafe_inject_key(
        keystore: &mut impl Keystore,
        request: &request::UnsafeInjectKey,
    ) -> Result<reply::UnsafeInjectKey, Error> {
        if request.raw_key.len() != TDES_KEY_SIZE {
            return Err(Error::InvalidSerializedKey);
        }

        let key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret,
            key::Kind::Symmetric(request.raw_key.len()),
            &request.raw_key,
        )?;

        Ok(reply::UnsafeInjectKey { key: key_id })
    }
}
