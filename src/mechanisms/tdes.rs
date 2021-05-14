//! This is so nasty!
//!
//! We need to support 3DES to provide compatibility with Yubico's braindead
//! implementation of key management...

// use cortex_m_semihosting::{dbg, hprintln};

use core::convert::TryInto;
// needed to even get ::new() from des...
use des::cipher::{BlockDecrypt, BlockEncrypt, NewBlockCipher};

use crate::api::*;
use crate::error::Error;
use crate::service::*;
use crate::types::*;

#[cfg(feature = "tdes")]
impl Encrypt for super::Tdes
{
    /// Encrypts a single block. Let's hope we don't have to support ECB!!
    #[inline(never)]
    fn encrypt(keystore: &mut impl Keystore, request: &request::Encrypt)
        -> Result<reply::Encrypt, Error>
    {
        if request.message.len() != 8 { return Err(Error::WrongMessageLength); }

        let key_id = request.key;

        let symmetric_key: [u8; 24] = keystore
            .load_key(key::Secrecy::Secret, None, &key_id)?
            .material.as_ref().try_into()
            .map_err(|_| Error::InternalError)?;

		let cipher = des::TdesEde3::new(GenericArray::from_slice(&symmetric_key));

		let mut message = request.message.clone();
        cipher.encrypt_block(GenericArray::from_mut_slice(&mut message));

        Ok(reply::Encrypt { ciphertext: message, nonce: Default::default(), tag: Default::default() })
    }
}

#[cfg(feature = "tdes")]
impl Decrypt for super::Tdes
{
    /// Decrypts a single block. Let's hope we don't have to support ECB!!
    #[inline(never)]
    fn decrypt(keystore: &mut impl Keystore, request: &request::Decrypt)
        -> Result<reply::Decrypt, Error>
    {
        if request.message.len() != 8 { return Err(Error::WrongMessageLength); }

        let key_id = request.key;

        let symmetric_key: [u8; 24] = keystore
            .load_key(key::Secrecy::Secret, None, &key_id)?
            .material.as_ref().try_into()
            .map_err(|_| Error::InternalError)?;

		let cipher = des::TdesEde3::new(GenericArray::from_slice(&symmetric_key));

        let mut message = request.message.clone();
        cipher.decrypt_block(GenericArray::from_mut_slice(&mut message));

        Ok(reply::Decrypt { plaintext: Some(message) })
    }
}
