use crate::api::*;
// use crate::config::*;
use crate::error::Error;
use crate::service::*;
use crate::types::*;

const AES256_KEY_SIZE: usize = 32;

#[cfg(feature = "aes256-cbc")]
impl Encrypt for super::Aes256Cbc {
    /// Encrypts the input *with zero IV*
    fn encrypt(
        keystore: &mut impl Keystore,
        request: &request::Encrypt,
    ) -> Result<reply::Encrypt, Error> {
        use aes::Aes256;
        use cbc::cipher::{block_padding::ZeroPadding, BlockEncryptMut, KeyIvInit};

        type Aes256CbcEnc = cbc::Encryptor<Aes256>;
        // TODO: perhaps use NoPadding and have client pad, to emphasize spec-conformance?

        let key_id = request.key;
        let key = keystore.load_key(key::Secrecy::Secret, None, &key_id)?;
        if !matches!(key.kind, key::Kind::Symmetric(AES256_KEY_SIZE)) {
            return Err(Error::WrongKeyKind);
        }

        let symmetric_key: [u8; AES256_KEY_SIZE] = key
            .material
            .as_slice()
            .try_into()
            .map_err(|_| Error::InternalError)?;

        let zero_iv = [0u8; 16];
        let cipher = Aes256CbcEnc::new_from_slices(&symmetric_key, &zero_iv).unwrap();

        // buffer must have enough space for message+padding
        let mut buffer = request.message.clone();
        // // copy message to the buffer
        // let pos = plaintext.len();
        // buffer[..pos].copy_from_slice(plaintext);
        let l = buffer.len();
        // hprintln!(" aes256cbc encrypting l = {}B: {:?}", l, &buffer).ok();

        // Encrypt message in-place.
        // &buffer[..pos] is used as a message and &buffer[pos..] as a reserved space for padding.
        // The padding space should be big enough for padding, otherwise method will return Err(BlockModeError).
        let ciphertext = cipher
            .encrypt_padded_mut::<ZeroPadding>(&mut buffer, l)
            .unwrap();

        let ciphertext = Message::from_slice(ciphertext).unwrap();
        Ok(reply::Encrypt {
            ciphertext,
            nonce: ShortData::new(),
            tag: ShortData::new(),
        })
    }
}

#[cfg(feature = "aes256-cbc")]
impl WrapKey for super::Aes256Cbc {
    fn wrap_key(
        keystore: &mut impl Keystore,
        request: &request::WrapKey,
    ) -> Result<reply::WrapKey, Error> {
        // TODO: need to check both secret and private keys
        // let path = keystore.key_path(key::Secrecy::Secret, &request.key)?;
        // let (serialized_key, _location) = keystore.load_key_unchecked(&path)?;

        // let message: Message = serialized_key.material.try_to_byte_buf().map_err(|_| Error::InternalError)?;

        let message = Message::from_slice(
            keystore
                .load_key(key::Secrecy::Secret, None, &request.key)?
                .material
                .as_slice(),
        )
        .map_err(|_| Error::InternalError)?;

        let encryption_request = request::Encrypt {
            mechanism: Mechanism::Aes256Cbc,
            key: request.wrapping_key,
            message,
            associated_data: request.associated_data.clone(),
            nonce: None,
        };
        let encryption_reply = <super::Aes256Cbc>::encrypt(keystore, &encryption_request)?;

        let wrapped_key = encryption_reply.ciphertext;

        Ok(reply::WrapKey { wrapped_key })
    }
}

#[cfg(feature = "aes256-cbc")]
impl Decrypt for super::Aes256Cbc {
    fn decrypt(
        keystore: &mut impl Keystore,
        request: &request::Decrypt,
    ) -> Result<reply::Decrypt, Error> {
        use aes::Aes256;
        use cbc::cipher::{block_padding::ZeroPadding, BlockDecryptMut, KeyIvInit};

        // TODO: perhaps use NoPadding and have client pad, to emphasize spec-conformance?
        type Aes256CbcDec = cbc::Decryptor<Aes256>;

        let key_id = request.key;
        let key = keystore.load_key(key::Secrecy::Secret, None, &key_id)?;
        if !matches!(key.kind, key::Kind::Symmetric(AES256_KEY_SIZE)) {
            return Err(Error::WrongKeyKind);
        }

        let symmetric_key: [u8; AES256_KEY_SIZE] = key
            .material
            .as_slice()
            .try_into()
            .map_err(|_| Error::InternalError)?;

        let zero_iv = [0u8; 16];
        let cipher = Aes256CbcDec::new_from_slices(&symmetric_key, &zero_iv).unwrap();

        // buffer must have enough space for message+padding
        let mut buffer = request.message.clone();
        // // copy message to the buffer
        // let pos = plaintext.len();
        // buffer[..pos].copy_from_slice(plaintext);
        // let l = buffer.len();

        // Decrypt message in-place.
        // Returns an error if buffer length is not multiple of block size and
        // if after decoding message has malformed padding.
        // hprintln!("encrypted: {:?}", &buffer).ok();
        // hprintln!("symmetric key: {:?}", &symmetric_key).ok();
        let plaintext = cipher
            .decrypt_padded_mut::<ZeroPadding>(&mut buffer)
            .unwrap();
        // hprintln!("decrypted: {:?}", &plaintext).ok();
        let plaintext = Message::from_slice(plaintext).unwrap();

        Ok(reply::Decrypt {
            plaintext: Some(plaintext),
        })
    }
}

#[cfg(feature = "aes256-cbc")]
impl UnsafeInjectKey for super::Aes256Cbc {
    fn unsafe_inject_key(
        keystore: &mut impl Keystore,
        request: &request::UnsafeInjectKey,
    ) -> Result<reply::UnsafeInjectKey, Error> {
        if request.raw_key.len() != AES256_KEY_SIZE {
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

#[cfg(not(feature = "aes256-cbc"))]
impl UnsafeInjectKey for super::Aes256Cbc {}

#[cfg(not(feature = "aes256-cbc"))]
impl Decrypt for super::Aes256Cbc {}

#[cfg(not(feature = "aes256-cbc"))]
impl Encrypt for super::Aes256Cbc {}
