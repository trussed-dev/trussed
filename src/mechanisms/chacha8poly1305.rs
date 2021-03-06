use core::convert::TryInto;

use crate::api::*;
// use crate::config::*;
use crate::error::Error;
use crate::service::*;
use crate::types::*;

// TODO: The non-detached versions seem better.
// This needs a bit of additional type gymnastics.
// Maybe start a discussion on the `aead` crate's GitHub about usability concerns...

#[cfg(feature = "chacha8-poly1305")]
impl GenerateKey for super::Chacha8Poly1305 {

    fn generate_key(keystore: &mut impl Keystore, request: request::GenerateKey)
        -> Result<reply::GenerateKey, Error>
    {
        use rand_core::RngCore as _;

        // 32 bytes entropy
        // 12 bytes nonce
        let mut serialized = [0u8; 44];

        let entropy = &mut serialized[..32];
        keystore.drbg().fill_bytes(entropy);

        // store keys
        let key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret,
            key::Kind::Symmetric32Nonce(12),
            &serialized,
        )?;

        Ok(reply::GenerateKey { key: ObjectHandle { object_id: key_id } })
    }
}

fn increment_nonce(nonce: &mut [u8]) -> Result<(), Error> {
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
impl Decrypt for super::Chacha8Poly1305
{
    fn decrypt(keystore: &mut impl Keystore, request: request::Decrypt)
        -> Result<reply::Decrypt, Error>
    {
        use chacha20poly1305::ChaCha8Poly1305;
        use chacha20poly1305::aead::{AeadInPlace, NewAead};

        let serialized_material = keystore
            .load_key(key::Secrecy::Secret, Some(key::Kind::Symmetric32Nonce(12)), &request.key.object_id)?
            .material;
        let serialized = serialized_material.as_ref();

        // if serialized.len() != 44 {
        //     return Error::InternalError;
        // }
        assert!(serialized.len() == 44);

        let symmetric_key = &serialized[..32];

        let aead = ChaCha8Poly1305::new(&GenericArray::clone_from_slice(&symmetric_key));

        let mut plaintext = request.message.clone();
        let nonce = GenericArray::from_slice(&request.nonce);
        let tag = GenericArray::from_slice(&request.tag);

        let outcome = aead.decrypt_in_place_detached(
            &nonce, &request.associated_data, &mut plaintext, &tag);

        // outcome.map_err(|_| Error::AeadError)?;

        Ok(reply::Decrypt { plaintext: {
            if outcome.is_ok() {
                Some(plaintext)
            } else {
                None
            }
        }})
    }
}

#[cfg(feature = "chacha8-poly1305")]
impl Encrypt for super::Chacha8Poly1305
{
    fn encrypt(keystore: &mut impl Keystore, request: request::Encrypt)
        -> Result<reply::Encrypt, Error>
    {
        use chacha20poly1305::ChaCha8Poly1305;
        use chacha20poly1305::aead::{AeadInPlace, NewAead};


        // load key and nonce
        let secrecy = key::Secrecy::Secret;
        let key_kind = key::Kind::Symmetric32Nonce(12);
        let key_id = &request.key.object_id;
        let mut serialized_material = keystore
            .load_key(secrecy, Some(key_kind), key_id)?
            .material;
        let serialized = serialized_material.as_mut();

        assert!(serialized.len() == 44);

        // no panic by above early return
        let location = keystore.location(secrecy, key_id).unwrap();

        // let key_id = request.key.object_id;
        // let path = keystore.prepare_path_for_key(key::Secrecy::Secret, &key_id)?;
        // let mut serialized = [0u8; 44];
        // debug!("loading encryption key: {:?}", &path);

        {
            let nonce = &mut serialized[32..];
            // increment nonce
            increment_nonce(nonce)?;
        }
        // increment_nonce(&mut serialized[32..])?;

        keystore.overwrite_key(location, secrecy, key_kind, key_id, &serialized)?;

        let (symmetric_key, generated_nonce) = serialized.split_at_mut(32);

        let nonce = match request.nonce.as_ref() {
            Some(nonce) => nonce.as_ref(),
            None => generated_nonce,
        };



        // keep in state?
        let aead = ChaCha8Poly1305::new(&GenericArray::clone_from_slice(symmetric_key));

        let mut ciphertext = request.message.clone();
        let tag: [u8; 16] = aead.encrypt_in_place_detached(
            &GenericArray::clone_from_slice(nonce),
            &request.associated_data,
            &mut ciphertext,
        ).unwrap().as_slice().try_into().unwrap();

        let nonce = ShortData::try_from_slice(nonce).unwrap();
        let tag = ShortData::try_from_slice(&tag).unwrap();

        // let ciphertext = Message::try_from_slice(&ciphertext).unwrap();
        Ok(reply::Encrypt { ciphertext, nonce, tag })
    }
}

#[cfg(feature = "chacha8-poly1305")]
impl WrapKey for super::Chacha8Poly1305
{
    fn wrap_key(keystore: &mut impl Keystore, request: request::WrapKey)
        -> Result<reply::WrapKey, Error>
    {
        debug!("trussed: Chacha8Poly1305::WrapKey");

        // TODO: need to check both secret and private keys
        let serialized_key = keystore
            .load_key(key::Secrecy::Secret, None, &request.key.object_id)?;

        let message = serialized_key.serialize().try_convert_into().unwrap();

        let encryption_request = request::Encrypt {
            mechanism: Mechanism::Chacha8Poly1305,
            key: request.wrapping_key,
            message,
            associated_data: ShortData::new(),
            nonce: None,
        };
        let encryption_reply = <super::Chacha8Poly1305>::encrypt(keystore, encryption_request)?;

        let wrapped_key = crate::cbor_serialize_bytes(&encryption_reply).map_err(|_| Error::CborError)?;

        Ok(reply::WrapKey { wrapped_key })
    }
}

#[cfg(feature = "chacha8-poly1305")]
impl UnwrapKey for super::Chacha8Poly1305
{
    fn unwrap_key(keystore: &mut impl Keystore, request: request::UnwrapKey)
        -> Result<reply::UnwrapKey, Error>
    {
        let reply::Encrypt { ciphertext, nonce, tag } = crate::cbor_deserialize(
            &request.wrapped_key).map_err(|_| Error::CborError)?;

        let decryption_request = request::Decrypt {
            mechanism: Mechanism::Chacha8Poly1305,
            key: request.wrapping_key,
            message: ciphertext,
            associated_data: request.associated_data,
            nonce,
            tag,
        };

        let serialized_key = if let Some(serialized_key) =
            <super::Chacha8Poly1305>::decrypt(keystore, decryption_request)?.plaintext {
            serialized_key
        } else {
            return Ok(reply::UnwrapKey { key: None } );
        };

        // TODO: probably change this to returning Option<key> too
        let key::Key{ flags: _, kind, material } = key::Key::try_deserialize(&serialized_key)?;

        // TODO: need to check both secret and private keys
        let key_id = keystore.store_key(
            request.attributes.persistence,
            // using for signing keys... we need to know
            key::Secrecy::Secret,
            kind,
            &material,
        )?;

        Ok(reply::UnwrapKey { key: Some(ObjectHandle { object_id: key_id }) } )
    }
}

// // // global choice of algorithm: we do Chacha8Poly1305 here
// // // TODO: oh how annoying these GenericArrays
// // pub fn aead_in_place(&mut self, ad: &[u8], buf: &mut [u8]) -> Result<(AeadNonce, AeadTag), Error> {
// //     use chacha20poly1305::aead::{Aead, NewAead};

// //     // keep in state?
// //     let aead = ChaCha8Poly1305::new(GenericArray::clone_from_slice(&self.get_aead_key()?));
// //     // auto-increments
// //     let nonce = self.get_aead_nonce()?;

// //     // aead.encrypt_in_place_detached(&nonce, ad, buf).map(|g| g.as_slice().try_into().unwrap())?;
// //     // not sure what can go wrong with AEAD
// //     let tag: AeadTag = aead.encrypt_in_place_detached(
// //         &GenericArray::clone_from_slice(&nonce), ad, buf
// //     ).unwrap().as_slice().try_into().unwrap();
// //     Ok((nonce, tag))
// // }

// // pub fn adad_in_place(&mut self, nonce: &AeadNonce, ad: &[u8], buf: &mut [u8], tag: &AeadTag) -> Result<(), Error> {
// //     use chacha20poly1305::aead::{Aead, NewAead};

// //     // keep in state?
// //     let aead = ChaCha8Poly1305::new(GenericArray::clone_from_slice(&self.get_aead_key()?));

// //     aead.decrypt_in_place_detached(
// //         &GenericArray::clone_from_slice(nonce),
// //         ad,
// //         buf,
// //         &GenericArray::clone_from_slice(tag)
// //     ).map_err(|_| Error::AeadError)
// // }


// #[cfg(feature = "chacha8-poly1305")]
// impl<P: Platform>
// Decrypt<P> for super::Chacha8Poly1305
// {
//     fn decrypt(keystore: &mut impl Keystore, request: request::Decrypt)
//         -> Result<reply::Decrypt, Error>
//     {
// 		use block_modes::{BlockMode, Cbc};
// 		// use block_modes::Cbc;
// 		use block_modes::block_padding::ZeroPadding;
// 		use aes::Aes256;

//         // TODO: perhaps use NoPadding and have client pad, to emphasize spec-conformance?
//         type Aes256Cbc = Cbc<Aes256, ZeroPadding>;

//         let key_id = request.key.object_id;
//         let mut symmetric_key = [0u8; 32];
//         let path = keystore.prepare_path_for_key(key::Secrecy::Secret, &key_id)?;
//         keystore.load_serialized_key(&path, key::Kind::SymmetricKey32, &mut symmetric_key)?;

//         let zero_iv = [0u8; 32];
// 		let cipher = Aes256Cbc::new_var(&symmetric_key, &zero_iv).unwrap();

// 		// buffer must have enough space for message+padding
// 		let mut buffer = request.message.clone();
// 		// // copy message to the buffer
// 		// let pos = plaintext.len();
// 		// buffer[..pos].copy_from_slice(plaintext);
//         let l = buffer.len();

//         // Decrypt message in-place.
//         // Returns an error if buffer length is not multiple of block size and
//         // if after decoding message has malformed padding.
// 		let plaintext = cipher.decrypt(&mut buffer).unwrap();
//         let plaintext = Message::try_from_slice(&plaintext).unwrap();

//         Ok(reply::Decrypt { plaintext: Ok(plaintext) })
//     }
// }

// // TODO: key a `/root/aead-nonce` counter (or use entropy?)
// // TODO: how do we want to organize this? probably the key itself should have an associated nonce,
// //       so using a key actually modifies its state!
// pub fn get_aead_nonce() -> Result<AeadNonce, Error> {
//     Ok([42u8; 12])
// }

// impl<P: Platform>
// Encrypt<P> for super::Chacha8Poly1305
// {
//     fn encrypt(keystore: &mut impl Keystore, request: request::Encrypt)
//         -> Result<reply::Encrypt, Error>
//     {
//         use chacha20poly1305::ChaCha8Poly1305;

//         let key_id = request.key.object_id;
//         let path = keystore.prepare_path_for_key(key::Secrecy::Secret, &key_id)?;

//         let mut symmetric_key = [0u8; 32];
//         keystore.load_serialized_key(&path, key::Kind::SymmetricKey32, &mut symmetric_key)?;

//         // keep in state?
//         let aead = ChaCha8Poly1305::new(GenericArray::clone_from_slice(&symmetric_key)?);
//         // auto-increments
//         let nonce: [u8; 12] = get_aead_nonce()?;

//         let tag: AeadTag = aead.encrypt_in_place_detached(
//             &GenericArray::clone_from_slice(&nonce), ad, buf
//         ).unwrap().as_slice().try_into().unwrap();
//         Ok((nonce, tag))

// 		// // buffer must have enough space for message+padding
// 		// let mut buffer = request.message.clone();
// 		// // // copy message to the buffer
// 		// // let pos = plaintext.len();
// 		// // buffer[..pos].copy_from_slice(plaintext);
//         // let l = buffer.len();

//         // // Encrypt message in-place.
//         // // &buffer[..pos] is used as a message and &buffer[pos..] as a reserved space for padding.
//         // // The padding space should be big enough for padding, otherwise method will return Err(BlockModeError).
// 		// let ciphertext = cipher.encrypt(&mut buffer, l).unwrap();

//         // let ciphertext = Message::try_from_slice(&ciphertext).unwrap();
//         Ok(reply::Encrypt { ciphertext })
//     }
// }

// // // global choice of algorithm: we do Chacha8Poly1305 here
// // // TODO: oh how annoying these GenericArrays
// // pub fn aead_in_place(&mut self, ad: &[u8], buf: &mut [u8]) -> Result<(AeadNonce, AeadTag), Error> {
// //     use chacha20poly1305::aead::{Aead, NewAead};

// //     // keep in state?
// //     let aead = ChaCha8Poly1305::new(GenericArray::clone_from_slice(&self.get_aead_key()?));
// //     // auto-increments
// //     let nonce = self.get_aead_nonce()?;

// //     // aead.encrypt_in_place_detached(&nonce, ad, buf).map(|g| g.as_slice().try_into().unwrap())?;
// //     // not sure what can go wrong with AEAD
// //     let tag: AeadTag = aead.encrypt_in_place_detached(
// //         &GenericArray::clone_from_slice(&nonce), ad, buf
// //     ).unwrap().as_slice().try_into().unwrap();
// //     Ok((nonce, tag))
// // }

// // pub fn adad_in_place(&mut self, nonce: &AeadNonce, ad: &[u8], buf: &mut [u8], tag: &AeadTag) -> Result<(), Error> {
// //     use chacha20poly1305::aead::{Aead, NewAead};

// //     // keep in state?
// //     let aead = ChaCha8Poly1305::new(GenericArray::clone_from_slice(&self.get_aead_key()?));

// //     aead.decrypt_in_place_detached(
// //         &GenericArray::clone_from_slice(nonce),
// //         ad,
// //         buf,
// //         &GenericArray::clone_from_slice(tag)
// //     ).map_err(|_| Error::AeadError)
// // }


#[cfg(not(feature = "chacha8-poly1305"))]
impl<P: Platform>
Decrypt<P> for super::Chacha8Poly1305 {}
#[cfg(not(feature = "chacha8-poly1305"))]
impl<P: Platform>
Encrypt<P> for super::Chacha8Poly1305 {}
#[cfg(not(feature = "chacha8-poly1305"))]
impl<P: Platform>
GenerateKey<P> for super::Chacha8Poly1305 {}
