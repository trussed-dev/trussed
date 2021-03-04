use core::convert::TryInto;

use crate::api::*;
// use crate::config::*;
use crate::error::Error;
use crate::service::*;
use crate::types::*;

#[cfg(feature = "hmac-sha256")]
impl Sign for super::HmacSha256
{
    fn sign(keystore: &mut impl Keystore, request: request::Sign)
        -> Result<reply::Sign, Error>
    {
        use sha2::Sha256;
        use hmac::{Hmac, Mac, NewMac};
        type HmacSha256 = Hmac<Sha256>;

        let key_id = request.key.object_id;
        let shared_secret = keystore.load_key(key::Secrecy::Secret, None, &key_id)?.material;

        // let path = keystore.prepare_path_for_key(key::Secrecy::Secret, &key_id)?;
        // let (serialized_key, _) = keystore.load_key_unchecked(&path)?;
        // let shared_secret = &serialized_key.material;
        let l = shared_secret.as_ref().len();
        if (l & 0xf) != 0 {
            info_now!("wrong key length, expected multiple of 16, got {}", l);
            return Err(Error::WrongKeyKind);
        }
        // keystore.load_key(&path, key::Kind::SharedSecret32, &mut shared_secret)?;
        // keystore.load_key(&path, key::Kind::SymmetricKey16, &mut shared_secret)?;

        // let mut mac = HmacSha256::new_varkey(&shared_secret)
        let mut mac = HmacSha256::new_varkey(&shared_secret.as_ref())
            .expect("HMAC can take key of any size");

        mac.update(&request.message);
        let result = mac.finalize();
        // To get underlying array use `code` method, but be carefull, since
        // incorrect use of the code material may permit timing attacks which defeat
        // the security provided by the `MacResult`
        let code_bytes: [u8; 32] = result.into_bytes().as_slice().try_into().unwrap();
        let signature = Signature::try_from_slice(&code_bytes).unwrap();

        // return signature
        Ok(reply::Sign { signature })

    }
}

#[cfg(feature = "hmac-sha256")]
impl GenerateKey for super::HmacSha256
{
    fn generate_key(keystore: &mut impl Keystore, request: request::GenerateKey)
        -> Result<reply::GenerateKey, Error>
    {
        let mut seed = [0u8; 16];
        keystore.drbg().fill_bytes(&mut seed);

        // let keypair = salty::Keypair::from(&seed);
        // #[cfg(all(test, feature = "verbose-tests"))]
        // println!("ed255 keypair with public key = {:?}", &keypair.public);

        // store keys
        let key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret,
            key::Kind::SymmetricKey16,
            &seed)?;

        // return handle
        Ok(reply::GenerateKey { key: ObjectHandle { object_id: key_id } })
    }
}


#[cfg(not(feature = "hmac-sha256"))]
impl Sign for super::HmacSha256 {}
