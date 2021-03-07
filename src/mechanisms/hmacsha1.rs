use crate::api::*;
// use crate::config::*;
use crate::error::Error;
use crate::service::*;
use crate::types::*;

#[cfg(feature = "hmac-sha1")]
impl Sign for super::HmacSha1
{
    #[inline(never)]
    fn sign(keystore: &mut impl Keystore, request: &request::Sign)
        -> Result<reply::Sign, Error>
    {
        use sha1::Sha1;
        use hmac::{Hmac, Mac, NewMac};
        type HmacSha1 = Hmac<Sha1>;

        let key_id = request.key.object_id;
        let shared_secret = keystore.load_key(key::Secrecy::Secret, None, &key_id)?.material;

        let mut mac = HmacSha1::new_varkey(&shared_secret.as_ref())
            .expect("HMAC can take key of any size");

        mac.update(&request.message);
        let result = mac.finalize();
        // To get underlying array use `code` method, but be carefull, since
        // incorrect use of the code material may permit timing attacks which defeat
        // the security provided by the `MacResult`
        // let code_bytes: [u8; 32] = result.into_bytes().as_slice().try_into().unwrap();
        let signature = Signature::try_from_slice(&result.into_bytes()).unwrap();

        // return signature
        Ok(reply::Sign { signature })

    }
}

#[cfg(feature = "hmac-sha1")]
impl GenerateKey for super::HmacSha1
{
    #[inline(never)]
    fn generate_key(keystore: &mut impl Keystore, request: &request::GenerateKey)
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
            key::Kind::Symmetric(16),
            &seed)?;

        // return handle
        Ok(reply::GenerateKey { key: ObjectHandle { object_id: key_id } })
    }
}


#[cfg(not(feature = "hmac-sha1"))]
impl Sign for super::HmacSha1 {}
