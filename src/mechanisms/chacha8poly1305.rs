use cipher::typenum::U44;
use trussed_core::{
    api::{reply, request},
    types::Mechanism,
    Error,
};

use crate::{service::MechanismImpl, store::Keystore};

type KeyNonceSize = U44;
type Aead = super::aead::Aead<chacha20poly1305::ChaCha8Poly1305, KeyNonceSize>;

// TODO: The non-detached versions seem better.
// This needs a bit of additional type gymnastics.
// Maybe start a discussion on the `aead` crate's GitHub about usability concerns...

impl MechanismImpl for super::Chacha8Poly1305 {
    #[inline(never)]
    fn generate_key(
        &self,
        keystore: &mut impl Keystore,
        request: &request::GenerateKey,
    ) -> Result<reply::GenerateKey, Error> {
        Aead::new(Mechanism::Chacha8Poly1305).generate_key(keystore, request)
    }

    #[inline(never)]
    fn decrypt(
        &self,
        keystore: &mut impl Keystore,
        request: &request::Decrypt,
    ) -> Result<reply::Decrypt, Error> {
        Aead::new(Mechanism::Chacha8Poly1305).decrypt(keystore, request)
    }

    #[inline(never)]
    fn encrypt(
        &self,
        keystore: &mut impl Keystore,
        request: &request::Encrypt,
    ) -> Result<reply::Encrypt, Error> {
        Aead::new(Mechanism::Chacha8Poly1305).encrypt(keystore, request)
    }

    #[inline(never)]
    fn wrap_key(
        &self,
        keystore: &mut impl Keystore,
        request: &request::WrapKey,
    ) -> Result<reply::WrapKey, Error> {
        Aead::new(Mechanism::Chacha8Poly1305).wrap_key(keystore, request)
    }

    #[inline(never)]
    fn unwrap_key(
        &self,
        keystore: &mut impl Keystore,
        request: &request::UnwrapKey,
    ) -> Result<reply::UnwrapKey, Error> {
        Aead::new(Mechanism::Chacha8Poly1305).unwrap_key(keystore, request)
    }
}
