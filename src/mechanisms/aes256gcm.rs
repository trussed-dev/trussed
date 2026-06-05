use cipher::typenum::U44;
use trussed_core::{
    api::{reply, request},
    types::Mechanism,
    Error,
};

use crate::{service::MechanismImpl, store::Keystore};

type KeyNonceSize = U44;
type Aead = super::aead::Aead<aes_gcm::Aes256Gcm, KeyNonceSize>;

impl MechanismImpl for super::Aes256Gcm {
    #[inline(never)]
    fn generate_key(
        &self,
        keystore: &mut impl Keystore,
        request: &request::GenerateKey,
    ) -> Result<reply::GenerateKey, Error> {
        Aead::new(Mechanism::Aes256Gcm).generate_key(keystore, request)
    }

    #[inline(never)]
    fn decrypt(
        &self,
        keystore: &mut impl Keystore,
        request: &request::Decrypt,
    ) -> Result<reply::Decrypt, Error> {
        Aead::new(Mechanism::Aes256Gcm).decrypt(keystore, request)
    }

    #[inline(never)]
    fn encrypt(
        &self,
        keystore: &mut impl Keystore,
        request: &request::Encrypt,
    ) -> Result<reply::Encrypt, Error> {
        Aead::new(Mechanism::Aes256Gcm).encrypt(keystore, request)
    }

    #[inline(never)]
    fn wrap_key(
        &self,
        keystore: &mut impl Keystore,
        request: &request::WrapKey,
    ) -> Result<reply::WrapKey, Error> {
        Aead::new(Mechanism::Aes256Gcm).wrap_key(keystore, request)
    }

    #[inline(never)]
    fn unwrap_key(
        &self,
        keystore: &mut impl Keystore,
        request: &request::UnwrapKey,
    ) -> Result<reply::UnwrapKey, Error> {
        Aead::new(Mechanism::Aes256Gcm).unwrap_key(keystore, request)
    }
}
