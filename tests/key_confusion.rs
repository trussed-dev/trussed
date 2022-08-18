#![cfg(feature = "virt")]

use serial_test::serial;
use trussed::client::mechanisms::{P256, X255};
use trussed::client::CryptoClient;
use trussed::error::Error;
use trussed::types::{KeyId, Mechanism, SignatureSerialization};
use trussed::{syscall, try_syscall};

mod client;

use trussed::types::Location::*;

fn assert_sign_mechanims_reject(key: KeyId, client: &mut impl CryptoClient) {
    for m in [
        Mechanism::Ed255,
        Mechanism::HmacBlake2s,
        Mechanism::HmacSha1,
        Mechanism::HmacSha256,
        Mechanism::HmacSha512,
    ] {
        let res = try_syscall!(client.sign(m, key, &[48; 32], SignatureSerialization::Raw));
        assert!(
            res == Err(Error::WrongKeyKind)
                || res == Err(Error::MechanismNotAvailable)
                || res == Err(Error::NoSuchKey),
            "Got result: {res:?}"
        );
    }
}

fn assert_encrypt_mechanims_reject(key: KeyId, client: &mut impl CryptoClient) {
    for m in [Mechanism::Aes256Cbc, Mechanism::Chacha8Poly1305] {
        let res_encrypt = try_syscall!(client.encrypt(m, key, b"", b"", None));
        assert!(
            res_encrypt == Err(Error::WrongKeyKind)
                || res_encrypt == Err(Error::MechanismNotAvailable)
                || res_encrypt == Err(Error::NoSuchKey),
            "Got result: {res_encrypt:?}"
        );

        let res_decrypt = try_syscall!(client.decrypt(m, key, b"", b"", b"", b""));
        assert!(
            res_decrypt == Err(Error::WrongKeyKind)
                || res_decrypt == Err(Error::MechanismNotAvailable)
                || res_decrypt == Err(Error::NoSuchKey),
            "Got result: {res_decrypt:?}"
        );
    }
}

#[test]
#[serial]
fn p256() {
    client::get(|client| {
        let sk1 = syscall!(client.generate_p256_private_key(Internal)).key;
        let pk1 = syscall!(client.derive_p256_public_key(sk1, Volatile)).key;

        assert_sign_mechanims_reject(sk1, client);
        assert_sign_mechanims_reject(pk1, client);
        assert_encrypt_mechanims_reject(sk1, client);
        assert_encrypt_mechanims_reject(pk1, client);
    })
}

#[test]
#[serial]
fn x255() {
    client::get(|client| {
        let sk1 = syscall!(client.generate_x255_secret_key(Internal)).key;
        let pk1 = syscall!(client.derive_x255_public_key(sk1, Volatile)).key;
        assert_sign_mechanims_reject(sk1, client);
        assert_sign_mechanims_reject(pk1, client);
        assert_encrypt_mechanims_reject(sk1, client);
        assert_encrypt_mechanims_reject(pk1, client);
    })
}
