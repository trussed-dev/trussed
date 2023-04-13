#![cfg(feature = "virt")]

use trussed::client::CryptoClient;
use trussed::syscall;
use trussed::types::{
    KeyId, KeySerialization, Location::*, Mechanism, PathBuf, SignatureSerialization,
    StorageAttributes,
};

mod client;

fn assert_key_eq(key1: KeyId, key2: KeyId, client: &mut impl trussed::Client) {
    let derivative1 = syscall!(client.sign(
        Mechanism::HmacSha256,
        key1,
        &[],
        SignatureSerialization::Raw
    ))
    .signature;
    let derivative2 = syscall!(client.sign(
        Mechanism::HmacSha256,
        key2,
        &[],
        SignatureSerialization::Raw
    ))
    .signature;
    assert_eq!(derivative1, derivative2);
}

#[test]
fn chacha_wrapkey() {
    client::get(|client| {
        // Way to get a compatible Symmetric32 key
        let key = syscall!(client.unsafe_inject_key(
            Mechanism::Aes256Cbc,
            b"12345678123456781234567812345678",
            Volatile,
            KeySerialization::Raw
        ))
        .key;

        let key2 = syscall!(client.generate_secret_key(32, Volatile)).key;

        let wrapped =
            syscall!(client.wrap_key(Mechanism::Chacha8Poly1305, key, key2, &[])).wrapped_key;
        let unwrapped = syscall!(client.unwrap_key(
            Mechanism::Chacha8Poly1305,
            key,
            wrapped,
            &[],
            StorageAttributes::new()
        ))
        .key
        .unwrap();
        assert_key_eq(key2, unwrapped, client);

        let wrapped_ad =
            syscall!(client.wrap_key(Mechanism::Chacha8Poly1305, key, key2, b"abc")).wrapped_key;
        assert!(syscall!(client.unwrap_key(
            Mechanism::Chacha8Poly1305,
            key,
            wrapped_ad.clone(),
            &[],
            StorageAttributes::new()
        ))
        .key
        .is_none());
        let unwrapped2 = syscall!(client.unwrap_key(
            Mechanism::Chacha8Poly1305,
            key,
            wrapped_ad,
            b"abc",
            StorageAttributes::new()
        ))
        .key
        .unwrap();
        assert_key_eq(key2, unwrapped2, client);
    });
}

#[test]
fn chacha_wraptofile() {
    client::get(|client| {
        // Way to get a compatible Symmetric32 key
        let key = syscall!(client.unsafe_inject_key(
            Mechanism::Aes256Cbc,
            b"12345678123456781234567812345678",
            Volatile,
            KeySerialization::Raw
        ))
        .key;

        let path = PathBuf::from("test_file");

        let key2 = syscall!(client.generate_secret_key(32, Volatile)).key;

        syscall!(client.wrap_key_to_file(
            Mechanism::Chacha8Poly1305,
            key,
            key2,
            path.clone(),
            Volatile,
            &[],
        ));

        let unwrapped = syscall!(client.unwrap_key_from_file(
            Mechanism::Chacha8Poly1305,
            key,
            path.clone(),
            Volatile,
            Volatile,
            &[],
        ))
        .key
        .unwrap();
        assert_key_eq(key2, unwrapped, client);

        syscall!(client.wrap_key_to_file(
            Mechanism::Chacha8Poly1305,
            key,
            key2,
            path.clone(),
            Volatile,
            b"some ad",
        ));

        assert!(syscall!(client.unwrap_key_from_file(
            Mechanism::Chacha8Poly1305,
            key,
            path.clone(),
            Volatile,
            Volatile,
            &[],
        ))
        .key
        .is_none());

        let unwrapped = syscall!(client.unwrap_key_from_file(
            Mechanism::Chacha8Poly1305,
            key,
            path,
            Volatile,
            Volatile,
            b"some ad",
        ))
        .key
        .unwrap();
        assert_key_eq(key2, unwrapped, client);
    });
}
