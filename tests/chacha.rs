#![cfg(feature = "virt")]

use trussed::client::CryptoClient;
use trussed::types::{KeySerialization, Location, Mechanism, PathBuf, StorageAttributes};
use trussed::{syscall, try_syscall};

mod client;

use trussed::types::Location::*;

#[test]
fn chacha_wrapkey() {
    client::get(|client| {
        // Way to get a compatible Symmetric32 key
        let key = syscall!(client.unsafe_inject_key(
            Mechanism::Aes256Cbc,
            b"12345678123456781234567812345678",
            Location::Volatile,
            KeySerialization::Raw
        ))
        .key;

        let key2 = syscall!(client.generate_key(Mechanism::X255, StorageAttributes::new())).key;

        let wrapped =
            syscall!(client.wrap_key(Mechanism::Chacha8Poly1305, key, key2, &[])).wrapped_key;
        let unwrapped = syscall!(client.unwrap_key(
            Mechanism::Chacha8Poly1305,
            key,
            wrapped,
            &[],
            StorageAttributes::new()
        ))
        .key;

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
        let _unwrapped = syscall!(client.unwrap_key(
            Mechanism::Chacha8Poly1305,
            key,
            wrapped_ad,
            b"abc",
            StorageAttributes::new()
        ))
        .key;
    });
}

#[test]
fn chacha_wraptofile() {
    client::get(|client| {
        // Way to get a compatible Symmetric32 key
        let key = syscall!(client.unsafe_inject_key(
            Mechanism::Aes256Cbc,
            b"12345678123456781234567812345678",
            Location::Volatile,
            KeySerialization::Raw
        ))
        .key;

        let path = PathBuf::from("test_file");

        let key2 = syscall!(client.generate_key(Mechanism::X255, StorageAttributes::new())).key;

        syscall!(client.wrap_to_file(
            Mechanism::Chacha8Poly1305,
            key,
            key2,
            path.clone(),
            Location::Volatile,
            &[],
        ));

        let unwrapped = syscall!(client.unwrap_from_file(
            Mechanism::Chacha8Poly1305,
            key,
            path.clone(),
            Location::Volatile,
            Location::Volatile,
            &[],
        ))
        .key
        .unwrap();

        syscall!(client.wrap_to_file(
            Mechanism::Chacha8Poly1305,
            key,
            key2,
            path.clone(),
            Location::Volatile,
            b"some ad",
        ));

        assert!(syscall!(client.unwrap_from_file(
            Mechanism::Chacha8Poly1305,
            key,
            path.clone(),
            Location::Volatile,
            Location::Volatile,
            &[],
        ))
        .key
        .is_none());

        let unwrapped = syscall!(client.unwrap_from_file(
            Mechanism::Chacha8Poly1305,
            key,
            path.clone(),
            Location::Volatile,
            Location::Volatile,
            b"some ad",
        ))
        .key
        .unwrap();
    });
}
