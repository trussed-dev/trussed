#![cfg(feature = "virt")]

use trussed::client::CryptoClient;
use trussed::syscall;

mod client;

use trussed::types::KeySerialization;
use trussed::types::Location::*;
use trussed::types::Mechanism;

use hex_literal::hex;

#[test]
fn tdes() {
    client::get(|client| {
        let key = syscall!(client.unsafe_inject_shared_key(&[48; 24], Volatile)).key;
        let ciphertext =
            syscall!(client.encrypt(Mechanism::Tdes, key, &[48; 8], &[], None)).ciphertext;

        assert_eq!(ciphertext, hex!("f47bb46273b15eb5"),);

        let plaintext = syscall!(client.decrypt(Mechanism::Tdes, key, &ciphertext, &[], &[], &[]))
            .plaintext
            .unwrap();
        assert_eq!(plaintext, &[48; 8]);
    });
    client::get(|client| {
        let key = syscall!(client.unsafe_inject_key(
            Mechanism::Tdes,
            &[48; 24],
            Volatile,
            KeySerialization::Raw
        ))
        .key;
        let ciphertext =
            syscall!(client.encrypt(Mechanism::Tdes, key, &[48; 8], &[], None)).ciphertext;

        assert_eq!(ciphertext, hex!("f47bb46273b15eb5"),);

        let plaintext = syscall!(client.decrypt(Mechanism::Tdes, key, &ciphertext, &[], &[], &[]))
            .plaintext
            .unwrap();
        assert_eq!(plaintext, &[48; 8]);
    })
}
