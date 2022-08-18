#![cfg(feature = "virt")]

use trussed::client::CryptoClient;
use trussed::syscall;

mod client;

use trussed::types::Location::*;
use trussed::types::{Mechanism, StorageAttributes};

use aes::Aes256;
use block_modes::block_padding::ZeroPadding;
use block_modes::{BlockMode, Cbc};
use sha2::digest::Digest;

#[test]
fn aes256cbc() {
    client::get(|client| {
        let secret = syscall!(client.unsafe_inject_shared_key(&[], Volatile)).key;
        let key =
            syscall!(client.derive_key(Mechanism::Sha256, secret, None, StorageAttributes::new()))
                .key;
        let ciphertext =
            syscall!(client.encrypt(Mechanism::Aes256Cbc, key, &[48; 64], &[], None)).ciphertext;

        let hash = sha2::Sha256::new();
        let key_ref = hash.finalize();
        let cipher = Cbc::<Aes256, ZeroPadding>::new_from_slices(&key_ref, &[0; 16]).unwrap();
        let mut buffer = [48; 64];
        cipher.encrypt(&mut buffer, 64).unwrap();
        assert_ne!(buffer, [48; 64]);
        assert_eq!(buffer.as_slice(), *ciphertext);

        let plaintext =
            syscall!(client.decrypt(Mechanism::Aes256Cbc, key, &ciphertext, &[], &[], &[]))
                .plaintext
                .unwrap();
        assert_eq!(plaintext, &[48; 64]);
    })
}
