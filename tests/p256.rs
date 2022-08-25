#![cfg(feature = "virt")]

use trussed::client::mechanisms::{HmacSha256, P256};
use trussed::client::CryptoClient;
use trussed::types::{KeySerialization, Mechanism, StorageAttributes};
use trussed::{syscall, try_syscall};

mod client;

use trussed::types::Location::*;

#[test]
fn p256_agree() {
    client::get(|client| {
        let sk1 = syscall!(client.generate_p256_private_key(Internal)).key;
        let pk1 = syscall!(client.derive_p256_public_key(sk1, Volatile)).key;
        let sk2 = syscall!(client.generate_p256_private_key(Internal)).key;
        let pk2 = syscall!(client.derive_p256_public_key(sk2, Volatile)).key;

        let secret1 = syscall!(client.agree_p256(sk1, pk2, Volatile)).shared_secret;

        let secret2 = syscall!(client.agree(
            Mechanism::P256,
            sk2,
            pk1,
            StorageAttributes::new().set_serializable(true)
        ))
        .shared_secret;

        // Trussed® won't give out secrets, but lets us use them
        let derivative1 = syscall!(client.sign_hmacsha256(secret1, &[])).signature;
        let derivative2 = syscall!(client.sign_hmacsha256(secret2, &[])).signature;
        assert_eq!(derivative1, derivative2);

        assert!(try_syscall!(client.serialize_key(
            Mechanism::SharedSecret,
            secret1,
            KeySerialization::Raw
        ))
        .is_err());
        let _ =
            syscall!(client.serialize_key(Mechanism::SharedSecret, secret2, KeySerialization::Raw));
    })
}
