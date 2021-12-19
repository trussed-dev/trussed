use trussed::client::mechanisms::Rsa2kPkcs;
use trussed::client::CryptoClient;
use trussed::syscall;
use trussed::types::KeyId;

mod client;

use trussed::types::KeySerialization;
use trussed::types::Location::*;
use trussed::types::StorageAttributes;

// TODO: Looks like the test infra is not supposed to be used with several tests like below -
//       right now it randomly fails with SIGSERV on either of the two, when run together,
//       but never when run separately. Need to investigate and fix.

#[test]
fn rsa2kpkcs_generate_key() {
    client::get(|client| {
        let sk = syscall!(client.generate_rsa2kpkcs_private_key(Internal)).key;

        // This assumes we don't ever get a key with ID 0
        // TODO: make sure the above always holds or find a better way to check for success
        assert_ne!(sk, KeyId::from_special(0));
    })
}

#[test]
fn rsa2kpkcs_derive_key() {
    client::get(|client| {
        let sk = syscall!(client.generate_rsa2kpkcs_private_key(Internal)).key;
        let pk = syscall!(client.derive_rsa2kpkcs_public_key(sk, Volatile)).key;

        // This assumes we don't ever get a key with ID 0
        // TODO: make sure the above always holds or find a better way to check for success
        assert_ne!(pk, KeyId::from_special(0));
    })
}

#[test]
fn rsa2kpkcs_exists_key() {
    client::get(|client| {
        let sk = syscall!(client.generate_rsa2kpkcs_private_key(Internal)).key;
        let key_exists = syscall!(client.exists(trussed::types::Mechanism::Rsa2kPkcs, sk)).exists;

        assert!(key_exists);
    })
}

#[test]
fn rsa2kpkcs_serialize_key() {
    client::get(|client| {
        let sk = syscall!(client.generate_rsa2kpkcs_private_key(Internal)).key;

        let serialized_key =
            syscall!(client.serialize_rsa2kpkcs_key(sk, KeySerialization::Raw)).serialized_key;

        assert!(!serialized_key.is_empty());
    })
}

#[test]
fn rsa2kpkcs_deserialize_key() {
    client::get(|client| {
        let sk = syscall!(client.generate_rsa2kpkcs_private_key(Internal)).key;
        let serialized_key =
            syscall!(client.serialize_rsa2kpkcs_key(sk, KeySerialization::Raw)).serialized_key;
        let location = StorageAttributes {
            persistence: Volatile,
        };

        let deserialized_key_id = syscall!(client.deserialize_rsa2kpkcs_key(
            &serialized_key,
            KeySerialization::Raw,
            location
        ))
        .key;

        // This assumes we don't ever get a key with ID 0
        // TODO: make sure the above always holds or find a better way to check for success
        assert_ne!(deserialized_key_id, KeyId::from_special(0));
    })
}
