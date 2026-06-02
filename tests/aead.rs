use trussed_core::{
    syscall, try_syscall,
    types::{Location, Mechanism},
    CryptoClient, Error,
};

mod client;

const MECHANISMS: &[Mechanism] = &[
    #[cfg(feature = "chacha8-poly1305")]
    Mechanism::Chacha8Poly1305,
    #[cfg(feature = "aes256-gcm")]
    Mechanism::Aes256Gcm,
];

#[test]
fn test_invalid_key_size() {
    client::get(|client| {
        for mechanism in MECHANISMS {
            let key = syscall!(client.generate_secret_key(16, Location::Volatile)).key;
            let result = try_syscall!(client.encrypt(*mechanism, key, &[], &[], None));
            assert_eq!(result, Err(Error::WrongKeyKind));
        }
    });
}
