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

#[test]
fn test_encrypt_bad_nonce_length() {
    client::get(|client| {
        for mechanism in MECHANISMS {
            let key = syscall!(client.generate_secret_key(32, Location::Volatile)).key;
            let result =
                try_syscall!(client.encrypt(*mechanism, key, &[], &[], Some(b"nonce".into())));
            assert_eq!(result, Err(Error::MechanismParamInvalid));
        }
    })
}

#[test]
fn test_decrypt_bad_lengths() {
    client::get(|client| {
        for mechanism in MECHANISMS {
            let key = syscall!(client.generate_secret_key(32, Location::Volatile)).key;
            let encrypted = syscall!(client.encrypt(*mechanism, key, &[], &[], None));

            // bad nonce length
            let result = try_syscall!(client.decrypt(
                *mechanism,
                key,
                &encrypted.ciphertext,
                &[],
                b"nonce",
                &encrypted.tag
            ));
            assert_eq!(result, Err(Error::MechanismParamInvalid));

            // bad tag length
            let result = try_syscall!(client.decrypt(
                *mechanism,
                key,
                &encrypted.ciphertext,
                &[],
                &encrypted.nonce,
                b"tag"
            ));
            assert_eq!(result, Err(Error::MechanismParamInvalid));
        }
    })
}
