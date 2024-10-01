// TODO: this needs to be overridable.
// Should we use the "config crate that can have a replacement patched in" idea?

pub const MAX_MESSAGE_LENGTH: usize = 1024;
pub const MAX_MEDIUM_DATA_LENGTH: usize = 256;
cfg_if::cfg_if! {
    if #[cfg(test)] {
        pub const MAX_SERVICE_CLIENTS: usize = 6;
    } else if #[cfg(feature = "clients-12")] {
        pub const MAX_SERVICE_CLIENTS: usize = 12;
    } else if #[cfg(feature = "clients-11")] {
        pub const MAX_SERVICE_CLIENTS: usize = 11;
    } else if #[cfg(feature = "clients-10")] {
        pub const MAX_SERVICE_CLIENTS: usize = 10;
    } else if #[cfg(feature = "clients-9")] {
        pub const MAX_SERVICE_CLIENTS: usize = 9;
    } else if #[cfg(feature = "clients-8")] {
        pub const MAX_SERVICE_CLIENTS: usize = 8;
    } else if #[cfg(feature = "clients-7")] {
        pub const MAX_SERVICE_CLIENTS: usize = 7;
    } else if #[cfg(feature = "clients-6")] {
        pub const MAX_SERVICE_CLIENTS: usize = 6;
    } else if #[cfg(feature = "clients-5")] {
        pub const MAX_SERVICE_CLIENTS: usize = 5;
    } else if #[cfg(feature = "clients-4")] {
        pub const MAX_SERVICE_CLIENTS: usize = 4;
    } else if #[cfg(feature = "clients-3")] {
        pub const MAX_SERVICE_CLIENTS: usize = 3;
    } else if #[cfg(feature = "clients-2")] {
        pub const MAX_SERVICE_CLIENTS: usize = 2;
    } else if #[cfg(feature = "clients-1")] {
        pub const MAX_SERVICE_CLIENTS: usize = 1;
    } else {
        pub const MAX_SERVICE_CLIENTS: usize = 0;
    }
}
pub const MAX_SHORT_DATA_LENGTH: usize = 128;

// Constant (static compile-time) max function
const fn max(a: usize, b: usize) -> usize {
    [a, b][(a < b) as usize]
}
pub const MAX_SIGNATURE_LENGTH: usize = max(
    // Default from before addition of PQC
    512 * 2,
    max(
        if cfg!(feature = "backend-dilithium2") {
            pqcrypto_dilithium::ffi::PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES
        } else {
            0
        },
        max(
            if cfg!(feature = "backend-dilithium3") {
                pqcrypto_dilithium::ffi::PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_BYTES
            } else {
                0
            },
            if cfg!(feature = "backend-dilithium5") {
                pqcrypto_dilithium::ffi::PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_BYTES
            } else {
                0
            },
        ),
    ),
);

// For the PQC algorithms, public and private key are generated at the same time and stored together as
// the private key. Then in the derive call, it just pulls the public key from the private key store
// and re-saves it as a public-only key. Therefore, the max material length is both keys together, plus
// the PKCS8 serialization overhead.
pub const MAX_KEY_MATERIAL_LENGTH: usize = max(
    // Default from before addition of PQC
    512 * 2,
    max(
        // + 31 is for PKCS#8 serialization
        if cfg!(feature = "backend-dilithium2") {
            pqcrypto_dilithium::ffi::PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES
                + pqcrypto_dilithium::ffi::PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_SECRETKEYBYTES
                + 31
        } else {
            0
        },
        max(
            if cfg!(feature = "backend-dilithium3") {
                pqcrypto_dilithium::ffi::PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_PUBLICKEYBYTES
                    + pqcrypto_dilithium::ffi::PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_SECRETKEYBYTES
                    + 31
            } else {
                0
            },
            if cfg!(feature = "backend-dilithium5") {
                pqcrypto_dilithium::ffi::PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_PUBLICKEYBYTES
                    + pqcrypto_dilithium::ffi::PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_SECRETKEYBYTES
                    + 31
            } else {
                0
            },
        ),
    ),
);

// Must be MAX_KEY_MATERIAL_LENGTH + 4
// Note that this is not the serialized key material (e.g. serialized PKCS#8), but
// the internal Trussed serialization that adds flags and such
pub const MAX_SERIALIZED_KEY_LENGTH: usize = MAX_KEY_MATERIAL_LENGTH + 4;

pub const MAX_USER_ATTRIBUTE_LENGTH: usize = 256;

pub const USER_ATTRIBUTE_NUMBER: u8 = 37;

// request size is chosen to not exceed the largest standard syscall, Decrypt, so that the Request
// enum does not grow from this variant
pub const SERDE_EXTENSION_REQUEST_LENGTH: usize =
    2 * MAX_MESSAGE_LENGTH + 2 * MAX_SHORT_DATA_LENGTH;
// reply size is chosen to not exceed the largest standard syscall, Encrypt, so that the Reply enum
// does not grow from this variant
pub const SERDE_EXTENSION_REPLY_LENGTH: usize = MAX_MESSAGE_LENGTH + 2 * MAX_SHORT_DATA_LENGTH;
