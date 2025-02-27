pub const MAX_MEDIUM_DATA_LENGTH: usize = 256;
pub const MAX_SHORT_DATA_LENGTH: usize = 128;
pub const MAX_USER_ATTRIBUTE_LENGTH: usize = 256;

// request size is chosen to not exceed the largest standard syscall, Decrypt, so that the Request
// enum does not grow from this variant
pub const SERDE_EXTENSION_REQUEST_LENGTH: usize =
    2 * MAX_MESSAGE_LENGTH + 2 * MAX_SHORT_DATA_LENGTH;
// reply size is chosen to not exceed the largest standard syscall, Encrypt, so that the Reply enum
// does not grow from this variant
pub const SERDE_EXTENSION_REPLY_LENGTH: usize = MAX_MESSAGE_LENGTH + 2 * MAX_SHORT_DATA_LENGTH;

// Must be MAX_KEY_MATERIAL_LENGTH + 4
// Note that this is not the serialized key material (e.g. serialized PKCS#8), but
// the internal Trussed serialization that adds flags and such
pub const MAX_SERIALIZED_KEY_LENGTH: usize = MAX_KEY_MATERIAL_LENGTH + 4;

// For the PQC algorithms, public and private key are generated at the same time and stored together as
// the private key. Then in the derive call, it just pulls the public key from the private key store
// and re-saves it as a public-only key. Therefore, the max material length is both keys together, plus
// the PKCS8 DER encoding overhead (31 bytes).
cfg_if::cfg_if! {
    if #[cfg(feature = "mldsa87")] {
        pub const MAX_SIGNATURE_LENGTH: usize = pqcrypto_mldsa::ffi::PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES;
        pub const MAX_KEY_MATERIAL_LENGTH: usize = pqcrypto_mldsa::ffi::PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES
        + pqcrypto_mldsa::ffi::PQCLEAN_MLDSA87_CLEAN_CRYPTO_SECRETKEYBYTES
        + 31;
        //pub const MAX_MESSAGE_LENGTH: usize = MAX_KEY_MATERIAL_LENGTH;
        pub const MAX_FIDO_WRAPPED_KEY_LENGTH: usize =  MAX_SERIALIZED_KEY_LENGTH + 57;
    } else if #[cfg(feature = "mldsa65")] {
        pub const MAX_SIGNATURE_LENGTH: usize = pqcrypto_mldsa::ffi::PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES;
        pub const MAX_KEY_MATERIAL_LENGTH: usize = pqcrypto_mldsa::ffi::PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES
        + pqcrypto_mldsa::ffi::PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES
        + 31;
        //pub const MAX_MESSAGE_LENGTH: usize = MAX_KEY_MATERIAL_LENGTH;
        pub const MAX_FIDO_WRAPPED_KEY_LENGTH: usize =  MAX_SERIALIZED_KEY_LENGTH + 57;
    } else if #[cfg(feature = "mldsa44")] {
        pub const MAX_SIGNATURE_LENGTH: usize = pqcrypto_mldsa::ffi::PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES;
        pub const MAX_KEY_MATERIAL_LENGTH: usize = pqcrypto_mldsa::ffi::PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES
        + pqcrypto_mldsa::ffi::PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES
        + 31;
        //pub const MAX_MESSAGE_LENGTH: usize = MAX_KEY_MATERIAL_LENGTH;
        pub const MAX_FIDO_WRAPPED_KEY_LENGTH: usize =  MAX_SERIALIZED_KEY_LENGTH + 57;
    } else {
        // Default from before addition of PQC
        pub const MAX_SIGNATURE_LENGTH: usize = 512 * 2;
        // FIXME: Value from https://stackoverflow.com/questions/5403808/private-key-length-bytes for Rsa2048 Private key
        pub const MAX_KEY_MATERIAL_LENGTH: usize = 1160 * 2 + 72;
        //pub const MAX_MESSAGE_LENGTH: usize = 1024;
        pub const MAX_FIDO_WRAPPED_KEY_LENGTH: usize = 128;
    }
}

// 30 bytes are added by CBOR serialization of a FullCredential
pub const MAX_MESSAGE_LENGTH: usize = MAX_FIDO_WRAPPED_KEY_LENGTH + 30 + 2031 + 32 + 37; // TODO: update this to use different consts for each area where this is needed
