#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]

use littlefs2::consts;

// TODO: this needs to be overridable.
// Should we use the "config crate that can have a replacement patched in" idea?

pub type MAX_APPLICATION_NAME_LENGTH = consts::U256;
pub const MAX_LONG_DATA_LENGTH: usize = 1024;
pub const MAX_MESSAGE_LENGTH: usize = 1024;
pub type MAX_OBJECT_HANDLES = consts::U16;
pub type MAX_LABEL_LENGTH = consts::U256;
pub const MAX_MEDIUM_DATA_LENGTH: usize = 256;
pub type MAX_PATH_LENGTH = consts::U256;
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

cfg_if::cfg_if! {
    if #[cfg(feature = "pqc")] {
        // TODO: derive these values appropriately
        // If we're using the PQC backend, pull the max sizes from that crate.
        pub const MAX_SIGNATURE_LENGTH: usize = 4627; //trussed_pqc_backend::sizes::MAX_SIGNATURE_LENGTH;
        // For the PQC algorithms, public and private key are generated at the same time and stored together as
        // the private key. Then in the derive call, it just pulls the public key from the private key store
        // and re-saves it as a public-only key. Therefore, the max material length is both keys together, plus
        // the PKCS8 serialization overhead.
        pub const MAX_KEY_MATERIAL_LENGTH: usize = 7519; //trussed_pqc_backend::sizes::MAX_PRIVATE_KEY_LENGTH + trussed_pqc_backend::sizes::MAX_PUBLIC_KEY_LENGTH;
    } else {
        pub const MAX_SIGNATURE_LENGTH: usize = 512 * 2;
        // FIXME: Value from https://stackoverflow.com/questions/5403808/private-key-length-bytes for Rsa2048 Private key
        pub const MAX_KEY_MATERIAL_LENGTH: usize = 1160 * 2 + 72;
    }
}

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
