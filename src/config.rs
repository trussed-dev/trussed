#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]

// TODO: this needs to be overridable.
// Should we use the "config crate that can have a replacement patched in" idea?

pub const MAX_LONG_DATA_LENGTH: usize = 1024;
pub const MAX_MESSAGE_LENGTH: usize = 1024;
pub const MAX_MEDIUM_DATA_LENGTH: usize = 256;

pub const MAX_SHORT_DATA_LENGTH: usize = 128;

pub const MAX_SIGNATURE_LENGTH: usize = 512 * 2;
// FIXME: Value from https://stackoverflow.com/questions/5403808/private-key-length-bytes for Rsa2048 Private key
pub const MAX_KEY_MATERIAL_LENGTH: usize = 1160 * 2 + 72;

// must be MAX_KEY_MATERIAL_LENGTH + 4
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
