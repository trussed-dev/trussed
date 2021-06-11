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
pub const MAX_KEY_MATERIAL_LENGTH: usize = 128;
// must be above + 4
pub const MAX_SERIALIZED_KEY_LENGTH: usize = 132;
pub type MAX_SERVICE_CLIENTS = consts::U5;
pub const MAX_SHORT_DATA_LENGTH: usize = 128;
// 72 was for P256, raw P384 is 96
pub const MAX_SIGNATURE_LENGTH: usize = 96;
pub const MAX_USER_ATTRIBUTE_LENGTH: usize = 256;

pub const USER_ATTRIBUTE_NUMBER: u8 = 37;

