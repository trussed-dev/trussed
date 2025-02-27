// TODO: this needs to be overridable.
// Should we use the "config crate that can have a replacement patched in" idea?

pub use trussed_core::config::{
    MAX_KEY_MATERIAL_LENGTH, MAX_MEDIUM_DATA_LENGTH, MAX_MESSAGE_LENGTH, MAX_SERIALIZED_KEY_LENGTH,
    MAX_SHORT_DATA_LENGTH, MAX_SIGNATURE_LENGTH, MAX_USER_ATTRIBUTE_LENGTH,
    SERDE_EXTENSION_REPLY_LENGTH, SERDE_EXTENSION_REQUEST_LENGTH,
};

pub const USER_ATTRIBUTE_NUMBER: u8 = 37;
