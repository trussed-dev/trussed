// TODO: this needs to be overridable.
// Should we use the "config crate that can have a replacement patched in" idea?

pub use trussed_core::config::{
    MAX_KEY_MATERIAL_LENGTH, MAX_MEDIUM_DATA_LENGTH, MAX_MESSAGE_LENGTH, MAX_SHORT_DATA_LENGTH,
    MAX_SIGNATURE_LENGTH, MAX_USER_ATTRIBUTE_LENGTH, SERDE_EXTENSION_REPLY_LENGTH,
    SERDE_EXTENSION_REQUEST_LENGTH,
};

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

// must be MAX_KEY_MATERIAL_LENGTH + 4
pub const MAX_SERIALIZED_KEY_LENGTH: usize = MAX_KEY_MATERIAL_LENGTH + 4;

pub const USER_ATTRIBUTE_NUMBER: u8 = 37;
