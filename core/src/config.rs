// `mldsa44` bumps this so trussed's sign() Message can carry WebAuthn's
// `auth_data ‖ client_data_hash` commitment when auth_data embeds an
// ML-DSA-44 public key (~1577 B + 32 = ~1609 B). The unfeatured 1024
// stays the same so stock interchange buffers don't grow.
#[cfg(feature = "mldsa44")]
pub const MAX_MESSAGE_LENGTH: usize = 2048;
#[cfg(not(feature = "mldsa44"))]
pub const MAX_MESSAGE_LENGTH: usize = 1024;
pub const MAX_MEDIUM_DATA_LENGTH: usize = 256;
pub const MAX_SHORT_DATA_LENGTH: usize = 128;

// ML-DSA-44 signatures are 2420 bytes; everything else stays at 1024. Gating
// the bump avoids growing every interchange buffer (`Reply::Sign`,
// `Request::Verify`, …) when the feature is off.
#[cfg(feature = "mldsa44")]
pub const MAX_SIGNATURE_LENGTH: usize = 2432;
#[cfg(not(feature = "mldsa44"))]
pub const MAX_SIGNATURE_LENGTH: usize = 1024;

// FIXME: Value from https://stackoverflow.com/questions/5403808/private-key-length-bytes for Rsa2048 Private key
pub const MAX_KEY_MATERIAL_LENGTH: usize = 1160 * 2 + 72;
pub const MAX_USER_ATTRIBUTE_LENGTH: usize = 256;

// request size is chosen to not exceed the largest standard syscall, Decrypt, so that the Request
// enum does not grow from this variant
pub const SERDE_EXTENSION_REQUEST_LENGTH: usize =
    2 * MAX_MESSAGE_LENGTH + 2 * MAX_SHORT_DATA_LENGTH;
// reply size is chosen to not exceed the largest standard syscall, Encrypt, so that the Reply enum
// does not grow from this variant
pub const SERDE_EXTENSION_REPLY_LENGTH: usize = MAX_MESSAGE_LENGTH + 2 * MAX_SHORT_DATA_LENGTH;
