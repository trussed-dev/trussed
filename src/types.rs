pub use generic_array::GenericArray;

pub use heapless::{String, Vec};

pub use crate::Bytes;

pub use littlefs2_core::{DirEntry, Metadata, Path, PathBuf, Result as LfsResult};

pub use trussed_core::types::{
    reboot, CertId, CounterId, Id, KeyId, KeySerialization, Location, Mechanism, MediumData,
    Message, ObjectId, SerializedKey, ShortData, Signature, SignatureSerialization, SpecialId,
    StorageAttributes, UserAttribute,
};

use crate::interrupt::InterruptFlag;
use crate::store::filestore::{ReadDirFilesState, ReadDirState};

pub use crate::client::FutureResult;
pub use crate::platform::Platform;

/// An empty struct not storing any data.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NoData;

pub mod ui {
    use serde::{Deserialize, Serialize};

    // TODO: Consider whether a simple "language" to specify "patterns"
    // makes sense, vs. "semantic" indications with platform-specific implementation
    #[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
    #[non_exhaustive]
    pub enum Status {
        Idle,
        WaitingForUserPresence,
        Processing,
        Error,
        Custom(u8),
    }
}

pub mod consent {
    pub use trussed_core::types::consent::{Error, Level, Result};

    use serde::{Deserialize, Serialize};

    #[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
    pub enum Urgency {
        /// Pending other user consent requests will fail as interrupted.
        InterruptOthers,
        /// If other user consent requests are pending, fail this request.
        FailIfOthers,
    }
}

pub const IMPLEMENTED_MECHANISMS: &[Mechanism] = &[
    #[cfg(feature = "aes256-cbc")]
    Mechanism::Aes256Cbc,
    #[cfg(feature = "chacha8-poly1305")]
    Mechanism::Chacha8Poly1305,
    #[cfg(feature = "ed255")]
    Mechanism::Ed255,
    #[cfg(feature = "hmac-blake2s")]
    Mechanism::HmacBlake2s,
    #[cfg(feature = "hmac-sha1")]
    Mechanism::HmacSha1,
    #[cfg(feature = "hmac-sha256")]
    Mechanism::HmacSha256,
    #[cfg(feature = "hmac-sha512")]
    Mechanism::HmacSha512,
    #[cfg(feature = "p256")]
    Mechanism::P256,
    #[cfg(feature = "p256")]
    Mechanism::P256Prehashed,
    #[cfg(feature = "p384")]
    Mechanism::P384,
    #[cfg(feature = "p384")]
    Mechanism::P384Prehashed,
    #[cfg(feature = "p521")]
    Mechanism::P521,
    #[cfg(feature = "p521")]
    Mechanism::P521Prehashed,
    #[cfg(feature = "sha256")]
    Mechanism::Sha256,
    #[cfg(feature = "shared-secret")]
    Mechanism::SharedSecret,
    #[cfg(feature = "tdes")]
    Mechanism::Tdes,
    #[cfg(feature = "totp")]
    Mechanism::Totp,
    #[cfg(feature = "x255")]
    Mechanism::X255,
];

/// The context for a syscall (per client).
///
/// The context stores the state used by the standard syscall implementations, see
/// [`CoreContext`][].  Additionally, backends can define a custom context for their syscall
/// implementations.
#[non_exhaustive]
pub struct Context<B> {
    pub core: CoreContext,
    pub backends: B,
}

impl<B: Default> From<CoreContext> for Context<B> {
    fn from(core: CoreContext) -> Self {
        Self {
            core,
            backends: B::default(),
        }
    }
}

// The "CoreContext" struct is the closest equivalent to a PCB that Trussed
// currently has. Trussed currently uses it to choose the client-specific
// subtree in the filesystem (see docs in src/store.rs) and to maintain
// the walker state of the directory traversal syscalls.
#[non_exhaustive]
pub struct CoreContext {
    pub path: PathBuf,
    pub read_dir_state: Option<ReadDirState>,
    pub read_dir_files_state: Option<ReadDirFilesState>,
    pub interrupt: Option<&'static InterruptFlag>,
}

impl CoreContext {
    pub fn new(path: PathBuf) -> Self {
        Self::with_interrupt(path, None)
    }

    pub fn with_interrupt(path: PathBuf, interrupt: Option<&'static InterruptFlag>) -> Self {
        if path.as_str() == "trussed" {
            panic!("trussed is a reserved client ID");
        }
        Self {
            path,
            read_dir_state: None,
            read_dir_files_state: None,
            interrupt,
        }
    }
}

// Object Hierarchy according to Cryptoki
// - Storage
//   - Domain parameters
//   - Key
//   - Certificate
//   - Data
// - Hardware feature
// - Mechanism
// - Profiles
