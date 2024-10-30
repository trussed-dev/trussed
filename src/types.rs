pub use generic_array::GenericArray;

pub use heapless::{String, Vec};

pub use crate::Bytes;

pub use littlefs2::{driver::Storage as LfsStorage, fs::Filesystem};
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
        Self {
            path,
            read_dir_state: None,
            read_dir_files_state: None,
            interrupt: None,
        }
    }

    pub fn with_interrupt(path: PathBuf, interrupt: Option<&'static InterruptFlag>) -> Self {
        Self {
            path,
            read_dir_state: None,
            read_dir_files_state: None,
            interrupt,
        }
    }
}

impl From<PathBuf> for CoreContext {
    fn from(path: PathBuf) -> Self {
        Self::new(path)
    }
}

impl From<&str> for CoreContext {
    fn from(s: &str) -> Self {
        Self::new(s.try_into().unwrap())
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
