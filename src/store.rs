//! `store` presents a combined interface to three littlefs2 filesystems:
//! internal flash, external flash, volatile/RAM.
//!
//! It covers two usecases:
//! - cryptographic key storage (for trussed itself)
//! - somewhat namespaced key-value storage for client apps
//!
//! The cryptographic keys are stored with a random filename (which is used as
//! "handle" for the key).
//!
//! The key-value storage has keys aka filenames choosable by the client.
//!
//! The guiding example for client apps is `fido-authenticator`, which stores:
//! - it basic state and config, and
//! - the metadata for its resident keys as a serialized struct
//!
//! Both include references to cryptographic keys (via their handle)
//!
//! Currently, the backend (internal/external/volatile) is determined via an
//! enum parameter, which is translated to the corresponding generic type.
//! I think it would be nice to "mount" the three in a unified filesystem,
//! e.g. internal under `/`, external under `/mnt` (it's not available when
//! powered via NFC), volatile under `/tmp`.
//!
//! If this is done, it would be great to abstract over the three backends,
//! and just take some array with associated "mount points". But KISS it ofc...
//!
//! This store needs to enforce namespacing by apps, ensuring they can't escape
//! by loading some file `../../<other app>/keys/...` or similar.
//! This is orthogonal to the three backends split, I'm not quite sure yet how
//! to expose this and how to map this to paths.
//!
//!
//! Here's my current thinking:
//!
//! ```text
//! /
//! |-- data/
//!     |-- <app id>/
//!         |--dir.1/
//!            +-- file.1
//!            +-- file.2
//!         |-- dir.2
//!            +-- file.1
//!            +-- file.2
//!         +-- file.1
//!         +-- file.2
//! |-- keys/
//! ```
//!
//! NOTE !!! ==> ideally can filter out CredentialProtectionPolicy in ReadDirFiles (via attribute)
//!
//! ```text
//! (fido)
//!     :   |-- data/              <-- the KeyValue portion
//!         :   |-- rk/
//!                 |-- <rp hash>/
//!                     + rk.1
//!                     + rk.2
//!                     :
//!                 |-- <rp hash>/
//!             + config
//!             +
//! ```
//!
//! Why? This:
//! - typical use-case is one RK per RP (I'd assume!)
//! - allows easy lookup in this case!
//! - allows easy "count RKs" (possibly filtered) for GetAssertion
//! - allows easy "count RPs" (for CredMgmt)
//! - CON: this is already two directories deep (not just "one namespace')
//! - Alternative: subdirectory <==> RP hash, everything else in flat files
//! - In any case need to "list dirs excluding . and .." or similar

use crate::error::Error;
use crate::types::{Bytes, Location};
use littlefs2_core::{path, DirEntry, Metadata, Path};

pub use littlefs2_core::{DynFile, DynFilesystem};

pub mod certstore;
pub mod counterstore;
pub mod filestore;
pub mod keystore;

// pub type FileContents = Bytes<MAX_FILE_SIZE>;

// pub mod our {
//     type Result = ();
// }

// pub trait KeyValue: Store + Copy {
//     fn set(
//         // "root" or an actual client. Maybe map to `/root` and `/home/<client>`?
//         client: ClientId,
//         // this needs to be piped via RPC, the idea is to allow a file "config"
//         // with no namespace, and e.g. a namespace "rk" that can easily be iterated over.
//         namespace: Option<PathComponent>,
//         // intention of attributes is to allow for easy (client-specified) filtering
//         // without reading and transmitting the contents of each file (it would be neat
//         // for the RPC call to pass a closure-filter, but I doubt would work currently).
//         // For instance, `fido-authenticator` can use "hashed RP ID" under its `rk` namespace.
//         attribute: Option<Attribute>,

//         // the data
//         data: FileContents,
//     ) -> our::Result<()>;

//     fn get(
//         client: ClientId,
//         namespace: Option<PathComponent>,
//         attribute: Option<Attribute>,
//     ) -> our::Result<FileContents>;
// }

// pub trait CryptoKey: Store + Copy {
// }

// This is a "trick" I learned from japaric's rewrite of the littlefs
// API, using a trait and a macro (that the caller implements with the specific
// LfsStorage-bound types) to remove lifetimes and generic parameters from Store.
//
// This makes everything using it *much* more ergonomic.
pub trait Store {
    fn ifs(&self) -> &dyn DynFilesystem;
    fn efs(&self) -> &dyn DynFilesystem;
    fn vfs(&self) -> &dyn DynFilesystem;
    fn fs(&self, location: Location) -> &dyn DynFilesystem {
        match location {
            Location::Internal => self.ifs(),
            Location::External => self.efs(),
            Location::Volatile => self.vfs(),
        }
    }
}

pub fn create_directories(fs: &dyn DynFilesystem, path: &Path) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        fs.create_dir_all(&parent)
            .map_err(|_| Error::FilesystemWriteFailure)?;
    }
    Ok(())
}

/// Reads contents from path in location of store.
#[inline(never)]
pub fn read<const N: usize>(
    store: &impl Store,
    location: Location,
    path: &Path,
) -> Result<Bytes<N>, Error> {
    debug_now!("reading {}", &path);
    store
        .fs(location)
        .read(path)
        .map_err(|_| Error::FilesystemReadFailure)
}

/// Writes contents to path in location of store.
#[inline(never)]
pub fn write(
    store: &impl Store,
    location: Location,
    path: &Path,
    contents: &[u8],
) -> Result<(), Error> {
    debug_now!("writing {}", &path);
    store
        .fs(location)
        .write(path, contents)
        .map_err(|_| Error::FilesystemWriteFailure)
}

/// Creates parent directory if necessary, then writes.
#[inline(never)]
pub fn store(
    store: &impl Store,
    location: Location,
    path: &Path,
    contents: &[u8],
) -> Result<(), Error> {
    debug_now!("storing {}", &path);
    create_directories(store.fs(location), path)?;
    store
        .fs(location)
        .write(path, contents)
        .map_err(|_| Error::FilesystemWriteFailure)
}

#[inline(never)]
pub fn delete(store: &impl Store, location: Location, path: &Path) -> bool {
    debug_now!("deleting {}", &path);
    let fs = store.fs(location);
    if fs.remove(path).is_err() {
        return false;
    }

    // Only delete ancestors for volatile FS
    if location != Location::Volatile {
        return true;
    }
    // first ancestor is the file itself
    for parent in path.ancestors().skip(1) {
        if &*parent == path!("/") {
            break;
        }
        let Ok(meta) = fs.metadata(&parent) else {
            return false;
        };
        if meta.is_dir() && meta.is_empty() {
            if fs.remove_dir(&parent).is_err() {
                return false;
            }
        } else {
            break;
        }
    }
    true
}

#[inline(never)]
pub fn exists(store: &impl Store, location: Location, path: &Path) -> bool {
    debug_now!("checking existence of {}", &path);
    store.fs(location).exists(path)
}

#[inline(never)]
pub fn metadata(
    store: &impl Store,
    location: Location,
    path: &Path,
) -> Result<Option<Metadata>, Error> {
    debug_now!("checking existence of {}", &path);
    match store.fs(location).metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(littlefs2_core::Error::NO_SUCH_ENTRY) => Ok(None),
        Err(_) => Err(Error::FilesystemReadFailure),
    }
}

#[inline(never)]
pub fn rename(store: &impl Store, location: Location, from: &Path, to: &Path) -> Result<(), Error> {
    debug_now!("renaming {} to {}", &from, &to);
    store
        .fs(location)
        .rename(from, to)
        .map_err(|_| Error::FilesystemWriteFailure)
}

#[inline(never)]
pub fn remove_dir(store: &impl Store, location: Location, path: &Path) -> bool {
    debug_now!("remove_dir'ing {}", &path);
    store.fs(location).remove_dir(path).is_ok()
}

#[inline(never)]
pub fn remove_dir_all_where(
    store: &impl Store,
    location: Location,
    path: &Path,
    predicate: &dyn Fn(&DirEntry) -> bool,
) -> Result<usize, Error> {
    debug_now!("remove_dir'ing {}", &path);
    store
        .fs(location)
        .remove_dir_all_where(path, predicate)
        .map_err(|_| Error::FilesystemWriteFailure)
}

// pub fn delete_volatile(store: impl Store, handle: &ObjectHandle) -> bool {
//     let secrecies = [
//         Secrecy::Secret,
//         Secrecy::Public,
//     ];

//     let success = secrecies.iter().any(|secrecy| {
//         let path = self.key_path(*secrecy, handle);
//         store::delete(store, Location::Volatile, &path)
//     });

//     success
// }

// pub fn delete_anywhere(store: impl Store, handle: &ObjectHandle) -> bool {
//     let secrecies = [
//         Secrecy::Secret,
//         Secrecy::Public,
//     ];

//     let locations = [
//         Location::Internal,
//         Location::External,
//         Location::Volatile,
//     ];

//     let success = secrecies.iter().any(|secrecy| {
//         let path = self.key_path(*secrecy, handle);
//         locations.iter().any(|location| {
//             store::delete(store, *location, &path)
//         })
//     });

//     success
// }
