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
use crate::types::*;
#[allow(unused_imports)]
#[cfg(feature = "semihosting")]
use cortex_m_semihosting::hprintln;
use littlefs2::fs::File;
use littlefs2::io::Write;
use littlefs2::path::Path;

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
pub unsafe trait Store: Copy {
    type I: 'static + LfsStorage;
    type E: 'static + LfsStorage;
    type V: 'static + LfsStorage;
    fn ifs(self) -> &'static Fs<Self::I>;
    fn efs(self) -> &'static Fs<Self::E>;
    fn vfs(self) -> &'static Fs<Self::V>;
}

pub struct Fs<S: 'static + LfsStorage> {
    fs: &'static Filesystem<'static, S>,
}

impl<S: 'static + LfsStorage> core::ops::Deref for Fs<S> {
    type Target = Filesystem<'static, S>;
    fn deref(&self) -> &Self::Target {
        self.fs
    }
}

impl<S: 'static + LfsStorage> Fs<S> {
    pub fn new(fs: &'static Filesystem<'static, S>) -> Self {
        Self { fs }
    }
}

#[macro_export]
macro_rules! store {
    (
    $store:ident,
    Internal: $Ifs:ty,
    External: $Efs:ty,
    Volatile: $Vfs:ty
) => {
        #[derive(Clone, Copy)]
        pub struct $store {
            // __: $crate::store::NotSendOrSync,
            __: core::marker::PhantomData<*mut ()>,
        }

        unsafe impl $crate::store::Store for $store {
            type I = $Ifs;
            type E = $Efs;
            type V = $Vfs;

            fn ifs(self) -> &'static $crate::store::Fs<$Ifs> {
                unsafe { &*Self::ifs_ptr() }
            }
            fn efs(self) -> &'static $crate::store::Fs<$Efs> {
                unsafe { &*Self::efs_ptr() }
            }
            fn vfs(self) -> &'static $crate::store::Fs<$Vfs> {
                unsafe { &*Self::vfs_ptr() }
            }
        }

        impl $store {
            #[allow(dead_code)]
            pub fn allocate(
                internal_fs: $Ifs,
                external_fs: $Efs,
                volatile_fs: $Vfs,
            ) -> (
                &'static mut littlefs2::fs::Allocation<$Ifs>,
                &'static mut $Ifs,
                &'static mut littlefs2::fs::Allocation<$Efs>,
                &'static mut $Efs,
                &'static mut littlefs2::fs::Allocation<$Vfs>,
                &'static mut $Vfs,
            ) {
                // static mut INTERNAL_STORAGE: $Ifs = i_ctor();//<$Ifs>::new();

                static mut INTERNAL_STORAGE: Option<$Ifs> = None;
                unsafe {
                    INTERNAL_STORAGE = Some(internal_fs);
                }
                static mut INTERNAL_FS_ALLOC: Option<littlefs2::fs::Allocation<$Ifs>> = None;
                unsafe {
                    INTERNAL_FS_ALLOC = Some(littlefs2::fs::Filesystem::allocate());
                }

                // static mut EXTERNAL_STORAGE: $Efs = <$Efs>::new();
                static mut EXTERNAL_STORAGE: Option<$Efs> = None;
                unsafe {
                    EXTERNAL_STORAGE = Some(external_fs);
                }
                static mut EXTERNAL_FS_ALLOC: Option<littlefs2::fs::Allocation<$Efs>> = None;
                unsafe {
                    EXTERNAL_FS_ALLOC = Some(littlefs2::fs::Filesystem::allocate());
                }

                // static mut VOLATILE_STORAGE: $Vfs = <$Vfs>::new();
                static mut VOLATILE_STORAGE: Option<$Vfs> = None;
                unsafe {
                    VOLATILE_STORAGE = Some(volatile_fs);
                }
                static mut VOLATILE_FS_ALLOC: Option<littlefs2::fs::Allocation<$Vfs>> = None;
                unsafe {
                    VOLATILE_FS_ALLOC = Some(littlefs2::fs::Filesystem::allocate());
                }

                (
                    unsafe { INTERNAL_FS_ALLOC.as_mut().unwrap() },
                    unsafe { INTERNAL_STORAGE.as_mut().unwrap() },
                    unsafe { EXTERNAL_FS_ALLOC.as_mut().unwrap() },
                    unsafe { EXTERNAL_STORAGE.as_mut().unwrap() },
                    unsafe { VOLATILE_FS_ALLOC.as_mut().unwrap() },
                    unsafe { VOLATILE_STORAGE.as_mut().unwrap() },
                )
            }

            #[allow(dead_code)]
            pub fn init(
                internal_fs: $Ifs,
                external_fs: $Efs,
                volatile_fs: $Vfs,
                format: bool,
            ) -> Self {
                let (ifs_alloc, ifs_storage, efs_alloc, efs_storage, vfs_alloc, vfs_storage) =
                    Self::allocate(internal_fs, external_fs, volatile_fs);
                let store = Self::claim().unwrap();
                store
                    .mount(
                        ifs_alloc,
                        ifs_storage,
                        efs_alloc,
                        efs_storage,
                        vfs_alloc,
                        vfs_storage,
                        format,
                    )
                    .unwrap();

                store
            }

            #[allow(dead_code)]
            pub fn init_raw(
                ifs: &'static littlefs2::fs::Filesystem<$Ifs>,
                efs: &'static littlefs2::fs::Filesystem<$Efs>,
                vfs: &'static littlefs2::fs::Filesystem<$Vfs>,
            ) -> Self {
                let store_ifs = $crate::store::Fs::new(ifs);
                let store_efs = $crate::store::Fs::new(efs);
                let store_vfs = $crate::store::Fs::new(vfs);
                unsafe {
                    Self::ifs_ptr().write(store_ifs);
                    Self::efs_ptr().write(store_efs);
                    Self::vfs_ptr().write(store_vfs);
                }
                Self::claim().unwrap()
            }

            #[allow(dead_code)]
            pub fn attach(internal_fs: $Ifs, external_fs: $Efs, volatile_fs: $Vfs) -> Self {
                Self::init(internal_fs, external_fs, volatile_fs, false)
            }

            #[allow(dead_code)]
            pub fn format(internal_fs: $Ifs, external_fs: $Efs, volatile_fs: $Vfs) -> Self {
                Self::init(internal_fs, external_fs, volatile_fs, true)
            }

            pub fn claim() -> Option<$store> {
                use core::sync::atomic::{AtomicBool, Ordering};
                // use $crate::store::NotSendOrSync;

                static CLAIMED: AtomicBool = AtomicBool::new(false);

                if CLAIMED
                    .compare_exchange_weak(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    // Some(Self { __: unsafe { $crate::store::NotSendOrSync::new() } })
                    Some(Self {
                        __: core::marker::PhantomData,
                    })
                } else {
                    None
                }
            }

            fn ifs_ptr() -> *mut $crate::store::Fs<$Ifs> {
                use core::mem::MaybeUninit;
                use $crate::store::Fs;
                static mut IFS: MaybeUninit<Fs<$Ifs>> = MaybeUninit::uninit();
                unsafe { IFS.as_mut_ptr() }
            }

            fn efs_ptr() -> *mut $crate::store::Fs<$Efs> {
                use core::mem::MaybeUninit;
                use $crate::store::Fs;
                static mut EFS: MaybeUninit<Fs<$Efs>> = MaybeUninit::uninit();
                unsafe { EFS.as_mut_ptr() }
            }

            fn vfs_ptr() -> *mut $crate::store::Fs<$Vfs> {
                use core::mem::MaybeUninit;
                use $crate::store::Fs;
                static mut VFS: MaybeUninit<Fs<$Vfs>> = MaybeUninit::uninit();
                unsafe { VFS.as_mut_ptr() }
            }

            // Ignore lint for compatibility
            #[allow(clippy::too_many_arguments)]
            pub fn mount(
                &self,

                ifs_alloc: &'static mut littlefs2::fs::Allocation<$Ifs>,
                ifs_storage: &'static mut $Ifs,
                efs_alloc: &'static mut littlefs2::fs::Allocation<$Efs>,
                efs_storage: &'static mut $Efs,
                vfs_alloc: &'static mut littlefs2::fs::Allocation<$Vfs>,
                vfs_storage: &'static mut $Vfs,

                // statics: (
                //     &'static mut littlefs2::fs::Allocation<$Ifs>,
                //     &'static mut $Ifs,
                //     &'static mut littlefs2::fs::Allocation<$Efs>,
                //     &'static mut $Efs,
                //     &'static mut littlefs2::fs::Allocation<$Vfs>,
                //     &'static mut $Vfs,
                // ),
                // TODO: flag per backend?
                format: bool,
            ) -> littlefs2::io::Result<()> {
                use core::mem::MaybeUninit;
                use littlefs2::fs::{Allocation, Filesystem};

                static mut IFS_ALLOC: MaybeUninit<&'static mut Allocation<$Ifs>> =
                    MaybeUninit::uninit();
                static mut IFS_STORAGE: MaybeUninit<&'static mut $Ifs> = MaybeUninit::uninit();
                static mut IFS: Option<Filesystem<'static, $Ifs>> = None;

                static mut EFS_ALLOC: MaybeUninit<&'static mut Allocation<$Efs>> =
                    MaybeUninit::uninit();
                static mut EFS_STORAGE: MaybeUninit<&'static mut $Efs> = MaybeUninit::uninit();
                static mut EFS: Option<Filesystem<'static, $Efs>> = None;

                static mut VFS_ALLOC: MaybeUninit<&'static mut Allocation<$Vfs>> =
                    MaybeUninit::uninit();
                static mut VFS_STORAGE: MaybeUninit<&'static mut $Vfs> = MaybeUninit::uninit();
                static mut VFS: Option<Filesystem<'static, $Vfs>> = None;

                // let (ifs_alloc, ifs_storage, efs_alloc, efs_storage, vfs_alloc, vfs_storage) = statics;

                unsafe {
                    // always need to format RAM
                    Filesystem::format(vfs_storage).expect("can format");
                    // this is currently a RAM fs too...
                    Filesystem::format(efs_storage).expect("can format");

                    if format {
                        Filesystem::format(ifs_storage).expect("can format");
                    }

                    IFS_ALLOC.as_mut_ptr().write(ifs_alloc);
                    IFS_STORAGE.as_mut_ptr().write(ifs_storage);
                    IFS = Some(Filesystem::mount(
                        &mut *IFS_ALLOC.as_mut_ptr(),
                        &mut *IFS_STORAGE.as_mut_ptr(),
                    )?);
                    let ifs = $crate::store::Fs::new(IFS.as_ref().unwrap());
                    Self::ifs_ptr().write(ifs);

                    EFS_ALLOC.as_mut_ptr().write(efs_alloc);
                    EFS_STORAGE.as_mut_ptr().write(efs_storage);
                    EFS = Some(Filesystem::mount(
                        &mut *EFS_ALLOC.as_mut_ptr(),
                        &mut *EFS_STORAGE.as_mut_ptr(),
                    )?);
                    let efs = $crate::store::Fs::new(EFS.as_ref().unwrap());
                    Self::efs_ptr().write(efs);

                    VFS_ALLOC.as_mut_ptr().write(vfs_alloc);
                    VFS_STORAGE.as_mut_ptr().write(vfs_storage);
                    VFS = Some(Filesystem::mount(
                        &mut *VFS_ALLOC.as_mut_ptr(),
                        &mut *VFS_STORAGE.as_mut_ptr(),
                    )?);
                    let vfs = $crate::store::Fs::new(VFS.as_ref().unwrap());
                    Self::vfs_ptr().write(vfs);

                    Ok(())
                }
            }

            #[allow(dead_code)]
            pub fn attach_else_format(
                internal_fs: $Ifs,
                external_fs: $Efs,
                volatile_fs: $Vfs,
            ) -> Self {
                // This unfortunately repeates the code of `allocate`.
                // It seems Rust's borrowing rules go against this.
                use littlefs2::fs::{Allocation, Filesystem};

                static mut INTERNAL_STORAGE: Option<$Ifs> = None;
                unsafe {
                    INTERNAL_STORAGE = Some(internal_fs);
                }
                static mut INTERNAL_FS_ALLOC: Option<Allocation<$Ifs>> = None;
                unsafe {
                    INTERNAL_FS_ALLOC = Some(Filesystem::allocate());
                }

                // static mut EXTERNAL_STORAGE: $Efs = <$Efs>::new();
                static mut EXTERNAL_STORAGE: Option<$Efs> = None;
                unsafe {
                    EXTERNAL_STORAGE = Some(external_fs);
                }
                static mut EXTERNAL_FS_ALLOC: Option<Allocation<$Efs>> = None;
                unsafe {
                    EXTERNAL_FS_ALLOC = Some(Filesystem::allocate());
                }

                // static mut VOLATILE_STORAGE: $Vfs = <$Vfs>::new();
                static mut VOLATILE_STORAGE: Option<$Vfs> = None;
                unsafe {
                    VOLATILE_STORAGE = Some(volatile_fs);
                }
                static mut VOLATILE_FS_ALLOC: Option<Allocation<$Vfs>> = None;
                unsafe {
                    VOLATILE_FS_ALLOC = Some(Filesystem::allocate());
                }

                let store = Self::claim().unwrap();
                if store
                    .mount(
                        unsafe { INTERNAL_FS_ALLOC.as_mut().unwrap() },
                        unsafe { INTERNAL_STORAGE.as_mut().unwrap() },
                        unsafe { EXTERNAL_FS_ALLOC.as_mut().unwrap() },
                        unsafe { EXTERNAL_STORAGE.as_mut().unwrap() },
                        unsafe { VOLATILE_FS_ALLOC.as_mut().unwrap() },
                        unsafe { VOLATILE_STORAGE.as_mut().unwrap() },
                        false,
                    )
                    .is_err()
                {
                    store
                        .mount(
                            unsafe { INTERNAL_FS_ALLOC.as_mut().unwrap() },
                            unsafe { INTERNAL_STORAGE.as_mut().unwrap() },
                            unsafe { EXTERNAL_FS_ALLOC.as_mut().unwrap() },
                            unsafe { EXTERNAL_STORAGE.as_mut().unwrap() },
                            unsafe { VOLATILE_FS_ALLOC.as_mut().unwrap() },
                            unsafe { VOLATILE_STORAGE.as_mut().unwrap() },
                            true,
                        )
                        .unwrap();
                }

                store
            }
        }
    };
}

// TODO: replace this with "fs.create_dir_all(path.parent())"
pub fn create_directories<S: LfsStorage>(fs: &Filesystem<S>, path: &Path) -> Result<(), Error> {
    // hprintln!("preparing {:?}", core::str::from_utf8(path).unwrap()).ok();
    let path_bytes = path.as_ref().as_bytes();

    for i in 0..path_bytes.len() {
        if path_bytes[i] == b'/' {
            let dir_bytes = &path_bytes[..i];
            let dir = PathBuf::from(dir_bytes);
            // let dir_str = core::str::from_utf8(dir).unwrap();
            // hprintln!("create dir {:?}", dir_str).ok();
            // fs.create_dir(dir).map_err(|_| Error::FilesystemWriteFailure)?;
            match fs.create_dir(&dir) {
                Err(littlefs2::io::Error::EntryAlreadyExisted) => {}
                Ok(()) => {}
                error => {
                    panic!("{:?}", &error);
                }
            }
        }
    }
    Ok(())
}

/// Reads contents from path in location of store.
#[inline(never)]
pub fn read<const N: usize>(
    store: impl Store,
    location: Location,
    path: &Path,
) -> Result<Bytes<N>, Error> {
    debug_now!("reading {}", &path);
    match location {
        Location::Internal => store.ifs().read(path),
        Location::External => store.efs().read(path),
        Location::Volatile => store.vfs().read(path),
    }
    .map(Bytes::from)
    .map_err(|_| Error::FilesystemReadFailure)
}

pub fn fs_read_chunk<Storage: LfsStorage, const N: usize>(
    fs: &Filesystem<Storage>,
    path: &Path,
    pos: OpenSeekFrom,
) -> Result<(Bytes<N>, usize), Error> {
    let mut contents = Bytes::default();
    contents.resize_default(contents.capacity()).unwrap();
    let file_len = File::open_and_then(fs, path, |file| {
        file.seek(pos.into())?;
        let read_n = file.read(&mut contents)?;
        contents.truncate(read_n);
        file.len()
    })
    .map_err(|_| Error::FilesystemReadFailure)?;
    Ok((contents, file_len))
}
/// Reads contents from path in location of store.
#[inline(never)]
pub fn read_chunk<const N: usize>(
    store: impl Store,
    location: Location,
    path: &Path,
    pos: OpenSeekFrom,
) -> Result<(Bytes<N>, usize), Error> {
    debug_now!("reading chunk {},{:?}", &path, pos);
    match location {
        Location::Internal => fs_read_chunk(store.ifs(), path, pos),
        Location::External => fs_read_chunk(store.efs(), path, pos),
        Location::Volatile => fs_read_chunk(store.vfs(), path, pos),
    }
}

/// Writes contents to path in location of store.
#[inline(never)]
pub fn write(
    store: impl Store,
    location: Location,
    path: &Path,
    contents: &[u8],
) -> Result<(), Error> {
    debug_now!("writing {}", &path);
    match location {
        Location::Internal => store.ifs().write(path, contents),
        Location::External => store.efs().write(path, contents),
        Location::Volatile => store.vfs().write(path, contents),
    }
    .map_err(|_| Error::FilesystemWriteFailure)
}

pub fn fs_write_chunk<Storage: LfsStorage>(
    fs: &Filesystem<Storage>,
    path: &Path,
    contents: &[u8],
    pos: OpenSeekFrom,
) -> Result<(), Error> {
    File::<Storage>::with_options()
        .read(true)
        .write(true)
        .open_and_then(fs, path, |file| {
            file.seek(pos.into())?;
            file.write_all(contents)
        })
        .map_err(|_| Error::FilesystemReadFailure)?;
    Ok(())
}

/// Writes contents to path in location of store.
#[inline(never)]
pub fn write_chunk(
    store: impl Store,
    location: Location,
    path: &Path,
    contents: &[u8],
    pos: OpenSeekFrom,
) -> Result<(), Error> {
    debug_now!("writing {}", &path);
    match location {
        Location::Internal => fs_write_chunk(store.ifs(), path, contents, pos),
        Location::External => fs_write_chunk(store.efs(), path, contents, pos),
        Location::Volatile => fs_write_chunk(store.vfs(), path, contents, pos),
    }
    .map_err(|_| Error::FilesystemWriteFailure)
}

pub fn rename(
    store: impl Store,
    location: Location,
    from_path: &Path,
    to_path: &Path,
) -> Result<(), Error> {
    debug_now!("renaming {} to {}", from_path, to_path);
    match location {
        Location::Internal => store.ifs().rename(from_path, to_path),
        Location::External => store.efs().rename(from_path, to_path),
        Location::Volatile => store.vfs().rename(from_path, to_path),
    }
    .map_err(|_| Error::FilesystemWriteFailure)
}

pub fn move_file(
    store: impl Store,
    from_location: Location,
    from_path: &Path,
    to_location: Location,
    to_path: &Path,
) -> Result<(), Error> {
    debug_now!(
        "Moving {:?}({}) to {:?}({})",
        from_location,
        from_path,
        to_location,
        to_path
    );

    match to_location {
        Location::Internal => create_directories(store.ifs(), to_path),
        Location::External => create_directories(store.efs(), to_path),
        Location::Volatile => create_directories(store.vfs(), to_path),
    }
    .map_err(|_err| {
        error!("Failed to create directories chunks: {:?}", _err);
        Error::FilesystemWriteFailure
    })?;

    let on_fail = |_err| {
        error!("Failed to rename file: {:?}", _err);
        Error::FilesystemWriteFailure
    };
    // Fast path for same-filesystem
    match (from_location, to_location) {
        (Location::Internal, Location::Internal) => {
            return store.ifs().rename(from_path, to_path).map_err(on_fail)
        }
        (Location::External, Location::External) => {
            return store.efs().rename(from_path, to_path).map_err(on_fail)
        }
        (Location::Volatile, Location::Volatile) => {
            return store.vfs().rename(from_path, to_path).map_err(on_fail)
        }
        _ => {}
    }

    match from_location {
        Location::Internal => {
            move_file_step1(store, &**store.ifs(), from_path, to_location, to_path)
        }
        Location::External => {
            move_file_step1(store, &**store.efs(), from_path, to_location, to_path)
        }
        Location::Volatile => {
            move_file_step1(store, &**store.vfs(), from_path, to_location, to_path)
        }
    }
}

// Separate generic function to avoid having 9 times the same code because the filesystem types are not the same.
fn move_file_step1<S: LfsStorage>(
    store: impl Store,
    from_fs: &Filesystem<S>,
    from_path: &Path,
    to_location: Location,
    to_path: &Path,
) -> Result<(), Error> {
    match to_location {
        Location::Internal => move_file_step2(from_fs, from_path, &**store.ifs(), to_path),
        Location::External => move_file_step2(from_fs, from_path, &**store.efs(), to_path),
        Location::Volatile => move_file_step2(from_fs, from_path, &**store.vfs(), to_path),
    }
}

// Separate generic function to avoid having 9 times the same code because the filesystem types are not the same.
fn move_file_step2<S1: LfsStorage, S2: LfsStorage>(
    from_fs: &Filesystem<S1>,
    from_path: &Path,
    to_fs: &Filesystem<S2>,
    to_path: &Path,
) -> Result<(), Error> {
    File::open_and_then(from_fs, from_path, |from_file| {
        File::create_and_then(to_fs, to_path, |to_file| copy_file_data(from_file, to_file))
    })
    .map_err(|_err| {
        error!("Failed to flush chunks: {:?}", _err);
        Error::FilesystemWriteFailure
    })
}

fn copy_file_data<S1: LfsStorage, S2: LfsStorage>(
    from: &File<S1>,
    to: &File<S2>,
) -> Result<(), littlefs2::io::Error> {
    let mut buf = [0; 1024];
    loop {
        let read = from.read(&mut buf)?;
        if read == 0 {
            return Ok(());
        }

        to.write_all(&buf[..read])?;
    }
}

/// Creates parent directory if necessary, then writes.
#[inline(never)]
pub fn store(
    store: impl Store,
    location: Location,
    path: &Path,
    contents: &[u8],
) -> Result<(), Error> {
    debug_now!("storing {}", &path);
    match location {
        Location::Internal => create_directories(store.ifs(), path)?,
        Location::External => create_directories(store.efs(), path)?,
        Location::Volatile => create_directories(store.vfs(), path)?,
    }
    write(store, location, path, contents)
}

#[inline(never)]
pub fn delete(store: impl Store, location: Location, path: &Path) -> bool {
    debug_now!("deleting {}", &path);
    let outcome = match location {
        Location::Internal => store.ifs().remove(path),
        Location::External => store.efs().remove(path),
        Location::Volatile => store.vfs().remove(path),
    };
    outcome.is_ok()
}

#[inline(never)]
pub fn exists(store: impl Store, location: Location, path: &Path) -> bool {
    debug_now!("checking existence of {}", &path);
    match location {
        Location::Internal => path.exists(store.ifs()),
        Location::External => path.exists(store.efs()),
        Location::Volatile => path.exists(store.vfs()),
    }
}

#[inline(never)]
pub fn metadata(
    store: impl Store,
    location: Location,
    path: &Path,
) -> Result<Option<Metadata>, Error> {
    debug_now!("checking existence of {}", &path);
    let result = match location {
        Location::Internal => store.ifs().metadata(path),
        Location::External => store.efs().metadata(path),
        Location::Volatile => store.vfs().metadata(path),
    };
    match result {
        Ok(metadata) => Ok(Some(metadata)),
        Err(littlefs2::io::Error::NoSuchEntry) => Ok(None),
        Err(_) => Err(Error::FilesystemReadFailure),
    }
}

#[inline(never)]
pub fn remove_dir(store: impl Store, location: Location, path: &Path) -> bool {
    debug_now!("remove_dir'ing {}", &path);
    let outcome = match location {
        Location::Internal => store.ifs().remove_dir(path),
        Location::External => store.efs().remove_dir(path),
        Location::Volatile => store.vfs().remove_dir(path),
    };
    outcome.is_ok()
}

#[inline(never)]
pub fn remove_dir_all_where<P>(
    store: impl Store,
    location: Location,
    path: &Path,
    predicate: P,
) -> Result<usize, Error>
where
    P: Fn(&DirEntry) -> bool,
{
    debug_now!("remove_dir'ing {}", &path);
    let outcome = match location {
        Location::Internal => store.ifs().remove_dir_all_where(path, &predicate),
        Location::External => store.efs().remove_dir_all_where(path, &predicate),
        Location::Volatile => store.vfs().remove_dir_all_where(path, &predicate),
    };
    outcome.map_err(|_| Error::FilesystemWriteFailure)
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
