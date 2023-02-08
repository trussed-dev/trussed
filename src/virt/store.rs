use std::{
    fs::{File, OpenOptions},
    io::{Read as _, Seek as _, SeekFrom, Write as _},
    marker::PhantomData,
    path::PathBuf,
};

use generic_array::typenum::{U512, U8};
use littlefs2::{const_ram_storage, driver::Storage, fs::Allocation};

use crate::{
    store,
    store::Store,
    types::{LfsResult, LfsStorage},
};

pub trait StoreProvider {
    type Store: Store;

    unsafe fn ifs() -> &'static mut <Self::Store as Store>::I;

    unsafe fn store() -> Self::Store;

    unsafe fn reset(&self);
}

const STORAGE_SIZE: usize = 512 * 128;

static mut INTERNAL_RAM_STORAGE: Option<InternalStorage> = None;
static mut INTERNAL_RAM_FS_ALLOC: Option<Allocation<InternalStorage>> = None;

static mut INTERNAL_FILESYSTEM_STORAGE: Option<FilesystemStorage> = None;
static mut INTERNAL_FILESYSTEM_FS_ALLOC: Option<Allocation<FilesystemStorage>> = None;

static mut EXTERNAL_STORAGE: Option<ExternalStorage> = None;
static mut EXTERNAL_FS_ALLOC: Option<Allocation<ExternalStorage>> = None;

static mut VOLATILE_STORAGE: Option<VolatileStorage> = None;
static mut VOLATILE_FS_ALLOC: Option<Allocation<VolatileStorage>> = None;

const_ram_storage!(InternalStorage, STORAGE_SIZE);
const_ram_storage!(ExternalStorage, STORAGE_SIZE);
const_ram_storage!(VolatileStorage, STORAGE_SIZE);

pub struct FilesystemStorage(PathBuf);

impl Storage for FilesystemStorage {
    const READ_SIZE: usize = 16;
    const WRITE_SIZE: usize = 16;
    const BLOCK_SIZE: usize = 512;

    const BLOCK_COUNT: usize = 128;
    const BLOCK_CYCLES: isize = -1;

    type CACHE_SIZE = U512;
    type LOOKAHEAD_SIZE = U8;

    fn read(&mut self, offset: usize, buffer: &mut [u8]) -> LfsResult<usize> {
        debug!("read: offset: {}, len: {}", offset, buffer.len());
        let mut file = File::open(&self.0).unwrap();
        file.seek(SeekFrom::Start(offset as _)).unwrap();
        let bytes_read = file.read(buffer).unwrap();
        assert!(bytes_read <= buffer.len());
        Ok(bytes_read as _)
    }

    fn write(&mut self, offset: usize, data: &[u8]) -> LfsResult<usize> {
        debug!("write: offset: {}, len: {}", offset, data.len());
        if offset + data.len() > STORAGE_SIZE {
            return Err(littlefs2::io::Error::NoSpace);
        }
        let mut file = OpenOptions::new().write(true).open(&self.0).unwrap();
        file.seek(SeekFrom::Start(offset as _)).unwrap();
        let bytes_written = file.write(data).unwrap();
        assert_eq!(bytes_written, data.len());
        file.flush().unwrap();
        Ok(bytes_written)
    }

    fn erase(&mut self, offset: usize, len: usize) -> LfsResult<usize> {
        debug!("erase: offset: {}, len: {}", offset, len);
        if offset + len > STORAGE_SIZE {
            return Err(littlefs2::io::Error::NoSpace);
        }
        let mut file = OpenOptions::new().write(true).open(&self.0).unwrap();
        file.seek(SeekFrom::Start(offset as _)).unwrap();
        let zero_block = [0xFFu8; Self::BLOCK_SIZE];
        for _ in 0..(len / Self::BLOCK_SIZE) {
            let bytes_written = file.write(&zero_block).unwrap();
            assert_eq!(bytes_written, Self::BLOCK_SIZE);
        }
        file.flush().unwrap();
        Ok(len)
    }
}

store!(
    FilesystemStore,
    Internal: FilesystemStorage,
    External: ExternalStorage,
    Volatile: VolatileStorage
);

impl Default for FilesystemStore {
    fn default() -> Self {
        Self { __: PhantomData }
    }
}

#[derive(Clone, Debug)]
pub struct Filesystem {
    internal: PathBuf,
    format: bool,
}

impl Filesystem {
    pub fn new(internal: impl Into<PathBuf>) -> Self {
        let internal = internal.into();
        let len = u64::try_from(STORAGE_SIZE).unwrap();
        let format = if let Ok(file) = File::open(&internal) {
            assert_eq!(file.metadata().unwrap().len(), len);
            false
        } else {
            let file = File::create(&internal).expect("failed to create storage file");
            file.set_len(len).expect("failed to set storage file len");
            true
        };
        Self { internal, format }
    }
}

impl StoreProvider for Filesystem {
    type Store = FilesystemStore;

    unsafe fn ifs() -> &'static mut FilesystemStorage {
        INTERNAL_FILESYSTEM_STORAGE
            .as_mut()
            .expect("ifs not initialized")
    }

    unsafe fn store() -> Self::Store {
        Self::Store { __: PhantomData }
    }

    unsafe fn reset(&self) {
        INTERNAL_FILESYSTEM_STORAGE.replace(FilesystemStorage(self.internal.clone()));
        INTERNAL_FILESYSTEM_FS_ALLOC.replace(littlefs2::fs::Filesystem::allocate());
        reset_external();
        reset_volatile();

        Self::store()
            .mount(
                INTERNAL_FILESYSTEM_FS_ALLOC.as_mut().unwrap(),
                INTERNAL_FILESYSTEM_STORAGE.as_mut().unwrap(),
                EXTERNAL_FS_ALLOC.as_mut().unwrap(),
                EXTERNAL_STORAGE.as_mut().unwrap(),
                VOLATILE_FS_ALLOC.as_mut().unwrap(),
                VOLATILE_STORAGE.as_mut().unwrap(),
                self.format,
            )
            .expect("failed to mount filesystem");
    }
}

store!(
    RamStore,
    Internal: InternalStorage,
    External: ExternalStorage,
    Volatile: VolatileStorage
);

#[derive(Copy, Clone, Debug, Default)]
pub struct Ram {}

impl StoreProvider for Ram {
    type Store = RamStore;

    unsafe fn ifs() -> &'static mut InternalStorage {
        INTERNAL_RAM_STORAGE.as_mut().expect("ifs not initialized")
    }

    unsafe fn store() -> Self::Store {
        Self::Store { __: PhantomData }
    }

    unsafe fn reset(&self) {
        INTERNAL_RAM_STORAGE.replace(InternalStorage::new());
        INTERNAL_RAM_FS_ALLOC.replace(littlefs2::fs::Filesystem::allocate());
        reset_external();
        reset_volatile();

        Self::store()
            .mount(
                INTERNAL_RAM_FS_ALLOC.as_mut().unwrap(),
                INTERNAL_RAM_STORAGE.as_mut().unwrap(),
                EXTERNAL_FS_ALLOC.as_mut().unwrap(),
                EXTERNAL_STORAGE.as_mut().unwrap(),
                VOLATILE_FS_ALLOC.as_mut().unwrap(),
                VOLATILE_STORAGE.as_mut().unwrap(),
                true,
            )
            .expect("failed to mount filesystem");
    }
}

unsafe fn reset_external() {
    EXTERNAL_STORAGE.replace(ExternalStorage::new());
    EXTERNAL_FS_ALLOC.replace(littlefs2::fs::Filesystem::allocate());
}

unsafe fn reset_volatile() {
    VOLATILE_STORAGE.replace(VolatileStorage::new());
    VOLATILE_FS_ALLOC.replace(littlefs2::fs::Filesystem::allocate());
}
