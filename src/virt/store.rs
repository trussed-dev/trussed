use std::{
    io::{Read as _, Seek as _, SeekFrom, Write as _},
    fs::{File, OpenOptions},
    marker::PhantomData,
    path::{Path, PathBuf},
};

use generic_array::typenum::{U16, U512};
use littlefs2::{const_ram_storage, driver::Storage};

use crate::{store, store::{Fs, Store}, types::{LfsResult, LfsStorage}};

pub trait Reset {
    fn reset(&self);
}

const STORAGE_SIZE: usize = 1024 * 16;

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
    type LOOKAHEADWORDS_SIZE = U16;
    // TODO: This can't actually be changed currently
    // type FILENAME_MAX_PLUS_ONE = U256;
    // type PATH_MAX_PLUS_ONE = U256;
    // const FILEBYTES_MAX: usize = littlefs2::ll::LFS_FILE_MAX as _;
    // TODO: This can't actually be changed currently
    // type ATTRBYTES_MAX = U1022;

    fn read(&self, offset: usize, buffer: &mut [u8]) -> LfsResult<usize> {
        let mut file = File::open(&self.0).unwrap();
        file.seek(SeekFrom::Start(offset as _)).unwrap();
        let bytes_read = file.read(buffer).unwrap();
        assert_eq!(bytes_read, buffer.len());
        Ok(bytes_read as _)
    }

    fn write(&mut self, offset: usize, data: &[u8]) -> LfsResult<usize> {
        let mut file = OpenOptions::new()
            .write(true)
            .open(&self.0)
            .unwrap();
        file.seek(SeekFrom::Start(offset as _)).unwrap();
        let bytes_written = file.write(data).unwrap();
        assert_eq!(bytes_written, data.len());
        file.flush().unwrap();
        Ok(bytes_written)
    }

    fn erase(&mut self, offset: usize, len: usize) -> LfsResult<usize> {
        let mut file = OpenOptions::new()
            .write(true)
            .open(&self.0)
            .unwrap();
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

store!(FilesystemStoreImpl,
  Internal: FilesystemStorage,
  External: ExternalStorage,
  Volatile: VolatileStorage
);

impl Default for FilesystemStoreImpl {
    fn default() -> Self {
        Self {
            __: PhantomData,
        }
    }
}

#[derive(Clone, Copy)]
pub struct FilesystemStore<'a> {
    inner: FilesystemStoreImpl,
    internal: &'a Path,
    format: bool,
}

impl<'a> FilesystemStore<'a> {
    pub fn new(internal: &'a Path) -> Self {
        let len = u64::try_from(STORAGE_SIZE).unwrap();
        let format = if let Ok(file) = File::open(internal) {
            assert_eq!(file.metadata().unwrap().len(), len);
            false
        } else {
            let file = File::create(internal).expect("failed to create storage file");
            file.set_len(len).expect("failed to set storage file len");
            true
        };
        Self {
            inner: Default::default(),
            internal,
            format,
        }
    }
}

unsafe impl<'a> Store for FilesystemStore<'a> {
    type I = <FilesystemStoreImpl as Store>::I;
    type E = <FilesystemStoreImpl as Store>::E;
    type V = <FilesystemStoreImpl as Store>::V;

    fn ifs(self) -> &'static Fs<Self::I> {
        self.inner.ifs()
    }

    fn efs(self) -> &'static Fs<Self::E> {
        self.inner.efs()
    }

    fn vfs(self) -> &'static Fs<Self::V> {
        self.inner.vfs()
    }
}

impl<'a> Reset for FilesystemStore<'a> {
    fn reset(&self) {
        let ifs = FilesystemStorage(self.internal.to_owned());
        let efs = ExternalStorage::default();
        let vfs = VolatileStorage::default();
        let (ifs_alloc, ifs_storage, efs_alloc, efs_storage, vfs_alloc, vfs_storage) =
            FilesystemStoreImpl::allocate(ifs, efs, vfs);
        let format = self.format;
        self.inner
            .mount(ifs_alloc, ifs_storage, efs_alloc, efs_storage, vfs_alloc, vfs_storage, format)
            .expect("failed to mount filesystem");
    }
}

store!(RamStore,
   Internal: InternalStorage,
   External: ExternalStorage,
   Volatile: VolatileStorage
);

impl Default for RamStore {
    fn default() -> Self {
        Self {
            __: PhantomData,
        }
    }
}

impl Reset for RamStore {
    fn reset(&self) {
        let ifs = InternalStorage::default();
        let efs = ExternalStorage::default();
        let vfs = VolatileStorage::default();
        let (ifs_alloc, ifs_storage, efs_alloc, efs_storage, vfs_alloc, vfs_storage) =
            Self::allocate(ifs, efs, vfs);
        self.mount(ifs_alloc, ifs_storage, efs_alloc, efs_storage, vfs_alloc, vfs_storage, true)
            .expect("failed to mount filesystem");
    }
}
