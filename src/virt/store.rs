use std::{
    fs::{File, OpenOptions},
    io::{Read as _, Seek as _, SeekFrom, Write as _},
    path::PathBuf,
};

use littlefs2::{const_ram_storage, driver::Storage, io::Result, object_safe::DynStorageAlloc};
use littlefs2_core::DynFilesystem;

use crate::store;

pub struct StoreConfig<'a> {
    pub internal: StorageConfig<'a>,
    pub external: StorageConfig<'a>,
    pub volatile: StorageConfig<'a>,
}

const BLOCK_SIZE: usize = 512;

impl StoreConfig<'_> {
    pub fn ram() -> Self {
        Self {
            internal: StorageConfig::ram(),
            external: StorageConfig::ram(),
            volatile: StorageConfig::ram(),
        }
    }

    pub fn with_store<F, T>(&mut self, f: F) -> T
    where
        F: FnOnce(Store) -> T,
    {
        self.internal
            .with_fs(|internal| {
                self.external
                    .with_fs(|external| {
                        self.volatile
                            .with_fs(|volatile| {
                                let store = Store {
                                    internal,
                                    external,
                                    volatile,
                                };
                                f(store)
                            })
                            .expect("failed to mount volatile storage")
                    })
                    .expect("failed to mount external storage")
            })
            .expect("failed to mount internal storage")
    }
}

pub struct StorageConfig<'a> {
    pub storage: Box<dyn DynStorageAlloc + 'a>,
    pub format: bool,
}

impl StorageConfig<'_> {
    pub fn ram() -> Self {
        Self {
            storage: Box::new(RamStorage::new()),
            format: true,
        }
    }

    pub fn filesystem(path: PathBuf) -> Self {
        let len = u64::try_from(STORAGE_SIZE).unwrap();
        let format = if let Ok(file) = File::open(&path) {
            assert_eq!(file.metadata().unwrap().len(), len);
            false
        } else {
            let file = File::create(&path).expect("failed to create storage file");
            file.set_len(len).expect("failed to set storage file len");
            true
        };
        Self {
            storage: Box::new(FilesystemStorage(path)),
            format,
        }
    }

    pub fn with_fs<F, T>(&mut self, f: F) -> Result<T>
    where
        F: FnOnce(&dyn DynFilesystem) -> T,
    {
        if self.format {
            self.storage.format()?;
        }
        self.storage.mount_and_then_once(|fs| Ok(f(fs)))
    }
}

const STORAGE_SIZE: usize = 512 * 128;

const_ram_storage!(RamStorage, STORAGE_SIZE);

struct FilesystemStorage(PathBuf);

impl Storage for FilesystemStorage {
    fn read_size(&self) -> usize {
        16
    }
    fn write_size(&self) -> usize {
        16
    }
    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }
    fn block_count(&self) -> usize {
        128
    }
    fn block_cycles(&self) -> isize {
        -1
    }

    fn cache_size(&self) -> usize {
        512
    }

    fn lookahead_size(&self) -> usize {
        8
    }

    type CACHE_BUFFER = [u8; 512];
    type LOOKAHEAD_BUFFER = [u8; 64];

    fn read(&mut self, offset: usize, buffer: &mut [u8]) -> Result<usize> {
        debug!("read: offset: {}, len: {}", offset, buffer.len());
        let mut file = File::open(&self.0).unwrap();
        file.seek(SeekFrom::Start(offset as _)).unwrap();
        let bytes_read = file.read(buffer).unwrap();
        assert!(bytes_read <= buffer.len());
        Ok(bytes_read as _)
    }

    fn write(&mut self, offset: usize, data: &[u8]) -> Result<usize> {
        debug!("write: offset: {}, len: {}", offset, data.len());
        if offset + data.len() > STORAGE_SIZE {
            return Err(littlefs2::io::Error::NO_SPACE);
        }
        let mut file = OpenOptions::new().write(true).open(&self.0).unwrap();
        file.seek(SeekFrom::Start(offset as _)).unwrap();
        let bytes_written = file.write(data).unwrap();
        assert_eq!(bytes_written, data.len());
        file.flush().unwrap();
        Ok(bytes_written)
    }

    fn erase(&mut self, offset: usize, len: usize) -> Result<usize> {
        debug!("erase: offset: {}, len: {}", offset, len);
        if offset + len > STORAGE_SIZE {
            return Err(littlefs2::io::Error::NO_SPACE);
        }
        let mut file = OpenOptions::new().write(true).open(&self.0).unwrap();
        file.seek(SeekFrom::Start(offset as _)).unwrap();
        let zero_block = [0xFFu8; BLOCK_SIZE];
        for _ in 0..(len / BLOCK_SIZE) {
            let bytes_written = file.write(&zero_block).unwrap();
            assert_eq!(bytes_written, BLOCK_SIZE);
        }
        file.flush().unwrap();
        Ok(len)
    }
}

#[derive(Clone, Copy)]
pub struct Store<'a> {
    pub internal: &'a dyn DynFilesystem,
    pub external: &'a dyn DynFilesystem,
    pub volatile: &'a dyn DynFilesystem,
}

impl store::Store for Store<'_> {
    fn ifs(&self) -> &dyn DynFilesystem {
        self.internal
    }

    fn efs(&self) -> &dyn DynFilesystem {
        self.external
    }

    fn vfs(&self) -> &dyn DynFilesystem {
        self.volatile
    }
}
