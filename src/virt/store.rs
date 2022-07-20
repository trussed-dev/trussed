use std::marker::PhantomData;

use littlefs2::const_ram_storage;

use crate::{store, types::{LfsResult, LfsStorage}};

pub trait Reset {
    fn reset(&self);
}

const_ram_storage!(InternalStorage, 16384);
const_ram_storage!(ExternalStorage, 16384);
const_ram_storage!(VolatileStorage, 16384);

// TODO: Add FileStore

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
