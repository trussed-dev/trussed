use littlefs2::const_ram_storage;
use trussed::types::{LfsResult, LfsStorage};

const_ram_storage!(InternalStorage, 8192);
// const_ram_storage!(InternalStorage, 16384);
const_ram_storage!(ExternalStorage, 8192);
const_ram_storage!(VolatileStorage, 8192);

trussed::store!(
    Store,
    Internal: InternalStorage,
    External: ExternalStorage,
    Volatile: VolatileStorage
);

#[allow(dead_code)]
pub fn get<R>(test: impl FnOnce(&mut Store) -> R) -> R {
    let mut store = init_store();
    test(&mut store)
}

#[allow(dead_code)]
fn init_store() -> Store {
    Store::format(
        InternalStorage::new(),
        ExternalStorage::new(),
        VolatileStorage::new(),
    )
}
