#![cfg(feature = "virt")]

use trussed::virt::{self, Client, RamStore};

pub fn get<R, F: FnOnce(&mut Client<RamStore>) -> R>(test: F) -> R {
    virt::with_ram_client("test", |mut client| test(&mut client))
}
