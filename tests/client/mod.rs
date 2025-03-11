#![cfg(feature = "virt")]

use trussed::virt::{self, Client, StoreConfig};

pub fn get<R, F: FnOnce(&mut Client) -> R>(test: F) -> R {
    virt::with_client(StoreConfig::ram(), "test", |mut client| test(&mut client))
}
