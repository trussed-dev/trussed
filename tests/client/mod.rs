#![cfg(feature = "virt")]

use trussed::virt::{self, Client};

pub fn get<R, F: FnOnce(&mut Client) -> R>(test: F) -> R {
    virt::with_ram_client("test", |mut client| test(&mut client))
}
