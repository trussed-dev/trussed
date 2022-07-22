#![cfg(feature = "virt")]

use trussed::virt::{self, Client, Ram};

pub fn get<R, F: FnOnce(&mut Client<Ram>) -> R>(test: F) -> R {
    virt::with_ram_client("test", |mut client| test(&mut client))
}
