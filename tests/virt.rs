#![cfg(feature = "virt")]

use std::time::Duration;
use trussed::{
    client::{FilesystemClient as _, ManagementClient as _},
    syscall,
    types::{Bytes, Location, PathBuf},
    virt,
};

fn run_test(data: u8) {
    let location = Location::Internal;
    let path = PathBuf::from("test");
    let mut write_data = Bytes::new();
    write_data.push(data).unwrap();
    virt::with_ram_client("test", |mut client| {
        // ensure that the filesystem is empty
        let read_dir = syscall!(client.read_dir_first(location, PathBuf::from(""), None)).entry;
        assert!(
            read_dir.is_none(),
            "Filesystem not empty: {:?}",
            read_dir.unwrap()
        );

        // ensure that no other client is messing with our filesystem
        while syscall!(client.uptime()).uptime < Duration::from_secs(1) {
            syscall!(client.write_file(location, path.clone(), write_data.clone()));
            let read_data = syscall!(client.read_file(location, path.clone())).data;
            assert_eq!(write_data, read_data);
        }
    })
}

#[test]
fn test1() {
    run_test(1);
}

#[test]
fn test2() {
    run_test(2);
}
