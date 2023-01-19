#![cfg(feature = "virt")]

use trussed::{
    client::{CryptoClient, FilesystemClient},
    error::Error,
    syscall, try_syscall,
    types::{Location, Mechanism, PathBuf, StorageAttributes},
};

mod client;

#[test]
fn escape_namespace_parent() {
    client::get(|client| {
        let key = syscall!(client.generate_key(Mechanism::P256, StorageAttributes::new())).key;

        // first approach: directly escape namespace
        let mut path = PathBuf::from("..");
        path.push(&PathBuf::from("sec"));
        path.push(&PathBuf::from(key.hex().as_slice()));
        assert_eq!(
            try_syscall!(client.read_file(Location::Volatile, path)),
            Err(Error::InvalidPath),
        );

        // second approach: start with subdir, then escape namespace
        let mut path = PathBuf::from("foobar/../..");
        path.push(&PathBuf::from("sec"));
        path.push(&PathBuf::from(key.hex().as_slice()));
        assert_eq!(
            try_syscall!(client.read_file(Location::Volatile, path)),
            Err(Error::InvalidPath),
        );

        // false positive: does not escape namespace but still forbidden
        let mut path = PathBuf::from("foobar/..");
        path.push(&PathBuf::from("sec"));
        path.push(&PathBuf::from(key.hex().as_slice()));
        assert_eq!(
            try_syscall!(client.read_file(Location::Volatile, path)),
            Err(Error::InvalidPath),
        );
    })
}

#[test]
fn escape_namespace_root() {
    client::get(|client| {
        let key = syscall!(client.generate_key(Mechanism::P256, StorageAttributes::new())).key;
        let mut path = PathBuf::from("/test");
        path.push(&PathBuf::from("sec"));
        path.push(&PathBuf::from(key.hex().as_slice()));
        assert!(try_syscall!(client.read_file(Location::Volatile, path)).is_err());
    })
}
