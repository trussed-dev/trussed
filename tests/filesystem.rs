#![cfg(feature = "virt")]

use trussed::{
    client::{CryptoClient, FilesystemClient},
    error::Error,
    syscall, try_syscall,
    types::{Bytes, Location, Mechanism, PathBuf, StorageAttributes},
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

fn iterating(location: Location) {
    for count in [0, 1, 10, 20] {
        let files: Vec<_> = (0..count).map(|i| format!("file{i:04}")).collect();
        client::get(|client| {
            // Setup filesystem
            for file in &files {
                syscall!(client.write_file(
                    location,
                    PathBuf::from(&**file),
                    Bytes::from_slice(file.as_bytes()).unwrap(),
                    None
                ));
            }

            // Iteration over entries (filenames)
            for i in 0..count {
                if let Some(f) = files.get(i) {
                    let entry = syscall!(client.read_dir_nth(location, PathBuf::new(), i))
                        .entry
                        .unwrap();
                    assert_eq!(entry.path().as_ref(), f);
                }

                for j in i + 1..count {
                    let entry = syscall!(client.read_dir_next()).entry.unwrap();
                    assert_eq!(entry.path().as_ref(), &files[j]);
                }
                assert!(syscall!(client.read_dir_next()).entry.is_none());
            }

            for i in 0..count {
                if let Some(f) = files.get(i) {
                    let data =
                        syscall!(client.read_dir_files_nth(location, PathBuf::new(), i, None))
                            .data
                            .unwrap();
                    assert_eq!(data, f.as_bytes());
                }

                for j in i + 1..count {
                    let data = syscall!(client.read_dir_files_next()).data.unwrap();
                    assert_eq!(data, files[j].as_bytes());
                }
                assert!(syscall!(client.read_dir_files_next()).data.is_none());
            }
        });
    }
}

#[test]
fn iterating_internal() {
    iterating(Location::Internal);
}
#[test]
fn iterating_external() {
    iterating(Location::External);
}
#[test]
fn iterating_volatile() {
    iterating(Location::Volatile);
}
