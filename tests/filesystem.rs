#![cfg(feature = "virt")]

use std::assert_eq;

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
    client::get(|client| {
        syscall!(client.write_file(
            location,
            PathBuf::from("foo"),
            Bytes::from_slice(b"foo").unwrap(),
            None
        ));
        syscall!(client.write_file(
            location,
            PathBuf::from("bar"),
            Bytes::from_slice(b"bar").unwrap(),
            None
        ));
        let first_entry = syscall!(client.read_dir_first(location, PathBuf::from(""), None))
            .entry
            .unwrap();
        assert_eq!(first_entry.file_name(), "bar");

        let next_entry = syscall!(client.read_dir_next()).entry.unwrap();
        assert_eq!(next_entry.file_name(), "foo");

        let first_data = syscall!(client.read_dir_files_first(location, PathBuf::from(""), None))
            .data
            .unwrap();
        assert_eq!(first_data, b"bar");
        let next_data = syscall!(client.read_dir_files_next()).data.unwrap();
        assert_eq!(next_data, b"foo");
    });
}

fn iterating_first(location: Location) {
    use littlefs2::path;
    client::get(|client| {
        let files = [
            path!("foo"),
            path!("bar"),
            path!("baz"),
            path!("foobar"),
            path!("foobaz"),
        ];

        let files_sorted_lfs = {
            let mut files = files;
            files.sort_by(|a, b| a.cmp_lfs(b));
            files
        };

        assert_eq!(
            files_sorted_lfs,
            [
                path!("bar"),
                path!("baz"),
                path!("foobar"),
                path!("foobaz"),
                path!("foo"),
            ]
        );

        let files_sorted_str = {
            let mut files = files;
            files.sort_by(|a, b| a.cmp_str(b));
            files
        };
        assert_eq!(
            files_sorted_str,
            [
                path!("bar"),
                path!("baz"),
                path!("foo"),
                path!("foobar"),
                path!("foobaz"),
            ]
        );

        for f in files {
            syscall!(client.write_file(
                location,
                PathBuf::from(f),
                Bytes::from_slice(f.as_ref().as_bytes()).unwrap(),
                None
            ));
        }

        let first_entry =
            syscall!(client.read_dir_first_alphabetical(location, PathBuf::from(""), None))
                .entry
                .unwrap();
        assert_eq!(first_entry.path(), files_sorted_lfs[0]);
        for f in &files_sorted_lfs[1..] {
            let entry = syscall!(client.read_dir_next()).entry.unwrap();
            assert_eq!(&entry.path(), f);
        }
        assert!(syscall!(client.read_dir_next()).entry.is_none());

        let first_entry = syscall!(client.read_dir_first_alphabetical(
            location,
            PathBuf::from(""),
            Some(PathBuf::from("fo"))
        ))
        .entry
        .unwrap();
        assert_eq!(first_entry.path(), path!("foobar"));

        for f in &(files_sorted_lfs[3..]) {
            let entry = syscall!(client.read_dir_next()).entry.unwrap();
            assert_eq!(&entry.path(), f);
        }
        assert!(syscall!(client.read_dir_next()).entry.is_none());
    });
}

fn iterating_files_and_dirs(location: Location) {
    use littlefs2::path;
    client::get(|client| {
        let files = [
            path!("foo"),
            path!("bar"),
            path!("baz"),
            path!("foobar"),
            path!("foobaz"),
        ];

        for f in files {
            syscall!(client.write_file(
                location,
                PathBuf::from(f),
                Bytes::from_slice(f.as_ref().as_bytes()).unwrap(),
                None
            ));
        }

        let directories = [
            path!("dir"),
            path!("foodir"),
            path!("bardir"),
            path!("bazdir"),
            path!("foobardir"),
            path!("foobazdir"),
        ];

        for d in directories {
            let mut file_path = PathBuf::from(d);
            file_path.push(path!("file"));

            syscall!(client.write_file(
                location,
                file_path.clone(),
                Bytes::from_slice(file_path.as_ref().as_bytes()).unwrap(),
                None
            ));
        }

        let all_entries: Vec<_> = files.into_iter().chain(directories).collect();
        let all_entries_sorted_str = {
            let mut all_entries = all_entries.clone();
            all_entries.sort_by(|a, b| a.cmp_str(b));
            all_entries
        };

        assert_eq!(
            all_entries_sorted_str,
            [
                path!("bar"),
                path!("bardir"),
                path!("baz"),
                path!("bazdir"),
                path!("dir"),
                path!("foo"),
                path!("foobar"),
                path!("foobardir"),
                path!("foobaz"),
                path!("foobazdir"),
                path!("foodir"),
            ]
        );

        let all_entries_sorted_lfs = {
            let mut all_entries = all_entries.clone();
            all_entries.sort_by(|a, b| a.cmp_lfs(b));
            all_entries
        };

        assert_eq!(
            all_entries_sorted_lfs,
            [
                path!("bardir"),
                path!("bar"),
                path!("bazdir"),
                path!("baz"),
                path!("dir"),
                path!("foobardir"),
                path!("foobar"),
                path!("foobazdir"),
                path!("foobaz"),
                path!("foodir"),
                path!("foo"),
            ]
        );

        let first_entry =
            syscall!(client.read_dir_first_alphabetical(location, PathBuf::from(""), None))
                .entry
                .unwrap();
        assert_eq!(first_entry.path(), all_entries_sorted_lfs[0]);
        for f in &all_entries_sorted_lfs[1..] {
            let entry = syscall!(client.read_dir_next()).entry.unwrap();
            assert_eq!(&entry.path(), f);
        }
        assert!(syscall!(client.read_dir_next()).entry.is_none());

        let first_entry = syscall!(client.read_dir_first_alphabetical(
            location,
            PathBuf::from(""),
            Some(PathBuf::from("dir"))
        ))
        .entry
        .unwrap();
        assert_eq!(first_entry.path(), all_entries_sorted_lfs[4]);
        for f in &all_entries_sorted_lfs[5..] {
            let entry = syscall!(client.read_dir_next()).entry.unwrap();
            assert_eq!(&entry.path(), f);
        }
        assert!(syscall!(client.read_dir_next()).entry.is_none());
    });
}

#[test]
fn iterating_internal() {
    iterating(Location::Internal);
    iterating_first(Location::Internal);
    iterating_files_and_dirs(Location::Internal);
}
#[test]
fn iterating_external() {
    iterating(Location::External);
    iterating_first(Location::External);
    iterating_files_and_dirs(Location::External);
}
#[test]
fn iterating_volatile() {
    iterating(Location::Volatile);
    iterating_first(Location::Volatile);
    iterating_files_and_dirs(Location::Volatile);
}
