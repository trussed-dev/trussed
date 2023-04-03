use crate::{
    error::{Error, Result},
    // service::ReadDirState,
    store::{self, Store},
    types::{LfsStorage, Location, Message, OpenSeekFrom, UserAttribute},
    Bytes,
};

#[derive(Clone)]
pub struct ReadDirState {
    real_dir: PathBuf,
    location: Location,
    last: usize,
}

#[derive(Clone)]
pub struct ReadDirFilesState {
    real_dir: PathBuf,
    last: usize,
    location: Location,
    user_attribute: Option<UserAttribute>,
}

use littlefs2::{
    fs::{DirEntry, Metadata},
    path::{Path, PathBuf},
};

use super::Fs;
pub type ClientId = PathBuf;

pub struct ClientFilestore<S>
where
    S: Store,
{
    client_id: ClientId,
    store: S,
}

impl<S: Store> ClientFilestore<S> {
    pub fn new(client_id: ClientId, store: S) -> Self {
        Self { client_id, store }
    }

    /// Client files are store below `/<client_id>/dat/`.
    pub fn actual_path(&self, client_path: &PathBuf) -> Result<PathBuf> {
        // Clients must not escape their namespace
        if client_path.as_ref().contains("..") {
            return Err(Error::InvalidPath);
        }

        let mut path = PathBuf::new();
        path.push(&self.client_id);
        path.push(&PathBuf::from("dat"));
        path.push(client_path);
        Ok(path)
    }

    /// Partially written client files are store below `/<client_id>/part/`.
    pub fn chunks_path(&self, client_path: &PathBuf) -> Result<PathBuf> {
        // Clients must not escape their namespace
        if client_path.as_ref().contains("..") {
            return Err(Error::InvalidPath);
        }

        let mut path = PathBuf::new();
        path.push(&self.client_id);
        path.push(&PathBuf::from("part"));
        path.push(client_path);
        Ok(path)
    }

    // TODO: this is waaay too fiddly, need an approach
    // that totally excludes off-by-N type errors.
    pub fn client_path(&self, actual_path: &Path) -> PathBuf {
        let bytes = actual_path.as_ref().as_bytes();
        let absolute = bytes[0] == b'/';
        let offset = usize::from(absolute);

        // we know `client_id` here, could use its length
        let end_of_namespace = bytes[1..]
            .iter()
            .position(|&x| x == b'/')
            // oh oh oh
            .unwrap();
        let dat_offset = "/dat/".len();
        PathBuf::from(&bytes[end_of_namespace + 1 + offset + dat_offset..])
    }
}

pub trait Filestore {
    fn read<const N: usize>(&mut self, path: &PathBuf, location: Location) -> Result<Bytes<N>>;
    fn read_chunk<const N: usize>(
        &mut self,
        path: &PathBuf,
        location: Location,
        pos: OpenSeekFrom,
    ) -> Result<(Bytes<N>, usize)>;
    fn write(&mut self, path: &PathBuf, location: Location, data: &[u8]) -> Result<()>;
    fn start_chunked_write(
        &mut self,
        path: &PathBuf,
        location: Location,
        data: &[u8],
    ) -> Result<()>;
    fn write_chunk(
        &mut self,
        path: &PathBuf,
        location: Location,
        data: &[u8],
        pos: OpenSeekFrom,
    ) -> Result<()>;
    fn flush_chunks(&mut self, path: &PathBuf, location: Location) -> Result<()>;
    fn abort_chunked_write(&mut self, path: &PathBuf, location: Location) -> bool;
    fn exists(&mut self, path: &PathBuf, location: Location) -> bool;
    fn metadata(&mut self, path: &PathBuf, location: Location) -> Result<Option<Metadata>>;
    fn remove_file(&mut self, path: &PathBuf, location: Location) -> Result<()>;
    fn remove_dir(&mut self, path: &PathBuf, location: Location) -> Result<()>;
    fn remove_dir_all(&mut self, path: &PathBuf, location: Location) -> Result<usize>;
    fn locate_file(
        &mut self,
        location: Location,
        underneath: Option<PathBuf>,
        filename: PathBuf,
    ) -> Result<Option<PathBuf>>;

    /// Iterate over entries of a directory (both file and directory entries).
    ///
    /// This function is modeled after `std::fs::read_dir`, within the limitations of our setup.
    ///
    /// The `not_before` parameter is an optimization for users to locate a specifically named
    /// file in one call - if the filename exists (e.g., `my-data.txt`), then return it directly.
    ///
    /// In case an entry was found, the returned option also contains state, so the expected
    /// call to `read_dir_next` can resume operation.
    fn read_dir_first(
        &mut self,
        dir: &PathBuf,
        location: Location,
        not_before: Option<&PathBuf>,
    ) -> Result<Option<(DirEntry, ReadDirState)>>;

    /// Continue iterating over entries of a directory.
    ///
    /// Return the entry just after the previous one. If it exists, also return state for the
    /// following call.
    fn read_dir_next(&mut self, state: ReadDirState) -> Result<Option<(DirEntry, ReadDirState)>>;

    /// Iterate over contents of files inside a directory.
    ///
    /// This has no equivalent in `std::fs`, it is an optimization to avoid duplicate
    /// calls and a more complicated state machine (interspersing read_dir_first/next calls
    /// with some sort of "fetch data").
    ///
    /// Additionally, files may optionally be filtered via attributes.
    fn read_dir_files_first(
        &mut self,
        clients_dir: &PathBuf,
        location: Location,
        user_attribute: Option<UserAttribute>,
    ) -> Result<Option<(Option<Message>, ReadDirFilesState)>>;

    /// Continuation of `read_dir_files_first`.
    fn read_dir_files_next(
        &mut self,
        state: ReadDirFilesState,
    ) -> Result<Option<(Option<Message>, ReadDirFilesState)>>;
}

/// Generic implementation allowing the use of any filesystem.
impl<S: Store> ClientFilestore<S> {
    fn read_dir_first_impl<F: LfsStorage + 'static>(
        &mut self,
        clients_dir: &PathBuf,
        location: Location,
        not_before: Option<&PathBuf>,
        fs: &'static Fs<F>,
    ) -> Result<Option<(DirEntry, ReadDirState)>> {
        let dir = self.actual_path(clients_dir)?;

        Ok(fs
            .read_dir_and_then(&dir, |it| {
                // this is an iterator with Item = (usize, Result<DirEntry>)
                it.enumerate()
                    // skip over `.` and `..`
                    .skip(2)
                    // todo: try ?-ing out of this (the API matches std::fs, where read/write errors
                    // can occur during operation)
                    //
                    // Option<usize, Result<DirEntry>> -> ??
                    .map(|(i, entry)| (i, entry.unwrap()))
                    // if there is a "not_before" entry, skip all entries before it.
                    .find(|(_, entry)| {
                        if let Some(not_before) = not_before {
                            entry.file_name() == not_before.as_ref()
                        } else {
                            true
                        }
                    })
                    // if there is an entry, construct the state that needs storing out of it,
                    // remove the prefix from the entry's path to not leak implementation details to
                    // the client, and return both the entry and the state
                    .map(|(i, mut entry)| {
                        let read_dir_state = ReadDirState {
                            real_dir: dir.clone(),
                            last: i,
                            location,
                        };
                        let entry_client_path = self.client_path(entry.path());
                        // trace_now!("converted path {} to client path {}", &entry.path(), &entry_client_path);
                        // This is a hidden function which allows us to modify `entry.path`.
                        // In regular use, `DirEntry` is not supposed to be constructable by the user
                        // (only by querying the filesystem), which is why the function is both
                        // hidden and tagged "unsafe" to discourage use. Our use case here is precisely
                        // the reason for its existence :)
                        *unsafe { entry.path_buf_mut() } = entry_client_path;
                        (entry, read_dir_state)

                        // the `ok_or` dummy error followed by the `ok` in the next line is because
                        // `read_dir_and_then` wants to see Results (although we naturally have an Option
                        // at this point)
                    })
                    .ok_or(littlefs2::io::Error::Io)
            })
            .ok())
    }
    fn read_dir_next_impl<F: LfsStorage + 'static>(
        &mut self,
        state: ReadDirState,
        fs: &'static Fs<F>,
    ) -> Result<Option<(DirEntry, ReadDirState)>> {
        let ReadDirState {
            real_dir,
            last,
            location,
        } = state;

        // all we want to do here is skip just past the previously found entry
        // in the directory iterator, then return it (plus state to continue on next call)
        Ok(fs
            .read_dir_and_then(&real_dir, |it| {
                // skip over previous
                it.enumerate()
                    .nth(last + 1)
                    // entry is still a Result :/ (see question in `read_dir_first`)
                    .map(|(i, entry)| (i, entry.unwrap()))
                    // convert Option into Result, again because `read_dir_and_then` expects this
                    .map(|(i, mut entry)| {
                        let read_dir_state = ReadDirState {
                            real_dir: real_dir.clone(),
                            last: i,
                            location,
                        };

                        let entry_client_path = self.client_path(entry.path());
                        *unsafe { entry.path_buf_mut() } = entry_client_path;

                        (entry, read_dir_state)
                    })
                    .ok_or(littlefs2::io::Error::Io)
            })
            .ok())
    }
    fn read_dir_files_first_impl<F: LfsStorage + 'static>(
        &mut self,
        clients_dir: &PathBuf,
        location: Location,
        user_attribute: Option<UserAttribute>,
        fs: &'static Fs<F>,
    ) -> Result<Option<(Option<Message>, ReadDirFilesState)>> {
        let dir = self.actual_path(clients_dir)?;

        Ok(fs
            .read_dir_and_then(&dir, |it| {
                // this is an iterator with Item = (usize, Result<DirEntry>)
                it.enumerate()
                    // todo: try ?-ing out of this (the API matches std::fs, where read/write errors
                    // can occur during operation)
                    //
                    // Option<usize, Result<DirEntry>> -> ??
                    .map(|(i, entry)| (i, entry.unwrap()))
                    // skip over directories (including `.` and `..`)
                    .filter(|(_, entry)| entry.file_type().is_file())
                    // take first entry that meets requirements
                    .find(|(_, entry)| {
                        if let Some(user_attribute) = user_attribute.as_ref() {
                            let mut path = dir.clone();
                            path.push(entry.file_name());
                            let attribute = fs
                                .attribute(&path, crate::config::USER_ATTRIBUTE_NUMBER)
                                .unwrap();

                            if let Some(attribute) = attribute {
                                user_attribute == attribute.data()
                            } else {
                                false
                            }
                        } else {
                            true
                        }
                    })
                    // if there is an entry, construct the state that needs storing out of it,
                    // and return the file's contents.
                    // the client, and return both the entry and the state
                    .map(|(i, entry)| {
                        let read_dir_files_state = ReadDirFilesState {
                            real_dir: dir.clone(),
                            last: i,
                            location,
                            user_attribute,
                        };
                        // The semantics is that for a non-existent file, we return None (not an error)
                        let data = store::read(self.store, location, entry.path()).ok();
                        (data, read_dir_files_state)

                        // the `ok_or` dummy error followed by the `ok` in the next line is because
                        // `read_dir_and_then` wants to see Results (although we naturally have an Option
                        // at this point)
                    })
                    .ok_or(littlefs2::io::Error::Io)
            })
            .ok())
    }

    fn read_dir_files_next_impl<F: LfsStorage + 'static>(
        &mut self,
        state: ReadDirFilesState,
        fs: &'static Fs<F>,
    ) -> Result<Option<(Option<Message>, ReadDirFilesState)>> {
        let ReadDirFilesState {
            real_dir,
            last,
            location,
            user_attribute,
        } = state;

        // all we want to do here is skip just past the previously found entry
        // in the directory iterator, then return it (plus state to continue on next call)
        Ok(fs
            .read_dir_and_then(&real_dir, |it| {
                // skip over previous
                it.enumerate()
                    .skip(last + 1)
                    // entry is still a Result :/ (see question in `read_dir_first`)
                    .map(|(i, entry)| (i, entry.unwrap()))
                    // skip over directories (including `.` and `..`)
                    .filter(|(_, entry)| entry.file_type().is_file())
                    // take first entry that meets requirements
                    .find(|(_, entry)| {
                        if let Some(user_attribute) = user_attribute.as_ref() {
                            let mut path = real_dir.clone();
                            path.push(entry.file_name());
                            let attribute = fs
                                .attribute(&path, crate::config::USER_ATTRIBUTE_NUMBER)
                                .unwrap();
                            if let Some(attribute) = attribute {
                                user_attribute == attribute.data()
                            } else {
                                false
                            }
                        } else {
                            true
                        }
                    })
                    .map(|(i, entry)| {
                        let read_dir_files_state = ReadDirFilesState {
                            real_dir: real_dir.clone(),
                            last: i,
                            location,
                            user_attribute,
                        };
                        // The semantics is that for a non-existent file, we return None (not an error)
                        let data = store::read(self.store, location, entry.path()).ok();
                        (data, read_dir_files_state)
                    })
                    // convert Option into Result, again because `read_dir_and_then` expects this
                    .ok_or(littlefs2::io::Error::Io)
            })
            .ok())
    }
}

impl<S: Store> Filestore for ClientFilestore<S> {
    fn read<const N: usize>(&mut self, path: &PathBuf, location: Location) -> Result<Bytes<N>> {
        let path = self.actual_path(path)?;

        store::read(self.store, location, &path)
    }
    fn read_chunk<const N: usize>(
        &mut self,
        path: &PathBuf,
        location: Location,
        pos: OpenSeekFrom,
    ) -> Result<(Bytes<N>, usize)> {
        let path = self.actual_path(path)?;

        store::read_chunk(self.store, location, &path, pos)
    }

    fn write(&mut self, path: &PathBuf, location: Location, data: &[u8]) -> Result<()> {
        let path = self.actual_path(path)?;
        store::store(self.store, location, &path, data)
    }

    fn start_chunked_write(
        &mut self,
        path: &PathBuf,
        location: Location,
        data: &[u8],
    ) -> Result<()> {
        let path = self.chunks_path(path)?;
        store::store(self.store, location, &path, data)
    }

    fn write_chunk(
        &mut self,
        path: &PathBuf,
        location: Location,
        data: &[u8],
        pos: OpenSeekFrom,
    ) -> Result<()> {
        let path = self.chunks_path(path)?;
        store::write_chunk(self.store, location, &path, data, pos)
    }

    fn abort_chunked_write(&mut self, path: &PathBuf, location: Location) -> bool {
        let Ok(path) = self.chunks_path(path) else {
            return false;
        };
        store::delete(self.store, location, &path)
    }

    fn flush_chunks(&mut self, path: &PathBuf, location: Location) -> Result<()> {
        let chunk_path = self.chunks_path(path)?;
        let client_path = self.actual_path(path)?;
        store::rename(self.store, location, &chunk_path, &client_path)
    }

    fn exists(&mut self, path: &PathBuf, location: Location) -> bool {
        if let Ok(path) = self.actual_path(path) {
            store::exists(self.store, location, &path)
        } else {
            false
        }
    }
    fn metadata(&mut self, path: &PathBuf, location: Location) -> Result<Option<Metadata>> {
        let path = self.actual_path(path)?;
        store::metadata(self.store, location, &path)
    }

    fn remove_file(&mut self, path: &PathBuf, location: Location) -> Result<()> {
        let path = self.actual_path(path)?;

        match store::delete(self.store, location, &path) {
            true => Ok(()),
            false => Err(Error::InternalError),
        }
    }

    fn remove_dir(&mut self, path: &PathBuf, location: Location) -> Result<()> {
        let path = self.actual_path(path)?;

        match store::delete(self.store, location, &path) {
            true => Ok(()),
            false => Err(Error::InternalError),
        }
    }

    fn remove_dir_all(&mut self, path: &PathBuf, location: Location) -> Result<usize> {
        let path = self.actual_path(path)?;

        store::remove_dir_all_where(self.store, location, &path, |_| true)
            .map_err(|_| Error::InternalError)
    }

    fn read_dir_first(
        &mut self,
        clients_dir: &PathBuf,
        location: Location,
        not_before: Option<&PathBuf>,
    ) -> Result<Option<(DirEntry, ReadDirState)>> {
        match location {
            Location::Internal => {
                self.read_dir_first_impl(clients_dir, location, not_before, self.store.ifs())
            }
            Location::External => {
                self.read_dir_first_impl(clients_dir, location, not_before, self.store.efs())
            }
            Location::Volatile => {
                self.read_dir_first_impl(clients_dir, location, not_before, self.store.vfs())
            }
        }
    }

    fn read_dir_next(&mut self, state: ReadDirState) -> Result<Option<(DirEntry, ReadDirState)>> {
        match state.location {
            Location::Internal => self.read_dir_next_impl(state, self.store.ifs()),
            Location::External => self.read_dir_next_impl(state, self.store.efs()),
            Location::Volatile => self.read_dir_next_impl(state, self.store.vfs()),
        }
    }

    fn read_dir_files_first(
        &mut self,
        clients_dir: &PathBuf,
        location: Location,
        user_attribute: Option<UserAttribute>,
    ) -> Result<Option<(Option<Message>, ReadDirFilesState)>> {
        match location {
            Location::Internal => self.read_dir_files_first_impl(
                clients_dir,
                location,
                user_attribute,
                self.store.ifs(),
            ),
            Location::External => self.read_dir_files_first_impl(
                clients_dir,
                location,
                user_attribute,
                self.store.efs(),
            ),
            Location::Volatile => self.read_dir_files_first_impl(
                clients_dir,
                location,
                user_attribute,
                self.store.vfs(),
            ),
        }
    }

    fn read_dir_files_next(
        &mut self,
        state: ReadDirFilesState,
    ) -> Result<Option<(Option<Message>, ReadDirFilesState)>> {
        match state.location {
            Location::Internal => self.read_dir_files_next_impl(state, self.store.ifs()),
            Location::External => self.read_dir_files_next_impl(state, self.store.efs()),
            Location::Volatile => self.read_dir_files_next_impl(state, self.store.vfs()),
        }
    }

    fn locate_file(
        &mut self,
        location: Location,
        underneath: Option<PathBuf>,
        filename: PathBuf,
    ) -> Result<Option<PathBuf>> {
        if location != Location::Internal {
            return Err(Error::RequestNotAvailable);
        }

        let clients_dir = underneath.unwrap_or_else(|| PathBuf::from("/"));
        let dir = self.actual_path(&clients_dir)?;
        let fs = self.store.ifs();

        info_now!("base dir {:?}", &dir);

        fn recursively_locate<S: 'static + crate::types::LfsStorage>(
            fs: &'static crate::store::Fs<S>,
            dir: PathBuf,
            filename: &Path,
        ) -> Option<PathBuf> {
            fs.read_dir_and_then(&dir, |it| {
                it.map(|entry| entry.unwrap())
                    .skip(2)
                    .filter_map(|entry| {
                        let is_file = entry.file_type().is_file();
                        if is_file {
                            if PathBuf::from(entry.file_name()) == PathBuf::from(filename) {
                                Some(PathBuf::from(entry.path()))
                            } else {
                                None
                            }
                        } else {
                            recursively_locate(fs, PathBuf::from(entry.path()), filename)
                        }
                    })
                    .next()
                    .ok_or(littlefs2::io::Error::Io)
            })
            .ok()
        }

        let path = recursively_locate(fs, dir, &filename).map(|path| self.client_path(&path));

        Ok(path)
    }
}
