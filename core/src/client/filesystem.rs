use super::{ClientResult, PollClient};
use crate::{
    api::{reply, request},
    types::{Location, Message, NotBefore, PathBuf, UserAttribute},
};

/// Read/Write/Delete files, iterate over directories.
pub trait FilesystemClient: PollClient {
    #[deprecated]
    fn debug_dump_store(&mut self) -> ClientResult<'_, reply::DebugDumpStore, Self> {
        self.request(request::DebugDumpStore {})
    }

    /// Open a directory for iteration with `read_dir_next`
    ///
    /// For optimization, not_before_filename can be passed to begin the iteration at that file.
    fn read_dir_first(
        &mut self,
        location: Location,
        dir: PathBuf,
        not_before_filename: Option<PathBuf>,
    ) -> ClientResult<'_, reply::ReadDirFirst, Self> {
        self.request(request::ReadDirFirst {
            location,
            dir,
            not_before: NotBefore::with_filename(not_before_filename),
        })
    }

    /// Open a directory for iteration with `read_dir_next`
    ///
    /// For optimization, not_before_filename can be passed to begin the iteration after the first file that is "alphabetically" before the original file
    ///
    /// <div class="warning">
    /// The notion used here for "alphabetical" does not correspond to the order of iteration yielded by littlefs. This function should be used with caution. If `not_before_filename` was yielded from a previous use of read_dir, it can lead to entries being repeated.
    /// </div>
    fn read_dir_first_alphabetical(
        &mut self,
        location: Location,
        dir: PathBuf,
        not_before_filename: Option<PathBuf>,
    ) -> ClientResult<'_, reply::ReadDirFirst, Self> {
        self.request(request::ReadDirFirst {
            location,
            dir,
            not_before: NotBefore::with_filename_part(not_before_filename),
        })
    }

    fn read_dir_next(&mut self) -> ClientResult<'_, reply::ReadDirNext, Self> {
        self.request(request::ReadDirNext {})
    }

    fn read_dir_files_first(
        &mut self,
        location: Location,
        dir: PathBuf,
        user_attribute: Option<UserAttribute>,
    ) -> ClientResult<'_, reply::ReadDirFilesFirst, Self> {
        self.request(request::ReadDirFilesFirst {
            dir,
            location,
            user_attribute,
        })
    }

    fn read_dir_files_next(&mut self) -> ClientResult<'_, reply::ReadDirFilesNext, Self> {
        self.request(request::ReadDirFilesNext {})
    }

    fn remove_dir(
        &mut self,
        location: Location,
        path: PathBuf,
    ) -> ClientResult<'_, reply::RemoveDir, Self> {
        self.request(request::RemoveDir { location, path })
    }

    fn remove_dir_all(
        &mut self,
        location: Location,
        path: PathBuf,
    ) -> ClientResult<'_, reply::RemoveDirAll, Self> {
        self.request(request::RemoveDirAll { location, path })
    }

    fn remove_file(
        &mut self,
        location: Location,
        path: PathBuf,
    ) -> ClientResult<'_, reply::RemoveFile, Self> {
        self.request(request::RemoveFile { location, path })
    }

    fn read_file(
        &mut self,
        location: Location,
        path: PathBuf,
    ) -> ClientResult<'_, reply::ReadFile, Self> {
        self.request(request::ReadFile { location, path })
    }

    /// Fetch the Metadata for a file or directory
    ///
    /// If the file doesn't exists, return None
    fn entry_metadata(
        &mut self,
        location: Location,
        path: PathBuf,
    ) -> ClientResult<'_, reply::Metadata, Self> {
        self.request(request::Metadata { location, path })
    }

    /// Rename a file or directory.
    ///
    /// If `to` exists, it must be the same type as `from` (i. e., both must be files or both must
    /// be directories).  If `to` is a directory, it must be empty.
    fn rename(
        &mut self,
        location: Location,
        from: PathBuf,
        to: PathBuf,
    ) -> ClientResult<'_, reply::Rename, Self> {
        self.request(request::Rename { location, from, to })
    }

    fn locate_file(
        &mut self,
        location: Location,
        dir: Option<PathBuf>,
        filename: PathBuf,
    ) -> ClientResult<'_, reply::LocateFile, Self> {
        self.request(request::LocateFile {
            location,
            dir,
            filename,
        })
    }

    fn write_file(
        &mut self,
        location: Location,
        path: PathBuf,
        data: Message,
        user_attribute: Option<UserAttribute>,
    ) -> ClientResult<'_, reply::WriteFile, Self> {
        self.request(request::WriteFile {
            location,
            path,
            data,
            user_attribute,
        })
    }
}
