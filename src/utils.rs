use littlefs2::path::PathBuf;

use crate::{
    syscall, try_syscall,
    types::{Location, Message, OpenSeekFrom, UserAttribute},
    Client, Error,
};

/// Write a large file (can be larger than 1KiB)
///
/// This is a wrapper around the [chunked writes api](crate::client::FilesystemClient::start_chunked_write)
pub fn write_all(
    client: &mut impl Client,
    location: Location,
    path: PathBuf,
    data: &[u8],
    user_attribute: Option<UserAttribute>,
) -> Result<(), Error> {
    if let Ok(msg) = Message::from_slice(data) {
        // Fast path for small files
        try_syscall!(client.write_file(location, path, msg, user_attribute))?;
        Ok(())
    } else {
        write_chunked(client, location, path, data, user_attribute)
    }
}

fn write_chunked(
    client: &mut impl Client,
    location: Location,
    path: PathBuf,
    data: &[u8],
    user_attribute: Option<UserAttribute>,
) -> Result<(), Error> {
    let res = write_chunked_inner(client, location, path.clone(), data, user_attribute);
    if res.is_ok() {
        try_syscall!(client.flush_chunks(location, path)).map(drop)
    } else {
        syscall!(client.abort_chunked_write(location, path));
        res
    }
}

fn write_chunked_inner(
    client: &mut impl Client,
    location: Location,
    path: PathBuf,
    data: &[u8],
    user_attribute: Option<UserAttribute>,
) -> Result<(), Error> {
    let mut msg = Message::new();
    let chunk_size = msg.capacity();
    let mut chunks = data.chunks(chunk_size).map(|chunk| {
        Message::from(
            heapless::Vec::try_from(chunk)
                .expect("Iteration over chunks yields maximum of chunk_size"),
        )
    });
    msg = chunks.next().unwrap_or_default();
    let mut written = msg.len();
    try_syscall!(client.start_chunked_write(location, path.clone(), msg, user_attribute))?;
    for chunk in chunks {
        let off = written;
        written += chunk.len();
        try_syscall!(client.write_file_chunk(
            location,
            path.clone(),
            chunk,
            OpenSeekFrom::Start(off as u32)
        ))?;
    }
    Ok(())
}
