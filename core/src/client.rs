use core::{marker::PhantomData, task::Poll};

use crate::{
    api::{reply, request, NotBefore, Reply, ReplyVariant, RequestVariant},
    error::{Error, Result},
    interrupt::InterruptFlag,
    types::{
        consent, reboot, Bytes, CertId, KeyId, KeySerialization, Location, Mechanism, MediumData,
        Message, PathBuf, SerializedKey, ShortData, Signature, SignatureSerialization,
        StorageAttributes, UserAttribute,
    },
};

mod mechanisms;
pub use mechanisms::{
    Aes256Cbc, Chacha8Poly1305, Ed255, HmacBlake2s, HmacSha1, HmacSha256, HmacSha512, Sha256, Tdes,
    Totp, P256, P384, P521, X255,
};

// to be fair, this is a programmer error,
// and could also just panic
#[derive(Copy, Clone, Debug)]
pub enum ClientError {
    Full,
    Pending,
    DataTooLarge,
    SerializationFailed,
}

pub type ClientResult<'c, T, C> = Result<FutureResult<'c, T, C>, ClientError>;

/// Lowest level interface, use one of the higher level ones.
pub trait PollClient {
    fn request<Rq: RequestVariant>(&mut self, req: Rq) -> ClientResult<'_, Rq::Reply, Self>;
    fn poll(&mut self) -> Poll<Result<Reply, Error>>;
    fn interrupt(&self) -> Option<&'static InterruptFlag> {
        None
    }
}

#[must_use = "Syscalls must be polled with the `syscall` macro"]
pub struct FutureResult<'c, T, C: ?Sized>
where
    C: PollClient,
{
    pub(crate) client: &'c mut C,
    __: PhantomData<T>,
}

impl<'c, T, C> FutureResult<'c, T, C>
where
    T: ReplyVariant,
    C: PollClient,
{
    pub fn new(client: &'c mut C) -> Self {
        Self {
            client,
            __: PhantomData,
        }
    }
    pub fn poll(&mut self) -> Poll<Result<T, Error>> {
        self.client
            .poll()
            .map(|result| result.and_then(TryFrom::try_from))
    }
}

/// Read/Write + Delete certificates
pub trait CertificateClient: PollClient {
    fn delete_certificate(
        &mut self,
        id: CertId,
    ) -> ClientResult<'_, reply::DeleteCertificate, Self> {
        self.request(request::DeleteCertificate { id })
    }

    fn read_certificate(&mut self, id: CertId) -> ClientResult<'_, reply::ReadCertificate, Self> {
        self.request(request::ReadCertificate { id })
    }

    /// Currently, this writes the cert (assumed but not verified to be DER)
    /// as-is. It might make sense to add attributes (such as "deletable").
    /// (On the other hand, the attn CA certs are not directly accessible to clients,
    /// and generated attn certs can be regenerated).
    fn write_certificate(
        &mut self,
        location: Location,
        der: &[u8],
    ) -> ClientResult<'_, reply::WriteCertificate, Self> {
        let der = Message::from_slice(der).map_err(|_| ClientError::DataTooLarge)?;
        self.request(request::WriteCertificate { location, der })
    }
}

/// Trussed Client interface that Trussed apps can rely on.
pub trait CryptoClient: PollClient {
    // call with any of `crate::api::request::*`
    // fn request<'c>(&'c mut self, req: impl Into<Request>)
    // -> core::result::Result<RawFutureResult<'c, Self>, ClientError>;

    fn agree(
        &mut self,
        mechanism: Mechanism,
        private_key: KeyId,
        public_key: KeyId,
        attributes: StorageAttributes,
    ) -> ClientResult<'_, reply::Agree, Self> {
        self.request(request::Agree {
            mechanism,
            private_key,
            public_key,
            attributes,
        })
    }

    #[cfg(feature = "crypto-client-attest")]
    fn attest(
        &mut self,
        signing_mechanism: Mechanism,
        private_key: KeyId,
    ) -> ClientResult<'_, reply::Attest, Self> {
        self.request(request::Attest {
            signing_mechanism,
            private_key,
        })
    }

    fn decrypt<'c>(
        &'c mut self,
        mechanism: Mechanism,
        key: KeyId,
        message: &[u8],
        associated_data: &[u8],
        nonce: &[u8],
        tag: &[u8],
    ) -> ClientResult<'c, reply::Decrypt, Self> {
        let message = Message::from_slice(message).map_err(|_| ClientError::DataTooLarge)?;
        let associated_data =
            Message::from_slice(associated_data).map_err(|_| ClientError::DataTooLarge)?;
        let nonce = ShortData::from_slice(nonce).map_err(|_| ClientError::DataTooLarge)?;
        let tag = ShortData::from_slice(tag).map_err(|_| ClientError::DataTooLarge)?;
        self.request(request::Decrypt {
            mechanism,
            key,
            message,
            associated_data,
            nonce,
            tag,
        })
    }

    fn delete(&mut self, key: KeyId) -> ClientResult<'_, reply::Delete, Self> {
        self.request(request::Delete {
            key,
            // mechanism,
        })
    }

    /// Clear private data from the key
    ///
    /// This will not delete all metadata from storage.
    /// Other backends can retain metadata required for `unwrap_key` to work properly
    /// and delete this metadata only once `delete` is called.
    fn clear(&mut self, key: KeyId) -> ClientResult<'_, reply::Clear, Self> {
        self.request(request::Clear {
            key,
            // mechanism,
        })
    }

    /// Skips deleting read-only / manufacture keys (currently, "low ID").
    fn delete_all(&mut self, location: Location) -> ClientResult<'_, reply::DeleteAllKeys, Self> {
        self.request(request::DeleteAllKeys { location })
    }

    fn derive_key(
        &mut self,
        mechanism: Mechanism,
        base_key: KeyId,
        additional_data: Option<MediumData>,
        attributes: StorageAttributes,
    ) -> ClientResult<'_, reply::DeriveKey, Self> {
        self.request(request::DeriveKey {
            mechanism,
            base_key,
            additional_data,
            attributes,
        })
    }

    fn deserialize_key<'c>(
        &'c mut self,
        mechanism: Mechanism,
        serialized_key: &[u8],
        format: KeySerialization,
        attributes: StorageAttributes,
    ) -> ClientResult<'c, reply::DeserializeKey, Self> {
        let serialized_key =
            SerializedKey::from_slice(serialized_key).map_err(|_| ClientError::DataTooLarge)?;
        self.request(request::DeserializeKey {
            mechanism,
            serialized_key,
            format,
            attributes,
        })
    }

    fn encrypt<'c>(
        &'c mut self,
        mechanism: Mechanism,
        key: KeyId,
        message: &[u8],
        associated_data: &[u8],
        nonce: Option<ShortData>,
    ) -> ClientResult<'c, reply::Encrypt, Self> {
        let message = Message::from_slice(message).map_err(|_| ClientError::DataTooLarge)?;
        let associated_data =
            ShortData::from_slice(associated_data).map_err(|_| ClientError::DataTooLarge)?;
        self.request(request::Encrypt {
            mechanism,
            key,
            message,
            associated_data,
            nonce,
        })
    }

    fn exists(
        &mut self,
        mechanism: Mechanism,
        key: KeyId,
    ) -> ClientResult<'_, reply::Exists, Self> {
        self.request(request::Exists { key, mechanism })
    }

    fn generate_key(
        &mut self,
        mechanism: Mechanism,
        attributes: StorageAttributes,
    ) -> ClientResult<'_, reply::GenerateKey, Self> {
        self.request(request::GenerateKey {
            mechanism,
            attributes,
        })
    }

    fn generate_secret_key(
        &mut self,
        size: usize,
        persistence: Location,
    ) -> ClientResult<'_, reply::GenerateSecretKey, Self> {
        self.request(request::GenerateSecretKey {
            size,
            attributes: StorageAttributes::new().set_persistence(persistence),
        })
    }

    fn hash(
        &mut self,
        mechanism: Mechanism,
        message: Message,
    ) -> ClientResult<'_, reply::Hash, Self> {
        self.request(request::Hash { mechanism, message })
    }

    fn random_bytes(&mut self, count: usize) -> ClientResult<'_, reply::RandomBytes, Self> {
        self.request(request::RandomBytes { count })
    }

    fn serialize_key(
        &mut self,
        mechanism: Mechanism,
        key: KeyId,
        format: KeySerialization,
    ) -> ClientResult<'_, reply::SerializeKey, Self> {
        self.request(request::SerializeKey {
            key,
            mechanism,
            format,
        })
    }

    fn sign<'c>(
        &'c mut self,
        mechanism: Mechanism,
        key: KeyId,
        data: &[u8],
        format: SignatureSerialization,
    ) -> ClientResult<'c, reply::Sign, Self> {
        self.request(request::Sign {
            key,
            mechanism,
            message: Bytes::from_slice(data).map_err(|_| ClientError::DataTooLarge)?,
            format,
        })
    }

    fn verify<'c>(
        &'c mut self,
        mechanism: Mechanism,
        key: KeyId,
        message: &[u8],
        signature: &[u8],
        format: SignatureSerialization,
    ) -> ClientResult<'c, reply::Verify, Self> {
        self.request(request::Verify {
            mechanism,
            key,
            message: Message::from_slice(message).expect("all good"),
            signature: Signature::from_slice(signature).expect("all good"),
            format,
        })
    }

    fn unsafe_inject_key(
        &mut self,
        mechanism: Mechanism,
        raw_key: &[u8],
        persistence: Location,
        format: KeySerialization,
    ) -> ClientResult<'_, reply::UnsafeInjectKey, Self> {
        self.request(request::UnsafeInjectKey {
            mechanism,
            raw_key: SerializedKey::from_slice(raw_key).unwrap(),
            attributes: StorageAttributes::new().set_persistence(persistence),
            format,
        })
    }

    fn unsafe_inject_shared_key(
        &mut self,
        raw_key: &[u8],
        location: Location,
    ) -> ClientResult<'_, reply::UnsafeInjectSharedKey, Self> {
        self.request(request::UnsafeInjectSharedKey {
            raw_key: ShortData::from_slice(raw_key).unwrap(),
            location,
        })
    }

    fn unwrap_key<'c>(
        &'c mut self,
        mechanism: Mechanism,
        wrapping_key: KeyId,
        wrapped_key: Message,
        associated_data: &[u8],
        nonce: &[u8],
        attributes: StorageAttributes,
    ) -> ClientResult<'c, reply::UnwrapKey, Self> {
        let associated_data =
            Message::from_slice(associated_data).map_err(|_| ClientError::DataTooLarge)?;
        let nonce = ShortData::from_slice(nonce).map_err(|_| ClientError::DataTooLarge)?;
        self.request(request::UnwrapKey {
            mechanism,
            wrapping_key,
            wrapped_key,
            associated_data,
            nonce,
            attributes,
        })
    }

    fn wrap_key(
        &mut self,
        mechanism: Mechanism,
        wrapping_key: KeyId,
        key: KeyId,
        associated_data: &[u8],
        nonce: Option<ShortData>,
    ) -> ClientResult<'_, reply::WrapKey, Self> {
        let associated_data =
            Bytes::from_slice(associated_data).map_err(|_| ClientError::DataTooLarge)?;
        self.request(request::WrapKey {
            mechanism,
            wrapping_key,
            key,
            associated_data,
            nonce,
        })
    }
}

/// Create counters, increment existing counters.
pub trait CounterClient: PollClient {
    #[cfg(feature = "counter-client")]
    fn create_counter(
        &mut self,
        location: Location,
    ) -> ClientResult<'_, reply::CreateCounter, Self> {
        self.request(request::CreateCounter { location })
    }

    #[cfg(feature = "counter-client")]
    fn increment_counter(
        &mut self,
        id: crate::types::CounterId,
    ) -> ClientResult<'_, reply::IncrementCounter, Self> {
        self.request(request::IncrementCounter { id })
    }
}

/// Read/Write/Delete files, iterate over directories.
pub trait FilesystemClient: PollClient {
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

/// All the other methods that are fit to expose.
pub trait ManagementClient: PollClient {
    fn reboot(&mut self, to: reboot::To) -> ClientResult<'_, reply::Reboot, Self> {
        self.request(request::Reboot { to })
    }

    fn uptime(&mut self) -> ClientResult<'_, reply::Uptime, Self> {
        self.request(request::Uptime {})
    }
}

/// User-interfacing functionality.
pub trait UiClient: PollClient {
    fn confirm_user_present(
        &mut self,
        timeout_milliseconds: u32,
    ) -> ClientResult<'_, reply::RequestUserConsent, Self> {
        self.request(request::RequestUserConsent {
            level: consent::Level::Normal,
            timeout_milliseconds,
        })
    }

    fn wink(&mut self, duration: core::time::Duration) -> ClientResult<'_, reply::Wink, Self> {
        self.request(request::Wink { duration })
    }

    fn set_custom_status(&mut self, status: u8) -> ClientResult<'_, reply::SetCustomStatus, Self> {
        self.request(request::SetCustomStatus { status })
    }
}

// would be interesting to use proper futures, and something like
// https://github.com/dflemstr/direct-executor/blob/master/src/lib.rs#L62-L66

#[macro_export]
// #[deprecated]
macro_rules! block {
    ($future_result:expr) => {{
        // evaluate the expression
        let mut future_result = $future_result;
        loop {
            match future_result.poll() {
                core::task::Poll::Ready(result) => {
                    break result;
                }
                core::task::Poll::Pending => {}
            }
        }
    }};
}

#[macro_export]
macro_rules! syscall {
    ($pre_future_result:expr) => {{
        // evaluate the expression
        let mut future_result = $pre_future_result.expect("no client error");
        loop {
            match future_result.poll() {
                core::task::Poll::Ready(result) => {
                    break result.expect("no errors");
                }
                core::task::Poll::Pending => {}
            }
        }
    }};
}

#[macro_export]
macro_rules! try_syscall {
    ($pre_future_result:expr) => {{
        // evaluate the expression
        let mut future_result = $pre_future_result.expect("no client error");
        loop {
            match future_result.poll() {
                core::task::Poll::Ready(result) => {
                    break result;
                }
                core::task::Poll::Pending => {}
            }
        }
    }};
}
