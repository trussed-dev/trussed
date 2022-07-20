//! # Client interface for applications.
//!
//! The API methods (such as `GenerateKey`, `Sign`, `Verify`,...) are implemented by a variety
//! of mechanisms (such as `Ed255`, `X255`, `Chacha8Poly1305`, `HmacSha256`,...).
//!
//! The `ClientImplementation` structure in this module offers only one general `request` method:
//! ```ignore
//! pub fn request<'c, T: From<Reply>>(&'c mut self, req: impl Into<Request>)
//!   -> ClientResult<'c, T, Self>
//! ```
//!
//! For convenience, the `Client` trait expands the API methods, keeping the mechanism general,
//! e.g.:
//! ```ignore
//! // use trussed::Client as _;
//! fn sign<'c>(&'c mut self,
//!   mechanism: Mechanism,
//!   key: KeyId,
//!   data: &[u8],
//!   format: SignatureSerialization
//! ) -> ClientResult<'c, reply::Sign, Self>;
//! ```
//!
//! For further convenience, each mechanism has a corresponding trait of the same name, e.g.,
//! `Ed255`, which also specializes the mechanism, e.g.
//! ```ignore
//! // use trussed::client::Ed255 as _;
//! fn sign_ed255<'c>(&'c mut self, key: &KeyId, message: &[u8])
//!   -> ClientResult<'c, reply::Sign, Self>
//! ```
//!
//! Pick your poison :)
//!
//! # Details
//!
//! The lower-level workings of `ClientResult` are currently a hand-rolled / semi-horrible
//! pseudo-`Future` implementation; this will likely be replaced by a proper `core::future::Future`
//! with something like the [direct-executor](https://github.com/dflemstr/direct-executor).
//!
//! The lifetimes indicate that the `ClientResult` takes ownership of the unique reference
//! to the client itself for the length of its own lifetime. That is, once the call to Trussed
//! completes (success or failure), there is no use for the `ClientResult` anymore, so due to
//! lexical lifetimes, the `ClientImplementation` can be used again.
//!
//! What does always happen is that each client has an Interchange with the service, in which
//! it places the `api::Request` (a Rust enum), and then uses the `Syscall` implementation, to
//! trigger processing by the Trussed service.
//!
//! In practice, in embedded Syscall is implemented by pending a hardware interrupt for the
//! service, which runs at a higher interrupt priority. For PC testing, the service itself
//! has a Syscall implementation ("call thyself"). In both cases, the caller is blocked until
//! processing completes.
//!
//! All the same, to unpack the "result" it is suggested to use the `syscall!` macro, which
//! returns the `Reply` corresponding to the `Request`. Example:
//! ```ignore
//! let secret_key = syscall!(client.generate_x255_secret_key(Internal)).key;
//! ```
//!
//! This `syscall!` can fail (by panicking) in two ways:
//! - logic error: clients are only allowed to make one syscall to the Trussed service at once,
//!   then they must wait for a response. By the above, this case cannot happen in practice.
//! - processing error: some methods are naturally fallible; for example, a public key that is
//!   to be imported via `Deserialize` may be invalid for the mechanism (such things are always checked).
//!
//! In this second case (probably in all cases when programming defensively, e.g. one possible
//! `trussed::error::Error` is `HostMemory`, which means out of RAM), the `try_syscall!` macro
//! should be used instead, which does not unwrap the inner Result type.
//!
//! In terms of the `Result<FutureResult<'c, T, C>, ClientError>` return type of the `Client::request`
//! method, the outer `Result` corresponds to the logic error (see `trussed::client::ClientError`)
//! for possible causes.
//!
//! The processing error corresponds to the `Result<From<Reply, trussed::error::Error>>` which is
//! the `Ready` variant of the `core::task::Poll` struct returns by the `FutureResult`'s `poll` method.
//! Possible causes are listed in `trussed::error::Error`.
//!
use core::marker::PhantomData;

use interchange::Requester;

use crate::api::*;
use crate::error::*;
use crate::pipe::TrussedInterchange;
use crate::types::*;

pub use crate::platform::Syscall;

pub mod mechanisms;
pub use mechanisms::*;

// to be fair, this is a programmer error,
// and could also just panic
#[derive(Copy, Clone, Debug)]
pub enum ClientError {
    Full,
    Pending,
    DataTooLarge,
}

pub type ClientResult<'c, T, C> = core::result::Result<FutureResult<'c, T, C>, ClientError>;

/// All-in-one trait bounding on the sub-traits.
pub trait Client:
    CertificateClient + CryptoClient + CounterClient + FilesystemClient + ManagementClient + UiClient
{
}

impl<S: Syscall> Client for ClientImplementation<S> {}

/// Lowest level interface, use one of the higher level ones.
pub trait PollClient {
    fn request<T: From<crate::api::Reply>>(
        &mut self,
        req: impl Into<Request>,
    ) -> ClientResult<'_, T, Self>;
    fn poll(&mut self) -> core::task::Poll<core::result::Result<Reply, Error>>;
    fn syscall(&mut self);
    fn set_service_backends(&mut self, backends: Vec<ServiceBackends, 2>) -> ClientResult<'_, reply::SetServiceBackends, Self>;
}

pub struct FutureResult<'c, T, C: ?Sized>
where
    C: PollClient,
{
    client: &'c mut C,
    __: PhantomData<T>,
}

impl<'c, T, C> FutureResult<'c, T, C>
where
    T: From<crate::api::Reply>,
    C: PollClient,
{
    pub fn new(client: &'c mut C) -> Self {
        Self {
            client,
            __: PhantomData,
        }
    }
    pub fn poll(&mut self) -> core::task::Poll<core::result::Result<T, Error>> {
        use core::task::Poll::{Pending, Ready};
        match self.client.poll() {
            Ready(Ok(reply)) => Ready(Ok(T::from(reply))),
            Ready(Err(error)) => Ready(Err(error)),
            Pending => Pending,
        }
    }
}

/// The client implementation client applications actually receive.
pub struct ClientImplementation<S> {
    // raw: RawClient<Client<S>>,
    syscall: S,

    // RawClient:
    pub(crate) interchange: Requester<TrussedInterchange>,
    // pending: Option<Discriminant<Request>>,
    pending: Option<u8>,
}

// impl<S> From<(RawClient, S)> for Client<S>
// where S: Syscall
// {
//     fn from(input: (RawClient, S)) -> Self {
//         Self { raw: input.0, syscall: input.1 }
//     }
// }

impl<S> ClientImplementation<S>
where
    S: Syscall,
{
    pub fn new(interchange: Requester<TrussedInterchange>, syscall: S) -> Self {
        Self {
            interchange,
            pending: None,
            syscall,
        }
    }
}

impl<S> PollClient for ClientImplementation<S>
where
    S: Syscall,
{
    fn poll(&mut self) -> core::task::Poll<core::result::Result<Reply, Error>> {
        match self.interchange.take_response() {
            Some(reply) => {
                // #[cfg(all(test, feature = "verbose-tests"))]
                // println!("got a reply: {:?}", &reply);
                match reply {
                    Ok(reply) => {
                        if Some(u8::from(&reply)) == self.pending {
                            self.pending = None;
                            core::task::Poll::Ready(Ok(reply))
                        } else {
                            // #[cfg(all(test, feature = "verbose-tests"))]
                            info!(
                                "got: {:?}, expected: {:?}",
                                Some(u8::from(&reply)),
                                self.pending
                            );
                            core::task::Poll::Ready(Err(Error::InternalError))
                        }
                    }
                    Err(error) => {
                        self.pending = None;
                        core::task::Poll::Ready(Err(error))
                    }
                }
            }
            None => core::task::Poll::Pending,
        }
    }

    // call with any of `crate::api::request::*`
    fn request<T: From<crate::api::Reply>>(
        &mut self,
        req: impl Into<Request>,
    ) -> ClientResult<'_, T, Self> {
        // TODO: handle failure
        // TODO: fail on pending (non-canceled) request)
        if self.pending.is_some() {
            return Err(ClientError::Pending);
        }
        // since no pending, also queue empty
        // if !self.ready() {
        //     return Err(ClientError::Fulle);
        // }
        // in particular, can unwrap
        let request = req.into();
        self.pending = Some(u8::from(&request));
        self.interchange.request(&request).map_err(drop).unwrap();
        Ok(FutureResult::new(self))
    }

    fn syscall(&mut self) {
        self.syscall.syscall()
    }

    fn set_service_backends(&mut self, backends: Vec<ServiceBackends, 2>)
        -> ClientResult<'_, reply::SetServiceBackends, Self>
    {
        let r = self.request(request::SetServiceBackends { backends })?;
        r.client.syscall();
        Ok(r)
    }

}

impl<S: Syscall> CertificateClient for ClientImplementation<S> {}
impl<S: Syscall> CryptoClient for ClientImplementation<S> {}
impl<S: Syscall> CounterClient for ClientImplementation<S> {}
impl<S: Syscall> FilesystemClient for ClientImplementation<S> {}
impl<S: Syscall> ManagementClient for ClientImplementation<S> {}
impl<S: Syscall> UiClient for ClientImplementation<S> {}

/// Read/Write + Delete certificates
pub trait CertificateClient: PollClient {
    fn delete_certificate(
        &mut self,
        id: CertId,
    ) -> ClientResult<'_, reply::DeleteCertificate, Self> {
        let r = self.request(request::DeleteCertificate { id })?;
        r.client.syscall();
        Ok(r)
    }

    fn read_certificate(&mut self, id: CertId) -> ClientResult<'_, reply::ReadCertificate, Self> {
        let r = self.request(request::ReadCertificate { id })?;
        r.client.syscall();
        Ok(r)
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
        let r = self.request(request::WriteCertificate { location, der })?;
        r.client.syscall();
        Ok(r)
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
        let r = self.request(request::Agree {
            mechanism,
            private_key,
            public_key,
            attributes,
        })?;
        r.client.syscall();
        Ok(r)
    }

    fn attest(
        &mut self,
        signing_mechanism: Mechanism,
        private_key: KeyId,
    ) -> ClientResult<'_, reply::Attest, Self> {
        let r = self.request(request::Attest {
            signing_mechanism,
            private_key,
        })?;
        r.client.syscall();
        Ok(r)
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
        let r = self.request(request::Decrypt {
            mechanism,
            key,
            message,
            associated_data,
            nonce,
            tag,
        })?;
        r.client.syscall();
        Ok(r)
    }

    fn delete(&mut self, key: KeyId) -> ClientResult<'_, reply::Delete, Self> {
        let r = self.request(request::Delete {
            key,
            // mechanism,
        })?;
        r.client.syscall();
        Ok(r)
    }

    /// Skips deleting read-only / manufacture keys (currently, "low ID").
    fn delete_all(&mut self, location: Location) -> ClientResult<'_, reply::DeleteAllKeys, Self> {
        let r = self.request(request::DeleteAllKeys { location })?;
        r.client.syscall();
        Ok(r)
    }

    fn derive_key(
        &mut self,
        mechanism: Mechanism,
        base_key: KeyId,
        additional_data: Option<MediumData>,
        attributes: StorageAttributes,
    ) -> ClientResult<'_, reply::DeriveKey, Self> {
        let r = self.request(request::DeriveKey {
            mechanism,
            base_key,
            additional_data,
            attributes,
        })?;
        r.client.syscall();
        Ok(r)
    }

    fn deserialize_key<'c>(
        &'c mut self,
        mechanism: Mechanism,
        serialized_key: &[u8],
        format: KeySerialization,
        attributes: StorageAttributes,
    ) -> ClientResult<'c, reply::DeserializeKey, Self> {
        let serialized_key =
            Message::from_slice(serialized_key).map_err(|_| ClientError::DataTooLarge)?;
        let r = self.request(request::DeserializeKey {
            mechanism,
            serialized_key,
            format,
            attributes,
        })?;
        r.client.syscall();
        Ok(r)
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
        let r = self.request(request::Encrypt {
            mechanism,
            key,
            message,
            associated_data,
            nonce,
        })?;
        r.client.syscall();
        Ok(r)
    }

    fn exists(
        &mut self,
        mechanism: Mechanism,
        key: KeyId,
    ) -> ClientResult<'_, reply::Exists, Self> {
        let r = self.request(request::Exists { key, mechanism })?;
        r.client.syscall();
        Ok(r)
    }

    fn generate_key(
        &mut self,
        mechanism: Mechanism,
        attributes: StorageAttributes,
    ) -> ClientResult<'_, reply::GenerateKey, Self> {
        let r = self.request(request::GenerateKey {
            mechanism,
            attributes,
        })?;
        r.client.syscall();
        Ok(r)
    }

    fn generate_secret_key(
        &mut self,
        size: usize,
        persistence: Location,
    ) -> ClientResult<'_, reply::GenerateSecretKey, Self> {
        let r = self.request(request::GenerateSecretKey {
            size,
            attributes: StorageAttributes::new().set_persistence(persistence),
        })?;
        r.client.syscall();
        Ok(r)
    }

    fn hash(
        &mut self,
        mechanism: Mechanism,
        message: Message,
    ) -> ClientResult<'_, reply::Hash, Self> {
        let r = self.request(request::Hash { mechanism, message })?;
        r.client.syscall();
        Ok(r)
    }

    fn random_bytes(&mut self, count: usize) -> ClientResult<'_, reply::RandomBytes, Self> {
        let r = self.request(request::RandomBytes { count })?;
        r.client.syscall();
        Ok(r)
    }

    fn serialize_key(
        &mut self,
        mechanism: Mechanism,
        key: KeyId,
        format: KeySerialization,
    ) -> ClientResult<'_, reply::SerializeKey, Self> {
        let r = self.request(request::SerializeKey {
            key,
            mechanism,
            format,
        })?;
        r.client.syscall();
        Ok(r)
    }

    fn sign<'c>(
        &'c mut self,
        mechanism: Mechanism,
        key: KeyId,
        data: &[u8],
        format: SignatureSerialization,
    ) -> ClientResult<'c, reply::Sign, Self> {
        let r = self.request(request::Sign {
            key,
            mechanism,
            message: Bytes::from_slice(data).map_err(|_| ClientError::DataTooLarge)?,
            format,
        })?;
        r.client.syscall();
        Ok(r)
    }

    fn verify<'c>(
        &'c mut self,
        mechanism: Mechanism,
        key: KeyId,
        message: &[u8],
        signature: &[u8],
        format: SignatureSerialization,
    ) -> ClientResult<'c, reply::Verify, Self> {
        let r = self.request(request::Verify {
            mechanism,
            key,
            message: Message::from_slice(message).expect("all good"),
            signature: Signature::from_slice(signature).expect("all good"),
            format,
        })?;
        r.client.syscall();
        Ok(r)
    }

    fn unsafe_inject_key(
        &mut self,
        mechanism: Mechanism,
        raw_key: &[u8],
        persistence: Location,
        format: KeySerialization,
    ) -> ClientResult<'_, reply::UnsafeInjectKey, Self> {
        let r = self.request(request::UnsafeInjectKey {
            mechanism,
            raw_key: ShortData::from_slice(raw_key).unwrap(),
            attributes: StorageAttributes::new().set_persistence(persistence),
            format,
        })?;
        r.client.syscall();
        Ok(r)
    }

    fn unsafe_inject_shared_key(
        &mut self,
        raw_key: &[u8],
        location: Location,
    ) -> ClientResult<'_, reply::UnsafeInjectSharedKey, Self> {
        let r = self.request(request::UnsafeInjectSharedKey {
            raw_key: ShortData::from_slice(raw_key).unwrap(),
            location,
        })?;
        r.client.syscall();
        Ok(r)
    }

    fn unwrap_key<'c>(
        &'c mut self,
        mechanism: Mechanism,
        wrapping_key: KeyId,
        wrapped_key: Message,
        associated_data: &[u8],
        attributes: StorageAttributes,
    ) -> ClientResult<'c, reply::UnwrapKey, Self> {
        let associated_data =
            Message::from_slice(associated_data).map_err(|_| ClientError::DataTooLarge)?;
        let r = self.request(request::UnwrapKey {
            mechanism,
            wrapping_key,
            wrapped_key,
            associated_data,
            attributes,
        })?;
        r.client.syscall();
        Ok(r)
    }

    fn wrap_key(
        &mut self,
        mechanism: Mechanism,
        wrapping_key: KeyId,
        key: KeyId,
        associated_data: &[u8],
    ) -> ClientResult<'_, reply::WrapKey, Self> {
        let associated_data =
            Message::from_slice(associated_data).map_err(|_| ClientError::DataTooLarge)?;
        let r = self.request(request::WrapKey {
            mechanism,
            wrapping_key,
            key,
            associated_data,
        })?;
        r.client.syscall();
        Ok(r)
    }
}

/// Create counters, increment existing counters.
pub trait CounterClient: PollClient {
    fn create_counter(
        &mut self,
        location: Location,
    ) -> ClientResult<'_, reply::CreateCounter, Self> {
        let r = self.request(request::CreateCounter { location })?;
        r.client.syscall();
        Ok(r)
    }

    fn increment_counter(
        &mut self,
        id: CounterId,
    ) -> ClientResult<'_, reply::IncrementCounter, Self> {
        let r = self.request(request::IncrementCounter { id })?;
        r.client.syscall();
        Ok(r)
    }
}

/// Read/Write/Delete files, iterate over directories.
pub trait FilesystemClient: PollClient {
    fn debug_dump_store(&mut self) -> ClientResult<'_, reply::DebugDumpStore, Self> {
        let r = self.request(request::DebugDumpStore {})?;
        r.client.syscall();
        Ok(r)
    }

    fn read_dir_first(
        &mut self,
        location: Location,
        dir: PathBuf,
        not_before_filename: Option<PathBuf>,
    ) -> ClientResult<'_, reply::ReadDirFirst, Self> {
        let r = self.request(request::ReadDirFirst {
            location,
            dir,
            not_before_filename,
        })?;
        r.client.syscall();
        Ok(r)
    }

    fn read_dir_next(&mut self) -> ClientResult<'_, reply::ReadDirNext, Self> {
        let r = self.request(request::ReadDirNext {})?;
        r.client.syscall();
        Ok(r)
    }

    fn read_dir_files_first(
        &mut self,
        location: Location,
        dir: PathBuf,
        user_attribute: Option<UserAttribute>,
    ) -> ClientResult<'_, reply::ReadDirFilesFirst, Self> {
        let r = self.request(request::ReadDirFilesFirst {
            dir,
            location,
            user_attribute,
        })?;
        r.client.syscall();
        Ok(r)
    }

    fn read_dir_files_next(&mut self) -> ClientResult<'_, reply::ReadDirFilesNext, Self> {
        let r = self.request(request::ReadDirFilesNext {})?;
        r.client.syscall();
        Ok(r)
    }

    fn remove_dir(
        &mut self,
        location: Location,
        path: PathBuf,
    ) -> ClientResult<'_, reply::RemoveDirAll, Self> {
        let r = self.request(request::RemoveDir { location, path })?;
        r.client.syscall();
        Ok(r)
    }

    fn remove_dir_all(
        &mut self,
        location: Location,
        path: PathBuf,
    ) -> ClientResult<'_, reply::RemoveDirAll, Self> {
        let r = self.request(request::RemoveDirAll { location, path })?;
        r.client.syscall();
        Ok(r)
    }

    fn remove_file(
        &mut self,
        location: Location,
        path: PathBuf,
    ) -> ClientResult<'_, reply::RemoveFile, Self> {
        let r = self.request(request::RemoveFile { location, path })?;
        r.client.syscall();
        Ok(r)
    }

    fn read_file(
        &mut self,
        location: Location,
        path: PathBuf,
    ) -> ClientResult<'_, reply::ReadFile, Self> {
        let r = self.request(request::ReadFile { location, path })?;
        r.client.syscall();
        Ok(r)
    }

    /// Fetch the Metadata for a file or directory
    ///
    /// If the file doesn't exists, return None
    fn entry_metadata(
        &mut self,
        location: Location,
        path: PathBuf,
    ) -> ClientResult<'_, reply::Metadata, Self> {
        let r = self.request(request::Metadata { location, path })?;
        r.client.syscall();
        Ok(r)
    }

    fn locate_file(
        &mut self,
        location: Location,
        dir: Option<PathBuf>,
        filename: PathBuf,
    ) -> ClientResult<'_, reply::LocateFile, Self> {
        let r = self.request(request::LocateFile {
            location,
            dir,
            filename,
        })?;
        r.client.syscall();
        Ok(r)
    }

    fn write_file(
        &mut self,
        location: Location,
        path: PathBuf,
        data: Message,
        user_attribute: Option<UserAttribute>,
    ) -> ClientResult<'_, reply::WriteFile, Self> {
        let r = self.request(request::WriteFile {
            location,
            path,
            data,
            user_attribute,
        })?;
        r.client.syscall();
        Ok(r)
    }
}

/// All the other methods that are fit to expose.
pub trait ManagementClient: PollClient {
    fn reboot(&mut self, to: reboot::To) -> ClientResult<'_, reply::Reboot, Self> {
        let r = self.request(request::Reboot { to })?;
        r.client.syscall();
        Ok(r)
    }

    fn uptime(&mut self) -> ClientResult<'_, reply::Uptime, Self> {
        let r = self.request(request::Uptime {})?;
        r.client.syscall();
        Ok(r)
    }
}

/// User-interfacing functionality.
pub trait UiClient: PollClient {
    fn confirm_user_present(
        &mut self,
        timeout_milliseconds: u32,
    ) -> ClientResult<'_, reply::RequestUserConsent, Self> {
        let r = self.request(request::RequestUserConsent {
            level: consent::Level::Normal,
            timeout_milliseconds,
        })?;
        r.client.syscall();
        Ok(r)
    }

    fn wink(&mut self, duration: core::time::Duration) -> ClientResult<'_, reply::Wink, Self> {
        let r = self.request(request::Wink { duration })?;
        r.client.syscall();
        Ok(r)
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
