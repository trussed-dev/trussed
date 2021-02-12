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
//!   key: ObjectHandle,
//!   data: &[u8],
//!   format: SignatureSerialization
//! ) -> ClientResult<'c, reply::Sign, Self>;
//! ```
//!
//! For further convenience, each mechanism has a corresponding trait of the same name, e.g.,
//! `Ed255`, which also specializes the mechanism, e.g.
//! ```ignore
//! // use trussed::client::Ed255 as _;
//! fn sign_ed255<'c>(&'c mut self, key: &ObjectHandle, message: &[u8])
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

// to be fair, this is a programmer error,
// and could also just panic
#[derive(Copy, Clone, Debug)]
pub enum ClientError {
    Full,
    Pending,
    DataTooLarge,
}

pub type ClientResult<'c, T, C> = core::result::Result<FutureResult<'c, T, C>, ClientError>;

#[cfg(feature = "p256")]
impl<S: Syscall> P256 for ClientImplementation<S> {}

pub trait P256: Client {
    fn generate_p256_private_key(&mut self, persistence: StorageLocation)
        -> ClientResult<'_, reply::GenerateKey, Self>
    {
        self.generate_key(Mechanism::P256, StorageAttributes::new().set_persistence(persistence))
    }

    fn derive_p256_public_key(&mut self, private_key: ObjectHandle, persistence: StorageLocation)
        -> ClientResult<'_, reply::DeriveKey, Self>
    {
        self.derive_key(Mechanism::P256, private_key, StorageAttributes::new().set_persistence(persistence))
    }

    fn deserialize_p256_key<'c>(&'c mut self, serialized_key: &[u8], format: KeySerialization, attributes: StorageAttributes)
        -> ClientResult<'c, reply::DeserializeKey, Self>
    {
        self.deserialize_key(Mechanism::P256, serialized_key, format, attributes)
    }

    fn serialize_p256_key(&mut self, key: ObjectHandle, format: KeySerialization)
        -> ClientResult<'_, reply::SerializeKey, Self>
    {
        self.serialize_key(Mechanism::P256, key, format)
    }

    // generally, don't offer multiple versions of a mechanism, if possible.
    // try using the simplest when given the choice.
    // hashing is something users can do themselves hopefully :)
    //
    // on the other hand: if users need sha256, then if the service runs in secure trustzone
    // domain, we'll maybe need two copies of the sha2 code
    fn sign_p256<'c>(&'c mut self, key: ObjectHandle, message: &[u8], format: SignatureSerialization)
        -> ClientResult<'c, reply::Sign, Self>
    {
        self.sign(Mechanism::P256, key, message, format)
    }

    fn verify_p256<'c>(&'c mut self, key: ObjectHandle, message: &[u8], signature: &[u8])
        -> ClientResult<'c, reply::Verify, Self>
    {
        self.verify(Mechanism::P256, key, message, signature, SignatureSerialization::Raw)
    }

    fn agree_p256(&mut self, private_key: ObjectHandle, public_key: ObjectHandle, persistence: StorageLocation)
        -> ClientResult<'_, reply::Agree, Self>
    {
        self.agree(
            Mechanism::P256,
            private_key,
            public_key,
            StorageAttributes::new().set_persistence(persistence),
        )
    }

}

#[cfg(feature = "ed255")]
impl<S: Syscall> Ed255 for ClientImplementation<S> {}

pub trait Ed255: Client {
    fn generate_ed255_private_key(&mut self, persistence: StorageLocation)
        -> ClientResult<'_, reply::GenerateKey, Self>
    {
        self.generate_key(Mechanism::Ed255, StorageAttributes::new().set_persistence(persistence))
    }

    fn derive_ed255_public_key(&mut self, private_key: ObjectHandle, persistence: StorageLocation)
        -> ClientResult<'_, reply::DeriveKey, Self>
    {
        self.derive_key(Mechanism::Ed255, private_key, StorageAttributes::new().set_persistence(persistence))
    }

    fn deserialize_ed255_key<'c>(&'c mut self, serialized_key: &[u8], format: KeySerialization, attributes: StorageAttributes)
        -> ClientResult<'c, reply::DeserializeKey, Self>
    {
        self.deserialize_key(Mechanism::Ed255, serialized_key, format, attributes)
    }

    fn serialize_ed255_key(&mut self, key: ObjectHandle, format: KeySerialization)
        -> ClientResult<'_, reply::SerializeKey, Self>
    {
        self.serialize_key(Mechanism::Ed255, key, format)
    }

    fn sign_ed255<'c>(&'c mut self, key: ObjectHandle, message: &[u8])
        -> ClientResult<'c, reply::Sign, Self>
    {
        self.sign(Mechanism::Ed255, key, message, SignatureSerialization::Raw)
    }

    fn verify_ed255<'c>(&'c mut self, key: ObjectHandle, message: &[u8], signature: &[u8])
        -> ClientResult<'c, reply::Verify, Self>
    {
        self.verify(Mechanism::Ed255, key, message, signature, SignatureSerialization::Raw)
    }
}

#[cfg(feature = "x255")]
impl<S: Syscall> X255 for ClientImplementation<S> {}

pub trait X255: Client {
    fn generate_x255_secret_key(&mut self, persistence: StorageLocation)
        -> ClientResult<'_, reply::GenerateKey, Self>
    {
        self.generate_key(Mechanism::X255, StorageAttributes::new().set_persistence(persistence))
    }

    fn derive_x255_public_key(&mut self, secret_key: ObjectHandle, persistence: StorageLocation)
        -> ClientResult<'_, reply::DeriveKey, Self>
    {
        self.derive_key(Mechanism::X255, secret_key, StorageAttributes::new().set_persistence(persistence))
    }

    fn agree_x255(&mut self, private_key: ObjectHandle, public_key: ObjectHandle, persistence: StorageLocation)
        -> ClientResult<'_, reply::Agree, Self>
    {
        self.agree(
            Mechanism::X255,
            private_key,
            public_key,
            StorageAttributes::new().set_persistence(persistence),
        )
    }
}

#[cfg(feature = "hmac-sha256")]
impl<S: Syscall> HmacSha256 for ClientImplementation<S> {}

pub trait HmacSha256: Client {
    fn generate_hmacsha256_key(&mut self, persistence: StorageLocation)
        -> ClientResult<'_, reply::GenerateKey, Self>
    {
        self.generate_key(Mechanism::HmacSha256, StorageAttributes::new().set_persistence(persistence))
    }

    fn sign_hmacsha256<'c>(&'c mut self, key: ObjectHandle, message: &[u8])
        -> ClientResult<'c, reply::Sign, Self>
    {
        self.sign(Mechanism::HmacSha256, key, message, SignatureSerialization::Raw)
    }

}

#[cfg(feature = "sha256")]
impl<S: Syscall> Sha256 for ClientImplementation<S> {}

pub trait Sha256: Client {
    fn hash_sha256<'c>(&'c mut self, message: &[u8])
        -> ClientResult<'c, reply::Hash, Self>
    {
        self.hash(Mechanism::Sha256, Message::try_from_slice(message).map_err(|_| ClientError::DataTooLarge)?)
    }
}

#[cfg(feature = "chacha8-poly1305")]
impl<S: Syscall> Chacha8Poly1305 for ClientImplementation<S> {}

pub trait Chacha8Poly1305: Client {
    fn decrypt_chacha8poly1305<'c>(&'c mut self, key: ObjectHandle, message: &[u8], associated_data: &[u8],
                                       nonce: &[u8], tag: &[u8])
        -> ClientResult<'c, reply::Decrypt, Self>
    {
        self.decrypt(Mechanism::Chacha8Poly1305, key, message, associated_data, nonce, tag)
    }

    fn encrypt_chacha8poly1305<'c>(&'c mut self, key: ObjectHandle, message: &[u8], associated_data: &[u8],
                                       nonce: Option<&[u8; 12]>)
        -> ClientResult<'c, reply::Encrypt, Self>
    {
        self.encrypt(Mechanism::Chacha8Poly1305, key, message, associated_data,
            nonce.and_then(|nonce| ShortData::try_from_slice(nonce).ok()))
    }

    fn generate_chacha8poly1305_key(&mut self, persistence: StorageLocation)
        -> ClientResult<'_, reply::GenerateKey, Self>
    {
        self.generate_key(Mechanism::Chacha8Poly1305, StorageAttributes::new().set_persistence(persistence))
    }

    fn unwrap_key_chacha8poly1305<'c>(&'c mut self, wrapping_key: ObjectHandle, wrapped_key: &[u8],
                       associated_data: &[u8], location: StorageLocation)
        -> ClientResult<'c, reply::UnwrapKey, Self>
    {
        self.unwrap_key(Mechanism::Chacha8Poly1305, wrapping_key,
                        Message::try_from_slice(wrapped_key).map_err(|_| ClientError::DataTooLarge)?,
                        associated_data,
                        StorageAttributes::new().set_persistence(location))
    }

    fn wrap_key_chacha8poly1305<'c>(&'c mut self, wrapping_key: ObjectHandle, key: ObjectHandle,
                       associated_data: &[u8])
        -> ClientResult<'c, reply::WrapKey, Self>
    {
        self.wrap_key(Mechanism::Chacha8Poly1305, wrapping_key, key, associated_data)
    }
}

#[cfg(feature = "aes256-cbc")]
impl<S: Syscall> Aes256Cbc for ClientImplementation<S> {}

pub trait Aes256Cbc: Client {
    fn decrypt_aes256cbc<'c>(&'c mut self, key: ObjectHandle, message: &[u8])
        -> ClientResult<'c, reply::Decrypt, Self>
    {
        self.decrypt(
            Mechanism::Aes256Cbc, key, message, &[], &[], &[],
        )
    }

    fn wrap_key_aes256cbc(&mut self, wrapping_key: ObjectHandle, key: ObjectHandle)
        -> ClientResult<'_, reply::WrapKey, Self>
    {
        self.wrap_key(Mechanism::Aes256Cbc, wrapping_key, key, &[])
    }
}

#[cfg(feature = "tdes")]
impl<S: Syscall> Tdes for ClientImplementation<S> {}

pub trait Tdes: Client {
    fn decrypt_tdes<'c>(&'c mut self, key: ObjectHandle, message: &[u8])
        -> ClientResult<'c, reply::Decrypt, Self>
    {
        self.decrypt(Mechanism::Tdes, key, message, &[], &[], &[])
    }

    fn encrypt_tdes<'c>(&'c mut self, key: ObjectHandle, message: &[u8])
        -> ClientResult<'c, reply::Encrypt, Self>
    {
        self.encrypt(Mechanism::Tdes, key, message, &[], None)
    }

    fn unsafe_inject_tdes_key<'c>(&'c mut self, raw_key: &[u8; 24], persistence: StorageLocation)
        -> ClientResult<'c, reply::UnsafeInjectKey, Self>
    {
        self.unsafe_inject_key(Mechanism::Tdes, raw_key, persistence)
    }
}

#[cfg(feature = "totp")]
impl<S: Syscall> Totp for ClientImplementation<S> {}

pub trait Totp: Client {
    fn sign_totp(&mut self, key: ObjectHandle, timestamp: u64)
        -> ClientResult<'_, reply::Sign, Self>
    {
        self.sign(Mechanism::Totp, key,
            &timestamp.to_le_bytes().as_ref(),
            SignatureSerialization::Raw,
        )
    }

    fn unsafe_inject_totp_key<'c>(&'c mut self, raw_key: &[u8; 20], persistence: StorageLocation)
        -> ClientResult<'c, reply::UnsafeInjectKey, Self>
    {
        self.unsafe_inject_key(Mechanism::Totp, raw_key, persistence)
    }
}

/// Trussed Client interface that Trussed apps can rely on.
pub trait Client {
    fn poll(&mut self) -> core::task::Poll<core::result::Result<Reply, Error>>;

    // call with any of `crate::api::request::*`
    // fn request<'c>(&'c mut self, req: impl Into<Request>)
        // -> core::result::Result<RawFutureResult<'c, Self>, ClientError>;

    fn agree(
        &mut self, mechanism: Mechanism,
        private_key: ObjectHandle, public_key: ObjectHandle,
        attributes: StorageAttributes,
        )
        -> ClientResult<'_, reply::Agree, Self>;

    fn derive_key(&mut self, mechanism: Mechanism, base_key: ObjectHandle, attributes: StorageAttributes)
        -> ClientResult<'_, reply::DeriveKey, Self>;


    fn encrypt<'c>(&'c mut self, mechanism: Mechanism, key: ObjectHandle,
                       message: &[u8], associated_data: &[u8], nonce: Option<ShortData>)
        -> ClientResult<'c, reply::Encrypt, Self>;

    fn decrypt<'c>(&'c mut self, mechanism: Mechanism, key: ObjectHandle,
                       message: &[u8], associated_data: &[u8],
                       nonce: &[u8], tag: &[u8],
                       )
        -> ClientResult<'c, reply::Decrypt, Self>;

    fn deserialize_key<'c>(&'c mut self, mechanism: Mechanism, serialized_key: &[u8],
                               format: KeySerialization, attributes: StorageAttributes)
        -> ClientResult<'c, reply::DeserializeKey, Self>;


    fn delete(&mut self, key: ObjectHandle)
        -> ClientResult<'_, reply::Delete, Self>;

    fn debug_dump_store(&mut self)
        -> ClientResult<'_, reply::DebugDumpStore, Self>;

    fn exists(&mut self, mechanism: Mechanism, key: ObjectHandle)
        -> ClientResult<'_, reply::Exists, Self>;

    fn generate_key(&mut self, mechanism: Mechanism, attributes: StorageAttributes)
        -> ClientResult<'_, reply::GenerateKey, Self>;

    fn read_dir_first(
        &mut self,
        location: StorageLocation,
        dir: PathBuf,
        not_before_filename: Option<PathBuf>,
    )
        -> ClientResult<'_, reply::ReadDirFirst, Self>;

    fn read_dir_next(&mut self)
        -> ClientResult<'_, reply::ReadDirNext, Self>;

    fn read_dir_files_first(
        &mut self,
        location: StorageLocation,
        dir: PathBuf,
        user_attribute: Option<UserAttribute>,
    )
        -> ClientResult<'_, reply::ReadDirFilesFirst, Self>;

    fn read_dir_files_next(&mut self)
        -> ClientResult<'_, reply::ReadDirFilesNext, Self>;

    fn remove_dir(&mut self, location: StorageLocation, path: PathBuf)
        -> ClientResult<'_, reply::RemoveFile, Self>;

    fn remove_file(&mut self, location: StorageLocation, path: PathBuf)
        -> ClientResult<'_, reply::RemoveFile, Self>;

    fn read_file(&mut self, location: StorageLocation, path: PathBuf)
        -> ClientResult<'_, reply::ReadFile, Self>;

    fn locate_file(&mut self, location: StorageLocation, dir: Option<PathBuf>, filename: PathBuf)
        -> ClientResult<'_, reply::LocateFile, Self>;

    fn write_file(
        &mut self,
        location: StorageLocation,
        path: PathBuf,
        data: Message,
        user_attribute: Option<UserAttribute>,
        )
        -> ClientResult<'_, reply::WriteFile, Self>;

          // - mechanism: Mechanism
          // - key: ObjectHandle
          // - format: KeySerialization

    fn serialize_key(&mut self, mechanism: Mechanism, key: ObjectHandle, format: KeySerialization)
        -> ClientResult<'_, reply::SerializeKey, Self>;

    fn sign<'c>(
        &'c mut self,
        mechanism: Mechanism,
        key: ObjectHandle,
        data: &[u8],
        format: SignatureSerialization,
    )
        -> ClientResult<'c, reply::Sign, Self>;

    fn verify<'c>(
        &'c mut self,
        mechanism: Mechanism,
        key: ObjectHandle,
        message: &[u8],
        signature: &[u8],
        format: SignatureSerialization,
    )
        -> ClientResult<'c, reply::Verify, Self>;

    fn random_bytes(&mut self, count: usize)
        -> ClientResult<'_, reply::RandomByteBuf, Self>;

    fn hash(&mut self, mechanism: Mechanism, message: Message)
        -> ClientResult<'_, reply::Hash, Self>;

    fn unwrap_key<'c>(&'c mut self, mechanism: Mechanism, wrapping_key: ObjectHandle, wrapped_key: Message,
                       associated_data: &[u8], attributes: StorageAttributes)
        -> ClientResult<'c, reply::UnwrapKey, Self>;

    fn wrap_key(&mut self, mechanism: Mechanism, wrapping_key: ObjectHandle, key: ObjectHandle,
                       associated_data: &[u8])
        -> ClientResult<'_, reply::WrapKey, Self>;

    fn unsafe_inject_key<'c>(&'c mut self, mechanism: Mechanism, raw_key: &[u8], persistence: StorageLocation)
        -> ClientResult<'c, reply::UnsafeInjectKey, Self>;

    fn confirm_user_present(&mut self, timeout_milliseconds: u32)
        -> ClientResult<'_, reply::RequestUserConsent, Self>;

    fn reboot(&mut self, to: reboot::To)
        -> ClientResult<'_, reply::Reboot, Self>;

}

// would be interesting to use proper futures, and something like
// https://github.com/dflemstr/direct-executor/blob/master/src/lib.rs#L62-L66

#[macro_export]
macro_rules! block {
    ($future_result:expr) => {{
        // evaluate the expression
        let mut future_result = $future_result;
        loop {
            match future_result.poll() {
                core::task::Poll::Ready(result) => { break result; },
                core::task::Poll::Pending => {},
            }
        }
    }}
}

#[macro_export]
macro_rules! syscall {
    ($pre_future_result:expr) => {{
        // evaluate the expression
        let mut future_result = $pre_future_result.expect("no client error");
        loop {
            match future_result.poll() {
                core::task::Poll::Ready(result) => { break result.expect("no errors"); },
                core::task::Poll::Pending => {},
            }
        }
    }}
}

#[macro_export]
macro_rules! try_syscall {
    ($pre_future_result:expr) => {{
        // evaluate the expression
        let mut future_result = $pre_future_result.expect("no client error");
        loop {
            match future_result.poll() {
                core::task::Poll::Ready(result) => { break result; },
                core::task::Poll::Pending => {},
            }
        }
    }}
}

pub struct FutureResult<'c, T, C: ?Sized>
where C: Client
{
    client: &'c mut C,
    __: PhantomData<T>,
}

impl<'c,T, C> FutureResult<'c, T, C>
where
    T: From<crate::api::Reply>,
    C: Client,
{
    pub fn new(client: &'c mut C) -> Self {
        Self { client, __: PhantomData}
    }
    pub fn poll(&mut self)
        -> core::task::Poll<core::result::Result<T, Error>>
    {
        use core::task::Poll::{Pending, Ready};
        match self.client.poll() {
            Ready(Ok(reply)) => Ready(Ok(T::from(reply))),
            Ready(Err(error)) => Ready(Err(error)),
            Pending => Pending
        }
    }

}

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
where S: Syscall
{
    pub fn new(interchange: Requester<TrussedInterchange>, syscall: S) -> Self {
        Self { interchange, pending: None, syscall }
    }

    // call with any of `crate::api::request::*`
    pub fn request<T: From<crate::api::Reply>>(&mut self, req: impl Into<Request>)
        // -> core::result::Result<FutureResult<'c, T, Client<S>>, ClientError>
        -> ClientResult<'_, T, Self>
    {
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
        self.interchange.request(request).map_err(drop).unwrap();
        Ok(FutureResult::new(self))
    }
}

impl<S> Client for ClientImplementation<S>
where S: Syscall {

    fn poll(&mut self)
        -> core::task::Poll<core::result::Result<Reply, Error>>
    {
        match self.interchange.take_response() {
            Some(reply) => {
                // #[cfg(all(test, feature = "verbose-tests"))]
                // println!("got a reply: {:?}", &reply);
                match reply {
                    Ok(reply) => {
                        if Some(u8::from(&reply)) == self.pending {
                            self.pending = None;
                            core::task::Poll::Ready(Ok(reply))
                        } else  {
                            // #[cfg(all(test, feature = "verbose-tests"))]
                            info!("got: {:?}, expected: {:?}", Some(u8::from(&reply)), self.pending);
                            core::task::Poll::Ready(Err(Error::InternalError))
                        }
                    }
                    Err(error) => {
                        self.pending = None;
                        core::task::Poll::Ready(Err(error))
                    }
                }

            },
            None => core::task::Poll::Pending
        }
    }

    fn agree(
        &mut self, mechanism: Mechanism,
        private_key: ObjectHandle, public_key: ObjectHandle,
        attributes: StorageAttributes,
        )
        -> ClientResult<'_, reply::Agree, Self>
    {
        let r = self.request(request::Agree {
            mechanism,
            private_key,
            public_key,
            attributes,
        })?;
        r.client.syscall.syscall();
        Ok(r)
    }

    fn derive_key(&mut self, mechanism: Mechanism, base_key: ObjectHandle, attributes: StorageAttributes)
        -> ClientResult<'_, reply::DeriveKey, Self>
    {
        let r = self.request(request::DeriveKey {
            mechanism,
            base_key,
            attributes,
        })?;
        r.client.syscall.syscall();
        Ok(r)
    }

          // - mechanism: Mechanism
          // - key: ObjectHandle
          // - message: Message
          // - associated_data: ShortData
    fn encrypt<'c>(&'c mut self, mechanism: Mechanism, key: ObjectHandle,
                       message: &[u8], associated_data: &[u8], nonce: Option<ShortData>)
        -> ClientResult<'c, reply::Encrypt, Self>
    {
        let message = Message::try_from_slice(message).map_err(|_| ClientError::DataTooLarge)?;
        let associated_data = ShortData::try_from_slice(associated_data).map_err(|_| ClientError::DataTooLarge)?;
        let r = self.request(request::Encrypt { mechanism, key, message, associated_data, nonce })?;
        r.client.syscall.syscall();
        Ok(r)
    }

          // - mechanism: Mechanism
          // - key: ObjectHandle
          // - message: Message
          // - associated_data: ShortData
          // - nonce: ShortData
          // - tag: ShortData
    fn decrypt<'c>(&'c mut self, mechanism: Mechanism, key: ObjectHandle,
                       message: &[u8], associated_data: &[u8],
                       nonce: &[u8], tag: &[u8],
                       )
        -> ClientResult<'c, reply::Decrypt, Self>
    {
        let message = Message::try_from_slice(message).map_err(|_| ClientError::DataTooLarge)?;
        let associated_data = Message::try_from_slice(associated_data).map_err(|_| ClientError::DataTooLarge)?;
        let nonce = ShortData::try_from_slice(nonce).map_err(|_| ClientError::DataTooLarge)?;
        let tag = ShortData::try_from_slice(tag).map_err(|_| ClientError::DataTooLarge)?;
        let r = self.request(request::Decrypt { mechanism, key, message, associated_data, nonce, tag })?;
        r.client.syscall.syscall();
        Ok(r)
    }

    fn deserialize_key<'c>(&'c mut self, mechanism: Mechanism, serialized_key: &[u8],
                               format: KeySerialization, attributes: StorageAttributes)
        -> ClientResult<'c, reply::DeserializeKey, Self>
    {
        let serialized_key = Message::try_from_slice(serialized_key).map_err(|_| ClientError::DataTooLarge)?;
        let r = self.request(request::DeserializeKey {
            mechanism, serialized_key, format, attributes
        } )?;
        r.client.syscall.syscall();
        Ok(r)
    }

    fn delete(&mut self, key: ObjectHandle)
        -> ClientResult<'_, reply::Delete, Self>
    {
        let r = self.request(request::Delete {
            key,
            // mechanism,
        })?;
        r.client.syscall.syscall();
        Ok(r)
    }

    fn debug_dump_store(&mut self)
        -> ClientResult<'_, reply::DebugDumpStore, Self>
    {
        let r = self.request(request::DebugDumpStore {})?;
        r.client.syscall.syscall();
        Ok(r)
    }

    fn exists(&mut self, mechanism: Mechanism, key: ObjectHandle)
        -> ClientResult<'_, reply::Exists, Self>
    {
        let r = self.request(request::Exists {
            key,
            mechanism,
        })?;
        r.client.syscall.syscall();
        Ok(r)
    }

    fn generate_key(&mut self, mechanism: Mechanism, attributes: StorageAttributes)
        -> ClientResult<'_, reply::GenerateKey, Self>
    {
        let r = self.request(request::GenerateKey {
            mechanism,
            attributes,
        })?;
        r.client.syscall.syscall();
        Ok(r)
    }

    fn read_dir_first(
        &mut self,
        location: StorageLocation,
        dir: PathBuf,
        not_before_filename: Option<PathBuf>,
    )
        -> ClientResult<'_, reply::ReadDirFirst, Self>
    {
        let r = self.request(request::ReadDirFirst { location, dir, not_before_filename } )?;
        r.client.syscall.syscall();
        Ok(r)
    }

    fn read_dir_next(
        &mut self,
    )
        -> ClientResult<'_, reply::ReadDirNext, Self>
    {
        let r = self.request(request::ReadDirNext {} )?;
        r.client.syscall.syscall();
        Ok(r)
    }

    fn read_dir_files_first(
        &mut self,
        location: StorageLocation,
        dir: PathBuf,
        user_attribute: Option<UserAttribute>,
    )
        -> ClientResult<'_, reply::ReadDirFilesFirst, Self>
    {
        let r = self.request(request::ReadDirFilesFirst { dir, location, user_attribute } )?;
        r.client.syscall.syscall();
        Ok(r)
    }

    fn read_dir_files_next(&mut self)
        -> ClientResult<'_, reply::ReadDirFilesNext, Self>
    {
        let r = self.request(request::ReadDirFilesNext {} )?;
        r.client.syscall.syscall();
        Ok(r)
    }

    fn remove_dir(&mut self, location: StorageLocation, path: PathBuf)
        -> ClientResult<'_, reply::RemoveFile, Self>
    {
        let r = self.request(request::RemoveDir { location, path } )?;
        r.client.syscall.syscall();
        Ok(r)
    }

    fn remove_file(&mut self, location: StorageLocation, path: PathBuf)
        -> ClientResult<'_, reply::RemoveFile, Self>
    {
        let r = self.request(request::RemoveFile { location, path } )?;
        r.client.syscall.syscall();
        Ok(r)
    }

    fn read_file(&mut self, location: StorageLocation, path: PathBuf)
        -> ClientResult<'_, reply::ReadFile, Self>
    {
        let r = self.request(request::ReadFile { location, path } )?;
        r.client.syscall.syscall();
        Ok(r)
    }

    fn locate_file(&mut self, location: StorageLocation, dir: Option<PathBuf>, filename: PathBuf)
        -> ClientResult<'_, reply::LocateFile, Self>
    {
        let r = self.request(request::LocateFile { location, dir, filename } )?;
        r.client.syscall.syscall();
        Ok(r)
    }

    fn write_file(
        &mut self,
        location: StorageLocation,
        path: PathBuf,
        data: Message,
        user_attribute: Option<UserAttribute>,
        )
        -> ClientResult<'_, reply::WriteFile, Self>
    {
        let r = self.request(request::WriteFile {
            location, path, data,
            user_attribute,
        } )?;
        r.client.syscall.syscall();
        Ok(r)
    }

    fn serialize_key(&mut self, mechanism: Mechanism, key: ObjectHandle, format: KeySerialization)
        -> ClientResult<'_, reply::SerializeKey, Self>
    {
        let r = self.request(request::SerializeKey {
            key,
            mechanism,
            format,
        })?;
        r.client.syscall.syscall();
        Ok(r)
    }

    fn sign<'c>(
        &'c mut self,
        mechanism: Mechanism,
        key: ObjectHandle,
        data: &[u8],
        format: SignatureSerialization,
    )
        -> ClientResult<'c, reply::Sign, Self>
    {
        let r = self.request(request::Sign {
            key,
            mechanism,
            message: ByteBuf::try_from_slice(data).map_err(|_| ClientError::DataTooLarge)?,
            format,
        })?;
        r.client.syscall.syscall();
        Ok(r)
    }

    fn verify<'c>(
        &'c mut self,
        mechanism: Mechanism,
        key: ObjectHandle,
        message: &[u8],
        signature: &[u8],
        format: SignatureSerialization,
    )
        -> ClientResult<'c, reply::Verify, Self>
    {
        let r = self.request(request::Verify {
            mechanism,
            key,
            message: Message::try_from_slice(&message).expect("all good"),
            signature: Signature::try_from_slice(&signature).expect("all good"),
            format,
        })?;
        r.client.syscall.syscall();
        Ok(r)
    }


    fn random_bytes(&mut self, count: usize)
        -> ClientResult<'_, reply::RandomByteBuf, Self>
    {
        let r = self.request(request::RandomByteBuf { count } )?;
        r.client.syscall.syscall();
        Ok(r)
    }

    fn hash(&mut self, mechanism: Mechanism, message: Message)
        -> ClientResult<'_, reply::Hash, Self>
    {
        let r = self.request(request::Hash { mechanism, message } )?;
        r.client.syscall.syscall();
        Ok(r)
    }


          // - mechanism: Mechanism
          // - wrapping_key: ObjectHandle
          // - wrapped_key: Message
          // - associated_data: Message
    fn unwrap_key<'c>(&'c mut self, mechanism: Mechanism, wrapping_key: ObjectHandle, wrapped_key: Message,
                       associated_data: &[u8], attributes: StorageAttributes)
        -> ClientResult<'c, reply::UnwrapKey, Self>
    {
        let associated_data = Message::try_from_slice(associated_data).map_err(|_| ClientError::DataTooLarge)?;
        let r = self.request(request::UnwrapKey {
            mechanism,
            wrapping_key,
            wrapped_key,
            associated_data,
            attributes
        })?;
        r.client.syscall.syscall();
        Ok(r)
    }

          // - mechanism: Mechanism
          // - wrapping_key: ObjectHandle
          // - key: ObjectHandle
          // - associated_data: Message
    fn wrap_key(&mut self, mechanism: Mechanism, wrapping_key: ObjectHandle, key: ObjectHandle,
                       associated_data: &[u8])
        -> ClientResult<'_, reply::WrapKey, Self>
    {
        let associated_data = Message::try_from_slice(associated_data).map_err(|_| ClientError::DataTooLarge)?;
        let r = self.request(request::WrapKey { mechanism, wrapping_key, key, associated_data })?;
        r.client.syscall.syscall();
        Ok(r)
    }

    fn unsafe_inject_key(&mut self, mechanism: Mechanism, raw_key: &[u8], persistence: StorageLocation)
        -> ClientResult<'_, reply::UnsafeInjectKey, Self>
    {
        let r = self.request(request::UnsafeInjectKey {
            mechanism,
            raw_key: ShortData::try_from_slice(raw_key).unwrap(),
            attributes: StorageAttributes::new().set_persistence(persistence),
        })?;
        r.client.syscall.syscall();
        Ok(r)
    }

    fn confirm_user_present(&mut self, timeout_milliseconds: u32)
        -> ClientResult<'_, reply::RequestUserConsent, Self>
    {
        let r = self.request(request::RequestUserConsent {
            level: consent::Level::Normal,
            timeout_milliseconds,
        } )?;
        r.client.syscall.syscall();
        Ok(r)
    }

    fn reboot(&mut self, to: reboot::To)
        -> ClientResult<'_, reply::Reboot, Self>
    {
        let r = self.request(request::Reboot { to })?;
        r.client.syscall.syscall();
        Ok(r)
    }

}
