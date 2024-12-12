//! Extensions to the core Trussed syscalls.
//!
//! *Requires the `serde-extensions` feature.*
//!
//! This module makes it possible to add additional syscalls to Trussed by implementing the
//! [`Extension`][] trait.  Extension requests and replies are serialized to
//! [`Request::SerdeExtension`][] and [`Reply::SerdeExtension`][].
//!
//! [`Request::SerdeExtension`]: `crate::api::Request::SerdeExtension`
//! [`Reply::SerdeExtension`]: `crate::api::Reply::SerdeExtension`

use core::{marker::PhantomData, task::Poll};

use serde::{de::DeserializeOwned, Serialize};

use crate::{
    api::{reply, request},
    client::{ClientError, FutureResult, PollClient},
    error::Error,
    types::Bytes,
};

/// A Trussed API extension.
pub trait Extension {
    /// The requests supported by this extension.
    type Request: DeserializeOwned + Serialize;
    /// The replies supported by this extension.
    type Reply: DeserializeOwned + Serialize;

    /// Serialize an extension request.
    ///
    /// Requests that are serialized with this function can be deserialized with
    /// [`Extension::deserialize_request`][].  The format is not guaranteed to be stable over
    /// crate releases.
    #[inline(never)]
    fn serialize_request(
        id: u8,
        request: &Self::Request,
    ) -> Result<request::SerdeExtension, ClientError> {
        postcard::to_vec(request)
            .map(Bytes::from)
            .map(|request| request::SerdeExtension { id, request })
            .map_err(|_| ClientError::SerializationFailed)
    }

    /// Deserialize an extension request.
    ///
    /// This function can be used to deserialize requests that have been serialized with
    /// [`Extension::serialize_request`][].  The format is not guaranteed to be stable over
    /// crate releases.
    #[inline(never)]
    fn deserialize_request(request: &request::SerdeExtension) -> Result<Self::Request, Error> {
        postcard::from_bytes(&request.request).map_err(|_| Error::InvalidSerializedRequest)
    }

    /// Serialize an extension reply.
    ///
    /// Replies that are serialized with this function can be deserialized with
    /// [`Extension::deserialize_reply`][].  The format is not guaranteed to be stable over
    /// crate releases.
    #[inline(never)]
    fn serialize_reply(reply: &Self::Reply) -> Result<reply::SerdeExtension, Error> {
        postcard::to_vec(reply)
            .map(Bytes::from)
            .map(|reply| reply::SerdeExtension { reply })
            .map_err(|_| Error::ReplySerializationFailure)
    }

    /// Deserialize an extension reply.
    ///
    /// This function can be used to deserialize replies that have been serialized with
    /// [`Extension::serialize_reply`][].  The format is not guaranteed to be stable over
    /// crate releases.
    #[inline(never)]
    fn deserialize_reply(reply: &reply::SerdeExtension) -> Result<Self::Reply, Error> {
        postcard::from_bytes(&reply.reply).map_err(|_| Error::InvalidSerializedReply)
    }
}

/// Executes extension requests.
///
/// Instead of using this trait directly, extensions should define their own traits that extend
/// this trait and use the `extension` function to execute extension requests.
pub trait ExtensionClient<E: Extension>: PollClient {
    /// Returns the ID for the `E` extension as defined by the runner.
    fn id() -> u8;

    /// Executes an extension request.
    ///
    /// Applications should not call this method directly and instead use a trait provided by the
    /// extension.
    fn extension<Rq, Rp>(&mut self, request: Rq) -> ExtensionResult<'_, E, Rp, Self>
    where
        Rq: Into<E::Request>,
        Rp: TryFrom<E::Reply, Error = Error>,
    {
        let request = E::serialize_request(Self::id(), &request.into())?;
        self.request(request).map(From::from)
    }
}

/// A result returned by [`ExtensionClient`][] and clients using it.
pub type ExtensionResult<'a, E, T, C> = Result<ExtensionFutureResult<'a, E, T, C>, ClientError>;

#[must_use = "Syscalls must be polled with the `syscall` macro"]
/// A future of an [`ExtensionResult`][].
pub struct ExtensionFutureResult<'c, E, T, C: ?Sized> {
    client: &'c mut C,
    __: PhantomData<(E, T)>,
}

impl<'c, E, T, C: ?Sized> ExtensionFutureResult<'c, E, T, C> {
    fn new(client: &'c mut C) -> Self {
        Self {
            client,
            __: PhantomData,
        }
    }
}

impl<E, T, C> ExtensionFutureResult<'_, E, T, C>
where
    E: Extension,
    T: TryFrom<E::Reply, Error = Error>,
    C: PollClient,
{
    pub fn poll(&mut self) -> Poll<Result<T, Error>> {
        self.client.poll().map(|result| {
            result.and_then(|reply| {
                let reply = reply::SerdeExtension::try_from(reply)?;
                let reply: E::Reply = E::deserialize_reply(&reply)?;
                reply.try_into()
            })
        })
    }
}

impl<'c, E, T, C> From<FutureResult<'c, reply::SerdeExtension, C>>
    for ExtensionFutureResult<'c, E, T, C>
where
    C: PollClient + ?Sized,
{
    fn from(result: FutureResult<'c, reply::SerdeExtension, C>) -> Self {
        Self::new(result.client)
    }
}
