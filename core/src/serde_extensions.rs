//! Extensions to the core Trussed syscalls.
//!
//! *Requires the `serde-extensions` feature.*
//!
//! This module makes it possible to add additional syscalls to Trussed by implementing the
//! [`Extension`][] trait.  Extension requests and replies are serialized to
//! [`Request::SerdeExtension`][] and [`Reply::SerdeExtension`][].

use core::{marker::PhantomData, task::Poll};

use heapless_bytes::Bytes;
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    api::{reply, request},
    client::{ClientError, FutureResult, PollClient},
    error::Error,
};

// To do: re-export postcard

/// A Trussed API extension.
pub trait Extension {
    /// The requests supported by this extension.
    type Request: DeserializeOwned + Serialize;
    /// The replies supported by this extension.
    type Reply: DeserializeOwned + Serialize;
}

/// A result returned by [`ExtensionClient`][] and clients using it.
pub type ExtensionResult<'a, E, T, C> = Result<ExtensionFutureResult<'a, E, T, C>, ClientError>;

/// Executes extension requests.
///
/// Instead of using this trait directly, extensions should define their own traits that extend
/// this trait and use the `extension` function to execute extension requests.
pub trait ExtensionClient<E: Extension>: PollClient {
    /// Returns the ID for the `E` extension as defined by the runner, see [`ExtensionId`][].
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
        let request =
            postcard::to_vec(&request.into()).map_err(|_| ClientError::SerializationFailed)?;
        self.request(request::SerdeExtension {
            id: Self::id(),
            request: Bytes::from(request),
        })
        .map(From::from)
    }
}

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

impl<'c, E, T, C> ExtensionFutureResult<'c, E, T, C>
where
    E: Extension,
    T: TryFrom<E::Reply, Error = Error>,
    C: PollClient,
{
    pub fn poll(&mut self) -> Poll<Result<T, Error>> {
        self.client.poll().map(|result| {
            result.and_then(|reply| {
                let reply = reply::SerdeExtension::try_from(reply)?;
                let reply: E::Reply = postcard::from_bytes(&reply.reply)
                    .map_err(|_| Error::InvalidSerializedReply)?;
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
