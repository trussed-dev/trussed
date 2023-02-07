use core::{marker::PhantomData, task::Poll};

use crate::{
    api::{reply, request, Reply, Request},
    backend::{Backend, CoreOnly, Dispatch, NoId},
    client::{ClientError, ClientImplementation, FutureResult, PollClient},
    error::Error,
    platform::{Platform, Syscall},
    postcard_deserialize, postcard_serialize_bytes,
    service::ServiceResources,
    types::{self, Context, CoreContext},
};

use serde::{de::DeserializeOwned, Serialize};

pub trait Extension {
    type Request: DeserializeOwned + Serialize;
    type Reply: DeserializeOwned + Serialize;
}

/// Dispatches extension requests to custom backends.
pub trait ExtensionDispatch<P: Platform> {
    /// The ID type for the custom backends used by this dispatch implementation.
    type BackendId: 'static;
    /// The context type used by this dispatch.
    type Context: Default;
    /// The ID type for the extensions supported by this dispatch implementation.
    type ExtensionId: TryFrom<u8, Error = Error>;

    /// Executes a request using a backend or returns [`Error::RequestNotAvailable`][] if it is not
    /// supported by the backend.
    fn core_request(
        &mut self,
        backend: &Self::BackendId,
        ctx: &mut Context<Self::Context>,
        request: &Request,
        resources: &mut ServiceResources<P>,
    ) -> Result<Reply, Error> {
        let _ = (backend, ctx, request, resources);
        Err(Error::RequestNotAvailable)
    }
    /// Executes an extension request using a backend or returns [`Error::RequestNotAvailable`][]
    /// if it is not supported by the backend.
    fn extension_request(
        &mut self,
        backend: &Self::BackendId,
        extension: &Self::ExtensionId,
        ctx: &mut Context<Self::Context>,
        request: &request::SerdeExtension,
        resources: &mut ServiceResources<P>,
    ) -> Result<reply::SerdeExtension, Error> {
        let _ = (backend, extension, ctx, request, resources);
        Err(Error::RequestNotAvailable)
    }
}

impl<P: Platform, T: ExtensionDispatch<P>> Dispatch<P> for T {
    type BackendId = T::BackendId;
    type Context = T::Context;

    fn request(
        &mut self,
        backend: &Self::BackendId,
        ctx: &mut Context<Self::Context>,
        request: &Request,
        resources: &mut ServiceResources<P>,
    ) -> Result<Reply, Error> {
        if let Request::SerdeExtension(request) = &request {
            T::ExtensionId::try_from(request.id)
                .and_then(|extension| {
                    self.extension_request(backend, &extension, ctx, request, resources)
                })
                .map(Reply::SerdeExtension)
        } else {
            self.core_request(backend, ctx, request, resources)
        }
    }
}

impl<P: Platform> ExtensionDispatch<P> for CoreOnly {
    type BackendId = NoId;
    type Context = types::NoData;
    type ExtensionId = NoId;
}

pub trait ExtensionImpl<E: Extension, P: Platform>: Backend<P> {
    fn extension_request(
        &mut self,
        core_ctx: &mut CoreContext,
        backend_ctx: &mut Self::Context,
        request: &E::Request,
        resources: &mut ServiceResources<P>,
    ) -> Result<E::Reply, Error>;

    fn extension_request_serialized(
        &mut self,
        core_ctx: &mut CoreContext,
        backend_ctx: &mut Self::Context,
        request: &request::SerdeExtension,
        resources: &mut ServiceResources<P>,
    ) -> Result<reply::SerdeExtension, Error> {
        let request =
            postcard_deserialize(&request.request).map_err(|_| Error::InvalidSerializedRequest)?;
        let reply = self.extension_request(core_ctx, backend_ctx, &request, resources)?;
        postcard_serialize_bytes(&reply)
            .map(|reply| reply::SerdeExtension { reply })
            .map_err(|_| Error::ReplySerializationFailure)
    }
}

pub trait ExtensionId<E> {
    type Id: Into<u8>;

    const ID: Self::Id;
}

pub trait ExtensionClient<E: Extension>: PollClient {
    fn id() -> u8;

    fn extension<Rq, Rp>(&mut self, request: Rq) -> ExtensionResult<'_, E, Rp, Self>
    where
        Rq: Into<E::Request>,
        Rp: TryFrom<E::Reply, Error = Error>,
    {
        self.request(request::SerdeExtension {
            id: Self::id(),
            request: postcard_serialize_bytes(&request.into())
                .map_err(|_| ClientError::SerializationFailed)?,
        })
        .map(From::from)
    }
}

impl<E, S, I> ExtensionClient<E> for ClientImplementation<S, I>
where
    E: Extension,
    S: Syscall,
    I: ExtensionId<E>,
{
    fn id() -> u8 {
        I::ID.into()
    }
}

pub type ExtensionResult<'a, E, T, C> = Result<ExtensionFutureResult<'a, E, T, C>, ClientError>;

pub struct ExtensionFutureResult<'c, E, T, C: ?Sized> {
    client: &'c mut C,
    __: PhantomData<(E, T)>,
}

impl<'c, E, T, C: ?Sized> ExtensionFutureResult<'c, E, T, C> {
    pub fn new(client: &'c mut C) -> Self {
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
                let reply: E::Reply = postcard_deserialize(&reply.reply)
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
