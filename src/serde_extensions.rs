//! Extensions to the core Trussed syscalls.
//!
//! *Requires the `serde-extensions` feature.*
//!
//! This module makes it possible to add additional syscalls to Trussed by implementing the
//! [`Extension`][] trait.  Extension requests and replies are serialized to
//! [`Request::SerdeExtension`][] and [`Reply::SerdeExtension`][].  Backends can implement the
//! [`ExtensionImpl`][] trait to support an extension.
//!
//! A runner can use multiple extensions.  To identify the extensions, the runner has to assign IDs
//! to the extension and declare them using the [`ExtensionId`][] trait.  Runners that want to use
//! extensions have to implement the [`ExtensionDispatch`][] trait instead of [`Dispatch`][].
//!
//! See `tests/serde_extensions.rs` for an example.

use crate::{
    api::{reply, request, Reply, Request},
    backend::{Backend, CoreOnly, Dispatch, NoId, OptionalBackend},
    client::ClientImplementation,
    error::Error,
    platform::{Platform, Syscall},
    service::ServiceResources,
    types::{self, Context, CoreContext},
};

pub use trussed_core::serde_extensions::{
    Extension, ExtensionClient, ExtensionFutureResult, ExtensionResult,
};

/// Dispatches extension requests to custom backends.
pub trait ExtensionDispatch {
    /// The ID type for the custom backends used by this dispatch implementation.
    type BackendId: 'static;
    /// The context type used by this dispatch.
    type Context: Default;
    /// The ID type for the extensions supported by this dispatch implementation.
    type ExtensionId: TryFrom<u8, Error = Error>;

    /// Executes a request using a backend or returns [`Error::RequestNotAvailable`][] if it is not
    /// supported by the backend.
    fn core_request<P: Platform>(
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
    fn extension_request<P: Platform>(
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

impl<T: ExtensionDispatch> Dispatch for T {
    type BackendId = T::BackendId;
    type Context = T::Context;

    fn request<P: Platform>(
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

impl ExtensionDispatch for CoreOnly {
    type BackendId = NoId;
    type Context = types::NoData;
    type ExtensionId = NoId;
}

/// Implements an extension for a backend.
pub trait ExtensionImpl<E: Extension>: Backend {
    /// Handles an extension request.
    fn extension_request<P: Platform>(
        &mut self,
        core_ctx: &mut CoreContext,
        backend_ctx: &mut Self::Context,
        request: &E::Request,
        resources: &mut ServiceResources<P>,
    ) -> Result<E::Reply, Error>;

    /// Handles an extension request and performs the necessary serialization and deserialization
    /// between [`request::SerdeExtension`][] and [`Extension::Request`][] as well as
    /// [`reply::SerdeExtension`][] and [`Extension::Reply`][].
    fn extension_request_serialized<P: Platform>(
        &mut self,
        core_ctx: &mut CoreContext,
        backend_ctx: &mut Self::Context,
        request: &request::SerdeExtension,
        resources: &mut ServiceResources<P>,
    ) -> Result<reply::SerdeExtension, Error> {
        let request = E::deserialize_request(request)?;
        let reply = self.extension_request(core_ctx, backend_ctx, &request, resources)?;
        E::serialize_reply(&reply)
    }
}

impl<E: Extension, I: ExtensionImpl<E>> ExtensionImpl<E> for OptionalBackend<I> {
    fn extension_request<P: Platform>(
        &mut self,
        core_ctx: &mut CoreContext,
        backend_ctx: &mut Self::Context,
        request: &E::Request,
        resources: &mut ServiceResources<P>,
    ) -> Result<E::Reply, Error> {
        self.inner()?
            .extension_request(core_ctx, backend_ctx, request, resources)
    }
}

/// Provides access to the extension IDs assigned by the runner.
pub trait ExtensionId<E> {
    /// The ID type used by the runner.
    type Id: Into<u8>;

    /// The ID assigned to the `E` extension.
    const ID: Self::Id;
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
