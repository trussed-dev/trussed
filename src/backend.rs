//! Custom backends that can override core request implementations.
//!
//! Trussed provides a default implementation for all [`Request`][]s, the core backend.  Runners
//! can add custom [`Backend`][] implementations using the [`Dispatch`][] trait that can override
//! the implementation of one or more requests.  The backends used to execute a request can be
//! selected per client when constructing a client using
//! [`ClientBuilder::backends`][`crate::client::ClientBuilder::backends`].

use crate::{
    api::{Reply, Request},
    error::Error,
    platform::Platform,
    service::ServiceResources,
    types::{Context, CoreContext, Empty, NoData},
};

/// The ID of a backend.
///
/// This ID can refer to the core backend provided by the Trussed crate, or to a custom backend
/// defined by the runner.  The custom ID type is defined by [`Dispatch::BackendId`][].
pub enum BackendId<I> {
    Core,
    Custom(I),
}

/// A custom backend that can override the core request implementations.
pub trait Backend<P: Platform> {
    /// The context for requests handled by this backend.
    type Context: Default;

    /// Executes a request using this backend or returns [`Error::RequestNotAvailable`][] if it is
    /// not supported by this backend.
    fn request(
        &mut self,
        core_ctx: &mut CoreContext,
        backend_ctx: &mut Self::Context,
        request: &Request,
        resources: &mut ServiceResources<P>,
    ) -> Result<Reply, Error> {
        let _ = (core_ctx, backend_ctx, request, resources);
        Err(Error::RequestNotAvailable)
    }
}

/// Dispatches requests to custom backends.
///
/// If a runner does not support custom backends, it can use the [`CoreOnly`][] dispatch.
/// Otherwise it can provide an implementation of this trait that defines which backends are
/// supported.  The backends that are used to execute a request can be selected when constructing a
/// client using [`ClientBuilder::backends`][`crate::client::ClientBuilder::backends`].
pub trait Dispatch<P: Platform> {
    /// The ID type for the custom backends used by this dispatch implementation.
    type BackendId: 'static;
    /// The context type used by this dispatch.
    type Context: Default;

    /// Executes a request using a backend or returns [`Error::RequestNotAvailable`][] if it is not
    /// supported by the backend.
    fn request(
        &mut self,
        backend: &Self::BackendId,
        ctx: &mut Context<Self::Context>,
        request: &Request,
        resources: &mut ServiceResources<P>,
    ) -> Result<Reply, Error> {
        let _ = (backend, ctx, request, resources);
        Err(Error::RequestNotAvailable)
    }
}

/// Always dispatches to the Trussed core backend.
#[derive(Debug, Default)]
pub struct CoreOnly;

impl<P: Platform> Dispatch<P> for CoreOnly {
    type BackendId = Empty;
    type Context = NoData;
}