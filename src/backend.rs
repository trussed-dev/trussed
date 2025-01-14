//! Custom backends that can override core request implementations.
//!
//! Trussed provides a default implementation for all [`Request`][]s, the core backend.  Runners
//! can add custom [`Backend`][] implementations using the [`Dispatch`][] trait that can override
//! the implementation of one or more requests.  The backends used to execute a request can be
//! selected per client when constructing the [`ServiceEndpoint`][`crate::pipe::ServiceEndpoint`].
//!
//! Backends can also implement API extensions to provide additional syscalls (see the
//! [`serde_extensions`][`crate::serde_extensions`] module).

use crate::{
    api::{Reply, Request},
    error::Error,
    platform::Platform,
    service::ServiceResources,
    types::{Context, CoreContext},
};

/// The ID of a backend.
///
/// This ID can refer to the core backend provided by the Trussed crate, or to a custom backend
/// defined by the runner.  The custom ID type is defined by [`Dispatch::BackendId`][].
#[derive(Debug, Clone)]
pub enum BackendId<I> {
    Core,
    Custom(I),
}

/// A custom backend that can override the core request implementations.
pub trait Backend {
    /// The context for requests handled by this backend.
    type Context: Default;

    /// Executes a request using this backend or returns [`Error::RequestNotAvailable`][] if it is
    /// not supported by this backend.
    fn request<P: Platform>(
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
/// supported.  The backends that are used to execute a request can be selected when constructing
/// the [`ServiceEndpoint`][`crate::pipe::ServiceEndpoint`] for the client.
pub trait Dispatch {
    /// The ID type for the custom backends used by this dispatch implementation.
    type BackendId: 'static;
    /// The context type used by this dispatch.
    type Context: Default;

    /// Executes a request using a backend or returns [`Error::RequestNotAvailable`][] if it is not
    /// supported by the backend.
    fn request<P: Platform>(
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

#[cfg(not(feature = "serde-extensions"))]
impl Dispatch for CoreOnly {
    type BackendId = NoId;
    type Context = crate::types::NoData;
}

/// An empty ID type.
pub enum NoId {}

impl TryFrom<u8> for NoId {
    type Error = Error;

    fn try_from(_: u8) -> Result<Self, Self::Error> {
        Err(Error::InternalError)
    }
}

/// Helper type for optional backends.
///
/// If the backend is `None`, [`Error::RequestNotAvailable`][] is returned.
#[derive(Debug)]
pub struct OptionalBackend<T>(Option<T>);

impl<T> OptionalBackend<T> {
    /// Crates a new optional backend from an `Option<T>`.
    pub fn new(backend: Option<T>) -> Self {
        Self(backend)
    }

    /// Returns a mutable reference to the wrapped backend or [`Error::RequestNotAvailable`][] if
    /// it is `None`.
    pub fn inner(&mut self) -> Result<&mut T, Error> {
        self.0.as_mut().ok_or(Error::RequestNotAvailable)
    }

    /// Returns the wrapped backend.
    pub fn into_inner(self) -> Option<T> {
        self.0
    }
}

impl<T> Default for OptionalBackend<T> {
    fn default() -> Self {
        Self(None)
    }
}

impl<T> From<T> for OptionalBackend<T> {
    fn from(backend: T) -> Self {
        Self(Some(backend))
    }
}

impl<T> From<Option<T>> for OptionalBackend<T> {
    fn from(backend: Option<T>) -> Self {
        Self(backend)
    }
}

impl<T: Backend> Backend for OptionalBackend<T> {
    type Context = T::Context;

    fn request<P: Platform>(
        &mut self,
        core_ctx: &mut CoreContext,
        backend_ctx: &mut Self::Context,
        request: &Request,
        resources: &mut ServiceResources<P>,
    ) -> Result<Reply, Error> {
        self.inner()?
            .request(core_ctx, backend_ctx, request, resources)
    }
}
