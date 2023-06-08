//! Custom backends that can override core request implementations.
//!
//! Trussed provides a default implementation for all [`Request`][]s, the core backend.  Runners
//! can add custom [`Backend`][] implementations using the [`Dispatch`][] trait that can override
//! the implementation of one or more requests.  The backends used to execute a request can be
//! selected per client when constructing a client using
//! [`ClientBuilder::backends`][`crate::client::ClientBuilder::backends`].
//!
//! Backends can also implement API extensions to provide additional syscalls (see the
//! [`serde_extensions`][`crate::serde_extensions`] module).

use littlefs2::consts::PATH_MAX_PLUS_ONE;

use crate::{
    api::{Reply, Request},
    error::{Error, Result},
    platform::Platform,
    service::ServiceResources,
    store::{
        certstore::ClientCertstore, counterstore::ClientCounterstore, filestore::ClientFilestore,
        keystore::ClientKeystore,
    },
    types::{Context, CoreContext, PathBuf},
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
/// supported.  The backends that are used to execute a request can be selected when constructing a
/// client using [`ClientBuilder::backends`][`crate::client::ClientBuilder::backends`].
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

/// Global and per-client resources for a backend.
///
/// This struct provides access to the store implementations for a backend, similar to
/// [`ServiceResources`][].  It adds the backend ID to all paths so that the global stores are
/// located at `backend-<id>/<store>` and the client stores are located at
/// `<client>/backend-<id>/<store>`.
pub struct BackendResources<'a, P: Platform> {
    resources: &'a mut ServiceResources<P>,
    global_ctx: CoreContext,
}

impl<'a, P: Platform> BackendResources<'a, P> {
    pub fn new(resources: &'a mut ServiceResources<P>, id: &str) -> Self {
        const PREFIX: &[u8] = "backend-".as_bytes();

        let id = id.as_bytes();
        let n = PREFIX.len();
        let m = id.len();
        let mut path = [0; PATH_MAX_PLUS_ONE];
        path[..n].copy_from_slice(PREFIX);
        path[n..n + m].copy_from_slice(id);

        Self {
            resources,
            global_ctx: CoreContext::new(PathBuf::from(&path[..n + m])),
        }
    }

    pub fn global_certstore(&mut self) -> Result<ClientCertstore<P::S>> {
        self.resources.certstore(&self.global_ctx)
    }

    pub fn global_counterstore(&mut self) -> Result<ClientCounterstore<P::S>> {
        self.resources.counterstore(&self.global_ctx)
    }

    pub fn global_filestore(&mut self) -> ClientFilestore<P::S> {
        self.resources.filestore(&self.global_ctx)
    }

    pub fn global_keystore(&mut self) -> Result<ClientKeystore<P::S>> {
        self.resources.keystore(&self.global_ctx)
    }

    fn client_ctx(&self, ctx: &CoreContext) -> CoreContext {
        let mut path = ctx.path.clone();
        path.push(&self.global_ctx.path);
        CoreContext::new(path)
    }

    pub fn client_certstore(&mut self, ctx: &CoreContext) -> Result<ClientCertstore<P::S>> {
        self.resources.certstore(&self.client_ctx(ctx))
    }

    pub fn client_counterstore(&mut self, ctx: &CoreContext) -> Result<ClientCounterstore<P::S>> {
        self.resources.counterstore(&self.client_ctx(ctx))
    }

    pub fn client_filestore(&mut self, ctx: &CoreContext) -> ClientFilestore<P::S> {
        self.resources.filestore(&self.client_ctx(ctx))
    }

    pub fn client_keystore(&mut self, ctx: &CoreContext) -> Result<ClientKeystore<P::S>> {
        self.resources.keystore(&self.client_ctx(ctx))
    }
}
