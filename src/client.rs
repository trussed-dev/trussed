use core::{marker::PhantomData, task::Poll};

use crate::api::{Reply, RequestVariant};
use crate::backend::{BackendId, CoreOnly, Dispatch};
use crate::error::{Error, Result};
use crate::interrupt::InterruptFlag;
use crate::pipe::{TrussedRequester, TRUSSED_INTERCHANGE};
use crate::service::Service;
use crate::types::{PathBuf, Platform};

pub use trussed_core::{
    client::{
        mechanisms::*, CertificateClient, Client, ClientError, ClientResult, CounterClient,
        CryptoClient, FilesystemClient, FutureResult, ManagementClient, PollClient, UiClient,
    },
    syscall, try_syscall,
};

pub use crate::platform::Syscall;

pub mod mechanisms;

impl<S: Syscall, E> Client for ClientImplementation<S, E> {}

/// The client implementation client applications actually receive.
pub struct ClientImplementation<S, D = CoreOnly> {
    // raw: RawClient<Client<S>>,
    syscall: S,

    // RawClient:
    pub(crate) interchange: TrussedRequester,
    pub(crate) interrupt: Option<&'static InterruptFlag>,
    // pending: Option<Discriminant<Request>>,
    pending: Option<u8>,
    _marker: PhantomData<D>,
}

// impl<S> From<(RawClient, S)> for Client<S>
// where S: Syscall
// {
//     fn from(input: (RawClient, S)) -> Self {
//         Self { raw: input.0, syscall: input.1 }
//     }
// }

impl<S, E> ClientImplementation<S, E>
where
    S: Syscall,
{
    pub fn new(
        interchange: TrussedRequester,
        syscall: S,
        interrupt: Option<&'static InterruptFlag>,
    ) -> Self {
        Self {
            interchange,
            pending: None,
            syscall,
            interrupt,
            _marker: Default::default(),
        }
    }
}

impl<S, E> PollClient for ClientImplementation<S, E>
where
    S: Syscall,
{
    fn poll(&mut self) -> Poll<Result<Reply, Error>> {
        match self.interchange.take_response() {
            Some(reply) => {
                // #[cfg(all(test, feature = "verbose-tests"))]
                // println!("got a reply: {:?}", &reply);
                match reply {
                    Ok(reply) => {
                        if Some(u8::from(&reply)) == self.pending {
                            self.pending = None;
                            Poll::Ready(Ok(reply))
                        } else {
                            // #[cfg(all(test, feature = "verbose-tests"))]
                            info!(
                                "got: {:?}, expected: {:?}",
                                Some(u8::from(&reply)),
                                self.pending
                            );
                            Poll::Ready(Err(Error::InternalError))
                        }
                    }
                    Err(error) => {
                        self.pending = None;
                        Poll::Ready(Err(error))
                    }
                }
            }
            None => {
                debug_assert_ne!(
                    self.interchange.state(),
                    interchange::State::Idle,
                    "requests can't be cancelled"
                );
                Poll::Pending
            }
        }
    }

    // call with any of `crate::api::request::*`
    fn request<Rq: RequestVariant>(&mut self, req: Rq) -> ClientResult<'_, Rq::Reply, Self> {
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
        self.interchange.request(request).unwrap();
        self.syscall.syscall();
        Ok(FutureResult::new(self))
    }

    fn interrupt(&self) -> Option<&'static InterruptFlag> {
        self.interrupt
    }
}

impl<S: Syscall, E> CertificateClient for ClientImplementation<S, E> {}
impl<S: Syscall, E> CryptoClient for ClientImplementation<S, E> {}
impl<S: Syscall, E> CounterClient for ClientImplementation<S, E> {}
impl<S: Syscall, E> FilesystemClient for ClientImplementation<S, E> {}
impl<S: Syscall, E> ManagementClient for ClientImplementation<S, E> {}
impl<S: Syscall, E> UiClient for ClientImplementation<S, E> {}

/// Builder for [`ClientImplementation`][].
///
/// This builder can be used to select the backends used for the client.  If no backends are used,
/// [`Service::try_new_client`][], [`Service::try_as_new_client`][] and
/// [`Service::try_into_new_client`][] can be used directly.
///
/// The maximum number of clients that can be created is defined by the `clients-?` features.  If
/// this number is exceeded, [`Error::ClientCountExceeded`][] is returned.
pub struct ClientBuilder<D: Dispatch = CoreOnly> {
    id: PathBuf,
    backends: &'static [BackendId<D::BackendId>],
    interrupt: Option<&'static InterruptFlag>,
}

impl ClientBuilder {
    /// Creates a new client builder using the given client ID.
    ///
    /// Per default, the client does not support backends and always uses the Trussed core
    /// implementation to execute requests.
    pub fn new(id: PathBuf) -> Self {
        Self {
            id,
            backends: &[],
            interrupt: None,
        }
    }
}

impl<D: Dispatch> ClientBuilder<D> {
    /// Selects the backends to use for this client.
    ///
    /// If `backends` is empty, the Trussed core implementation is always used.
    pub fn backends<E: Dispatch>(
        self,
        backends: &'static [BackendId<E::BackendId>],
    ) -> ClientBuilder<E> {
        ClientBuilder {
            id: self.id,
            backends,
            interrupt: self.interrupt,
        }
    }

    pub fn interrupt(self, interrupt: Option<&'static InterruptFlag>) -> Self {
        Self { interrupt, ..self }
    }

    fn create_endpoint<P: Platform>(
        self,
        service: &mut Service<P, D>,
    ) -> Result<TrussedRequester, Error> {
        let (requester, responder) = TRUSSED_INTERCHANGE
            .claim()
            .ok_or(Error::ClientCountExceeded)?;
        service.add_endpoint(responder, self.id, self.backends, self.interrupt)?;
        Ok(requester)
    }

    /// Prepare a client using the given service.
    ///
    /// This allocates a [`TrussedInterchange`][`crate::pipe::TrussedInterchange`] and a
    /// [`ServiceEndpoint`][`crate::service::ServiceEndpoint`].
    pub fn prepare<P: Platform>(
        self,
        service: &mut Service<P, D>,
    ) -> Result<PreparedClient<D>, Error> {
        let interrupt = self.interrupt;
        self.create_endpoint(service)
            .map(|requester| PreparedClient::new(requester, interrupt))
    }
}

/// An intermediate step of the [`ClientBuilder`][].
///
/// This struct already has an allocated [`TrussedInterchange`][`crate::pipe::TrussedInterchange`] and
/// [`ServiceEndpoint`][`crate::service::ServiceEndpoint`] but still needs a [`Syscall`][]
/// implementation.
pub struct PreparedClient<D> {
    requester: TrussedRequester,
    interrupt: Option<&'static InterruptFlag>,
    _marker: PhantomData<D>,
}

impl<D> PreparedClient<D> {
    fn new(requester: TrussedRequester, interrupt: Option<&'static InterruptFlag>) -> Self {
        Self {
            requester,
            interrupt,
            _marker: Default::default(),
        }
    }

    /// Builds the client using the given syscall implementation.
    pub fn build<S: Syscall>(self, syscall: S) -> ClientImplementation<S, D> {
        ClientImplementation::new(self.requester, syscall, self.interrupt)
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
