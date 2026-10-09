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
use core::{marker::PhantomData, task::Poll};

use trussed_core::{
    api::{Reply, RequestVariant},
    ClientError, ClientResult, Error, FutureResult, InterruptFlag, PollClient, Result,
};

use crate::backend::CoreOnly;
use crate::pipe::TrussedRequester;
use crate::platform::Syscall;

#[cfg(feature = "crypto-client")]
mod mechanisms;

/// All-in-one trait bounding on the sub-traits.
#[cfg(feature = "all-clients")]
pub trait Client:
    trussed_core::CertificateClient
    + trussed_core::CryptoClient
    + trussed_core::CounterClient
    + trussed_core::FilesystemClient
    + trussed_core::ManagementClient
    + trussed_core::UiClient
{
}

#[cfg(feature = "all-clients")]
impl<S: Syscall, E> Client for ClientImplementation<'_, S, E> {}

/// The client implementation client applications actually receive.
pub struct ClientImplementation<'a, S, D = CoreOnly> {
    // raw: RawClient<Client<S>>,
    syscall: S,

    // RawClient:
    pub(crate) interchange: TrussedRequester<'a>,
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

impl<'a, S, E> ClientImplementation<'a, S, E>
where
    S: Syscall,
{
    pub fn new(
        interchange: TrussedRequester<'a>,
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

impl<S, E> PollClient for ClientImplementation<'_, S, E>
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

#[cfg(feature = "certificate-client")]
impl<S: Syscall, E> trussed_core::CertificateClient for ClientImplementation<'_, S, E> {}
#[cfg(feature = "crypto-client")]
impl<S: Syscall, E> trussed_core::CryptoClient for ClientImplementation<'_, S, E> {}
#[cfg(feature = "counter-client")]
impl<S: Syscall, E> trussed_core::CounterClient for ClientImplementation<'_, S, E> {}
#[cfg(feature = "filesystem-client")]
impl<S: Syscall, E> trussed_core::FilesystemClient for ClientImplementation<'_, S, E> {}
#[cfg(feature = "management-client")]
impl<S: Syscall, E> trussed_core::ManagementClient for ClientImplementation<'_, S, E> {}
#[cfg(feature = "ui-client")]
impl<S: Syscall, E> trussed_core::UiClient for ClientImplementation<'_, S, E> {}

// `MultiplexedClient` shares one `TrussedRequester` across N apps; each request
// carries a `ClientTag` so the service dispatches with the matching context.

use core::cell::RefCell;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use critical_section::Mutex;

/// Identifies the multiplexed client owning the in-flight request.
pub type ClientTag = u8;

/// The active client tag, written on request and read on dispatch.
pub struct CurrentTagCell(AtomicU8);

impl CurrentTagCell {
    pub const fn new() -> Self {
        Self(AtomicU8::new(0))
    }
    pub fn set(&self, tag: ClientTag) {
        self.0.store(tag, Ordering::Relaxed);
    }
    pub fn get(&self) -> ClientTag {
        self.0.load(Ordering::Relaxed)
    }
}

impl Default for CurrentTagCell {
    fn default() -> Self {
        Self::new()
    }
}

/// Lets `poll()` skip the critical section until a response is waiting.
pub static RESPONSE_READY: AtomicBool = AtomicBool::new(false);

/// The shared `TrussedRequester`, installed once at boot.
pub struct SharedRequesterCell(Mutex<RefCell<Option<TrussedRequester<'static>>>>);

impl SharedRequesterCell {
    pub const fn new() -> Self {
        Self(Mutex::new(RefCell::new(None)))
    }
    /// Install the requester. Call once at boot from the runner.
    pub fn init(&self, requester: TrussedRequester<'static>) {
        critical_section::with(|cs| {
            *self.0.borrow(cs).borrow_mut() = Some(requester);
        });
    }
    /// Panics if not yet initialised.
    pub fn with_mut<R>(&self, f: impl FnOnce(&mut TrussedRequester<'static>) -> R) -> R {
        critical_section::with(|cs| {
            let mut r = self.0.borrow(cs).borrow_mut();
            f(r.as_mut().expect("SharedRequesterCell not initialised"))
        })
    }
}

impl Default for SharedRequesterCell {
    fn default() -> Self {
        Self::new()
    }
}

/// Client that funnels requests through a shared `TrussedRequester` and
/// tags each request with a `ClientTag` so the Service can route to the
/// right context. Implements the same client traits as `ClientImplementation`.
pub struct MultiplexedClient<S, D = CoreOnly> {
    syscall: S,
    shared: &'static SharedRequesterCell,
    current_tag: &'static CurrentTagCell,
    tag: ClientTag,
    interrupt: Option<&'static InterruptFlag>,
    pending: Option<u8>,
    _marker: PhantomData<D>,
}

impl<S, D> MultiplexedClient<S, D>
where
    S: Syscall,
{
    pub fn new(
        shared: &'static SharedRequesterCell,
        current_tag: &'static CurrentTagCell,
        tag: ClientTag,
        syscall: S,
        interrupt: Option<&'static InterruptFlag>,
    ) -> Self {
        Self {
            shared,
            current_tag,
            tag,
            syscall,
            interrupt,
            pending: None,
            _marker: PhantomData,
        }
    }
}

impl<S, D> PollClient for MultiplexedClient<S, D>
where
    S: Syscall,
{
    fn poll(&mut self) -> Poll<Result<Reply, Error>> {
        // Cheap fast-path: if no response has been published yet, skip the
        // critical section entirely. The Service sets `RESPONSE_READY` after
        // `respond()`; we clear it once we've taken the response.
        if !RESPONSE_READY.load(Ordering::Acquire) {
            return Poll::Pending;
        }
        let taken = self.shared.with_mut(|r| (r.take_response(), r.state()));
        if taken.0.is_some() {
            RESPONSE_READY.store(false, Ordering::Release);
        }
        match taken.0 {
            Some(reply) => match reply {
                Ok(reply) => {
                    if Some(u8::from(&reply)) == self.pending {
                        self.pending = None;
                        Poll::Ready(Ok(reply))
                    } else {
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
            },
            None => {
                debug_assert_ne!(
                    taken.1,
                    interchange::State::Idle,
                    "requests can't be cancelled"
                );
                Poll::Pending
            }
        }
    }

    fn request<Rq: RequestVariant>(&mut self, req: Rq) -> ClientResult<'_, Rq::Reply, Self> {
        if self.pending.is_some() {
            return Err(ClientError::Pending);
        }
        self.current_tag.set(self.tag);
        let request = req.into();
        self.pending = Some(u8::from(&request));
        self.shared.with_mut(|r| r.request(request).unwrap());
        self.syscall.syscall();
        Ok(FutureResult::new(self))
    }

    fn interrupt(&self) -> Option<&'static InterruptFlag> {
        self.interrupt
    }
}

#[cfg(feature = "certificate-client")]
impl<S: Syscall, D> trussed_core::CertificateClient for MultiplexedClient<S, D> {}
#[cfg(feature = "crypto-client")]
impl<S: Syscall, D> trussed_core::CryptoClient for MultiplexedClient<S, D> {}
#[cfg(feature = "counter-client")]
impl<S: Syscall, D> trussed_core::CounterClient for MultiplexedClient<S, D> {}
#[cfg(feature = "filesystem-client")]
impl<S: Syscall, D> trussed_core::FilesystemClient for MultiplexedClient<S, D> {}
#[cfg(feature = "management-client")]
impl<S: Syscall, D> trussed_core::ManagementClient for MultiplexedClient<S, D> {}
#[cfg(feature = "ui-client")]
impl<S: Syscall, D> trussed_core::UiClient for MultiplexedClient<S, D> {}
#[cfg(feature = "all-clients")]
impl<S: Syscall, D> Client for MultiplexedClient<S, D> {}
