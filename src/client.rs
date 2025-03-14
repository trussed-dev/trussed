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

use crate::api::{Reply, RequestVariant};
use crate::backend::CoreOnly;
use crate::error::{Error, Result};
use crate::interrupt::InterruptFlag;
use crate::pipe::TrussedRequester;

pub use crate::platform::Syscall;

#[cfg(feature = "crypto-client")]
pub mod mechanisms;
#[cfg(feature = "crypto-client")]
pub use mechanisms::*;

pub use trussed_core::{ClientError, ClientResult, FutureResult, PollClient};

#[cfg(feature = "attestation-client")]
pub use trussed_core::AttestationClient;
#[cfg(feature = "certificate-client")]
pub use trussed_core::CertificateClient;
#[cfg(feature = "counter-client")]
pub use trussed_core::CounterClient;
#[cfg(feature = "crypto-client")]
pub use trussed_core::CryptoClient;
#[cfg(feature = "filesystem-client")]
pub use trussed_core::FilesystemClient;
#[cfg(feature = "management-client")]
pub use trussed_core::ManagementClient;
#[cfg(feature = "ui-client")]
pub use trussed_core::UiClient;

/// All-in-one trait bounding on the sub-traits.
#[cfg(feature = "all-clients")]
pub trait Client:
    CertificateClient + CryptoClient + CounterClient + FilesystemClient + ManagementClient + UiClient
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
impl<S: Syscall, E> CertificateClient for ClientImplementation<'_, S, E> {}
#[cfg(feature = "crypto-client")]
impl<S: Syscall, E> CryptoClient for ClientImplementation<'_, S, E> {}
#[cfg(feature = "counter-client")]
impl<S: Syscall, E> CounterClient for ClientImplementation<'_, S, E> {}
#[cfg(feature = "filesystem-client")]
impl<S: Syscall, E> FilesystemClient for ClientImplementation<'_, S, E> {}
#[cfg(feature = "management-client")]
impl<S: Syscall, E> ManagementClient for ClientImplementation<'_, S, E> {}
#[cfg(feature = "ui-client")]
impl<S: Syscall, E> UiClient for ClientImplementation<'_, S, E> {}
