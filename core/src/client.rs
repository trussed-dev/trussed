use core::{marker::PhantomData, task::Poll};

use crate::{
    api::{Reply, ReplyVariant, RequestVariant},
    error::{Error, Result},
    interrupt::InterruptFlag,
};

#[cfg(feature = "attestation-client")]
mod attestation;
#[cfg(feature = "certificate-client")]
mod certificate;
#[cfg(feature = "counter-client")]
mod counter;
#[cfg(feature = "crypto-client")]
mod crypto;
#[cfg(feature = "filesystem-client")]
mod filesystem;
#[cfg(feature = "management-client")]
mod management;
#[cfg(feature = "ui-client")]
mod ui;

#[cfg(feature = "attestation-client")]
pub use attestation::AttestationClient;
#[cfg(feature = "certificate-client")]
pub use certificate::CertificateClient;
#[cfg(feature = "counter-client")]
pub use counter::CounterClient;
#[cfg(feature = "crypto-client")]
pub use crypto::*;
#[cfg(feature = "filesystem-client")]
pub use filesystem::FilesystemClient;
#[cfg(feature = "management-client")]
pub use management::ManagementClient;
#[cfg(feature = "ui-client")]
pub use ui::UiClient;

// to be fair, this is a programmer error,
// and could also just panic
#[derive(Copy, Clone, Debug)]
#[non_exhaustive]
pub enum ClientError {
    Full,
    Pending,
    DataTooLarge,
    SerializationFailed,
}

pub type ClientResult<'c, T, C> = Result<FutureResult<'c, T, C>, ClientError>;

/// Lowest level interface, use one of the higher level ones.
pub trait PollClient {
    fn request<Rq: RequestVariant>(&mut self, req: Rq) -> ClientResult<'_, Rq::Reply, Self>;
    fn poll(&mut self) -> Poll<Result<Reply, Error>>;
    fn interrupt(&self) -> Option<&'static InterruptFlag> {
        None
    }
}

#[must_use = "Syscalls must be polled with the `syscall` macro"]
pub struct FutureResult<'c, T, C: ?Sized>
where
    C: PollClient,
{
    pub(crate) client: &'c mut C,
    __: PhantomData<T>,
}

impl<'c, T, C> FutureResult<'c, T, C>
where
    T: ReplyVariant,
    C: PollClient,
{
    pub fn new(client: &'c mut C) -> Self {
        Self {
            client,
            __: PhantomData,
        }
    }
    pub fn poll(&mut self) -> Poll<Result<T, Error>> {
        self.client
            .poll()
            .map(|result| result.and_then(TryFrom::try_from))
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

#[macro_export]
macro_rules! syscall {
    ($pre_future_result:expr) => {{
        // evaluate the expression
        let mut future_result = $pre_future_result.expect("no client error");
        loop {
            match future_result.poll() {
                core::task::Poll::Ready(result) => {
                    break result.expect("no errors");
                }
                core::task::Poll::Pending => {}
            }
        }
    }};
}

#[macro_export]
macro_rules! try_syscall {
    ($pre_future_result:expr) => {{
        // evaluate the expression
        let mut future_result = $pre_future_result.expect("no client error");
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
