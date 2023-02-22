#![allow(clippy::transmute_ptr_to_ptr)]
// Ignore lint caused by interchange! macro
#![allow(clippy::derive_partial_eq_without_eq)]

use interchange::{Interchange, Requester, Responder};

use crate::api::{Reply, Request};
use crate::backend::BackendId;
use crate::error::Error;
use crate::types::Context;

pub type TrussedInterchange<const MAX_CLIENTS: usize> =
    Interchange<Request, Result<Reply, Error>, { MAX_CLIENTS }>;

pub type TrussedResponder<'pipe> = Responder<'pipe, Request, Result<Reply, Error>>;
pub type TrussedRequester<'pipe> = Requester<'pipe, Request, Result<Reply, Error>>;

// pub use interchange::TrussedInterchange;

// TODO: The request pipe should block if there is an unhandled
// previous request/reply. As a side effect, the service should always
// be able to assume that the reply pipe is "ready".

// PRIOR ART:
// https://xenomai.org/documentation/xenomai-2.4/html/api/group__native__queue.html
// https://doc.micrium.com/display/osiiidoc/Using+Message+Queues

pub struct ServiceEndpoint<'pipe, I: 'static, C> {
    pub interchange: TrussedResponder<'pipe>,
    // service (trusted) has this, not client (untrusted)
    // used among other things to namespace cryptographic material
    pub ctx: Context<C>,
    pub backends: &'static [BackendId<I>],
}

// pub type ClientEndpoint = Requester<TrussedInterchange>;

#[cfg(test)]
mod tests {
    use crate::api::{Reply, Request};
    use core::mem;

    // The following checks are used to ensure that we don’t accidentally increase the interchange
    // size.  Bumping the size is not a breaking change but should only be done if really
    // necessary.

    const MAX_SIZE: usize = 2432;

    fn assert_size<T>() {
        let size = mem::size_of::<T>();
        assert!(size <= MAX_SIZE, "{size}");
    }

    #[test]
    fn test_request_size() {
        assert_size::<Request>();
    }

    #[test]
    fn test_reply_size() {
        assert_size::<Reply>();
    }

    #[test]
    fn test_interchange_size() {
        use interchange::Channel;
        // The real cost per-client
        assert_size::<Channel<Request, Reply>>();
    }
}
