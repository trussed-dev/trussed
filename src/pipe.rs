#![allow(clippy::transmute_ptr_to_ptr)]
// Ignore lint caused by interchange! macro
#![allow(clippy::derive_partial_eq_without_eq)]

use interchange::{Channel, Requester, Responder};

use crate::api::{Reply, Request};
use crate::backend::BackendId;
use crate::error::Error;
use crate::types::{Context, CoreContext};

pub type TrussedChannel = Channel<Request, Result<Reply, Error>>;
pub type TrussedResponder<'a> = Responder<'a, Request, Result<Reply, Error>>;
pub type TrussedRequester<'a> = Requester<'a, Request, Result<Reply, Error>>;

// pub use interchange::TrussedInterchange;

// TODO: The request pipe should block if there is an unhandled
// previous request/reply. As a side effect, the service should always
// be able to assume that the reply pipe is "ready".

// PRIOR ART:
// https://xenomai.org/documentation/xenomai-2.4/html/api/group__native__queue.html
// https://doc.micrium.com/display/osiiidoc/Using+Message+Queues

pub struct ServiceEndpoint<'a, I: 'static, C> {
    pub(crate) interchange: TrussedResponder<'a>,
    // service (trusted) has this, not client (untrusted)
    // used among other things to namespace cryptographic material
    pub(crate) ctx: Context<C>,
    pub(crate) backends: &'static [BackendId<I>],
}

impl<'a, I: 'static, C: Default> ServiceEndpoint<'a, I, C> {
    pub fn new(
        interchange: TrussedResponder<'a>,
        context: CoreContext,
        backends: &'static [BackendId<I>],
    ) -> Self {
        Self {
            interchange,
            ctx: context.into(),
            backends,
        }
    }
}

// pub type ClientEndpoint = Requester<TrussedInterchange>;

#[cfg(test)]
mod tests {
    use super::TrussedChannel;
    use crate::api::{Reply, Request};
    use core::mem;

    // The following checks are used to ensure that we don’t accidentally increase the interchange
    // size.  Bumping the size is not a breaking change but should only be done if really
    // necessary.
    //
    // The cap tracks `MAX_SIGNATURE_LENGTH`, which grows when `mldsa44` is enabled (ML-DSA-44
    // signatures are 2420 bytes). Both `Request::Verify` and `Reply::Sign` carry a
    // `Bytes<MAX_SIGNATURE_LENGTH>`; under `mldsa44` the largest variant lands near 3504 bytes.

    #[cfg(feature = "mldsa44")]
    const MAX_SIZE: usize = 3520;
    #[cfg(not(feature = "mldsa44"))]
    const MAX_SIZE: usize = 2416;

    #[test]
    fn test_sizes() {
        let request_size = mem::size_of::<Request>();
        let reply_size = mem::size_of::<Reply>();
        let channel_size = mem::size_of::<TrussedChannel>();

        assert!(request_size <= MAX_SIZE, "request_size = {request_size}");
        assert!(reply_size <= MAX_SIZE, "reply_size = {request_size}");

        // Allow some overhead for the channel metadata
        assert!(
            channel_size <= MAX_SIZE + 64,
            "channel_size = {channel_size}"
        );
    }
}
