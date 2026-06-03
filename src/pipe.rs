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

/// Multiplexed endpoint: a single shared interchange's `Responder` plus a
/// table mapping `ClientTag` → `(Context<C>, backends)`. Used by
/// `Service::process_multiplexed` to route an incoming request to the right
/// app's context based on `CURRENT_TAG`. Holds up to `MAX_CLIENTS` entries.
pub const MAX_MULTIPLEXED_CLIENTS: usize = 8;

pub type MultiplexedClientEntry<I, C> = (
    crate::client::ClientTag,
    Context<C>,
    &'static [BackendId<I>],
);

pub struct MultiplexedEndpoint<'a, I: 'static, C> {
    pub interchange: TrussedResponder<'a>,
    pub clients: [Option<MultiplexedClientEntry<I, C>>; MAX_MULTIPLEXED_CLIENTS],
    pub len: usize,
}

impl<'a, I: 'static, C> MultiplexedEndpoint<'a, I, C> {
    pub fn new(interchange: TrussedResponder<'a>) -> Self {
        Self {
            interchange,
            clients: [const { None }; MAX_MULTIPLEXED_CLIENTS],
            len: 0,
        }
    }

    /// Register a multiplexed client's tag, context, and backends list.
    /// Returns `Err(entry)` if the table is already at `MAX_MULTIPLEXED_CLIENTS`.
    // The `Err` hands the (large) entry back so the caller can recover it
    // without allocation; boxing would defeat the no_std, alloc-free design.
    #[allow(clippy::result_large_err)]
    pub fn register(
        &mut self,
        entry: MultiplexedClientEntry<I, C>,
    ) -> core::result::Result<(), MultiplexedClientEntry<I, C>> {
        if self.len >= MAX_MULTIPLEXED_CLIENTS {
            return Err(entry);
        }
        self.clients[self.len] = Some(entry);
        self.len += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::TrussedChannel;
    use crate::api::{Reply, Request};
    use core::mem;

    // The following checks are used to ensure that we don’t accidentally increase the interchange
    // size.  Bumping the size is not a breaking change but should only be done if really
    // necessary.

    const MAX_SIZE: usize = 2416
        + if cfg!(feature = "mldsa44") {
            // our largest request has a Message and a Signature field and the mldsa44 feature bumps
            // those by 1024 and 1408 bytes
            1024 + 1408
        } else {
            0
        };

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
