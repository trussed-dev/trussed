#![allow(clippy::transmute_ptr_to_ptr)]
// Ignore lint caused by interchange! macro
#![allow(clippy::derive_partial_eq_without_eq)]

use interchange::Responder;

use crate::api::{Reply, Request};
use crate::backend::BackendId;
use crate::error::Error;
use crate::types::Context;

cfg_if::cfg_if! {

    if #[cfg(feature = "clients-12")] {
        interchange::interchange! {
            TrussedInterchange: (Request, Result<Reply, Error>, 12)
        }
    } else if #[cfg(feature = "clients-11")] {
        interchange::interchange! {
            TrussedInterchange: (Request, Result<Reply, Error>, 11)
        }
    } else if #[cfg(feature = "clients-10")] {
        interchange::interchange! {
            TrussedInterchange: (Request, Result<Reply, Error>, 10)
        }
    } else if #[cfg(feature = "clients-9")] {
        interchange::interchange! {
            TrussedInterchange: (Request, Result<Reply, Error>, 9)
        }
    } else if #[cfg(feature = "clients-8")] {
        interchange::interchange! {
            TrussedInterchange: (Request, Result<Reply, Error>, 8)
        }
    } else if #[cfg(feature = "clients-7")] {
        interchange::interchange! {
            TrussedInterchange: (Request, Result<Reply, Error>, 7)
        }
    } else if #[cfg(feature = "clients-6")] {
        interchange::interchange! {
            TrussedInterchange: (Request, Result<Reply, Error>, 6)
        }
    } else if #[cfg(feature = "clients-5")] {
        interchange::interchange! {
            TrussedInterchange: (Request, Result<Reply, Error>, 5)
        }
    } else if #[cfg(feature = "clients-4")] {
        interchange::interchange! {
            TrussedInterchange: (Request, Result<Reply, Error>, 4)
        }
    } else if #[cfg(feature = "clients-3")] {
        interchange::interchange! {
            TrussedInterchange: (Request, Result<Reply, Error>, 3)
        }
    } else if #[cfg(feature = "clients-2")] {
        interchange::interchange! {
            TrussedInterchange: (Request, Result<Reply, Error>, 2)
        }
    } else if #[cfg(feature = "clients-1")] {
        interchange::interchange! {
            TrussedInterchange: (Request, Result<Reply, Error>, 1)
        }
    }
}

// pub use interchange::TrussedInterchange;

// TODO: The request pipe should block if there is an unhandled
// previous request/reply. As a side effect, the service should always
// be able to assume that the reply pipe is "ready".

// PRIOR ART:
// https://xenomai.org/documentation/xenomai-2.4/html/api/group__native__queue.html
// https://doc.micrium.com/display/osiiidoc/Using+Message+Queues

pub struct ServiceEndpoint<I: 'static, C> {
    pub interchange: Responder<TrussedInterchange>,
    // service (trusted) has this, not client (untrusted)
    // used among other things to namespace cryptographic material
    pub ctx: Context<C>,
    pub backends: &'static [BackendId<I>],
}

// pub type ClientEndpoint = Requester<TrussedInterchange>;
