use interchange::Responder;

use crate::api::{Request, Reply};
use crate::error::Error;
use crate::types::ClientId;

#[cfg(not(any(
    feature = "clients-2",
    feature = "clients-3",
    feature = "clients-4",
    feature = "clients-5",
    feature = "clients-6",
    feature = "clients-7",
    feature = "clients-8",
    feature = "clients-9",
    feature = "clients-10",
    feature = "clients-11",
    feature = "clients-12",
)))]
interchange::interchange! {
    TrussedInterchange: (Request, Result<Reply, Error>)
}

#[cfg(feature = "clients-2")]
interchange::interchange! {
    TrussedInterchange: (Request, Result<Reply, Error>, 2)
}

#[cfg(feature = "clients-3")]
interchange::interchange! {
    TrussedInterchange: (Request, Result<Reply, Error>, 3)
}

#[cfg(feature = "clients-4")]
interchange::interchange! {
    TrussedInterchange: (Request, Result<Reply, Error>, 4)
}

#[cfg(feature = "clients-5")]
interchange::interchange! {
    TrussedInterchange: (Request, Result<Reply, Error>, 5)
}

#[cfg(feature = "clients-6")]
interchange::interchange! {
    TrussedInterchange: (Request, Result<Reply, Error>, 6)
}

#[cfg(feature = "clients-7")]
interchange::interchange! {
    TrussedInterchange: (Request, Result<Reply, Error>, 7)
}

#[cfg(feature = "clients-8")]
interchange::interchange! {
    TrussedInterchange: (Request, Result<Reply, Error>, 8)
}

#[cfg(feature = "clients-9")]
interchange::interchange! {
    TrussedInterchange: (Request, Result<Reply, Error>, 9)
}

#[cfg(feature = "clients-10")]
interchange::interchange! {
    TrussedInterchange: (Request, Result<Reply, Error>, 10)
}

#[cfg(feature = "clients-11")]
interchange::interchange! {
    TrussedInterchange: (Request, Result<Reply, Error>, 11)
}

#[cfg(feature = "clients-12")]
interchange::interchange! {
    TrussedInterchange: (Request, Result<Reply, Error>, 12)
}

// pub use interchange::TrussedInterchange;

// TODO: The request pipe should block if there is an unhandled
// previous request/reply. As a side effect, the service should always
// be able to assume that the reply pipe is "ready".

// PRIOR ART:
// https://xenomai.org/documentation/xenomai-2.4/html/api/group__native__queue.html
// https://doc.micrium.com/display/osiiidoc/Using+Message+Queues

pub struct ServiceEndpoint {
    pub interchange: Responder<TrussedInterchange>,
    // service (trusted) has this, not client (untrusted)
    // used among other things to namespace cryptographic material
    pub client_id: ClientId,
}

// pub type ClientEndpoint = Requester<TrussedInterchange>;



