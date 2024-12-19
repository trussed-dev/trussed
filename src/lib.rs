#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
//! # Trussed
//!
//! Trussed® is a minimal, modular way to write cryptographic applications on microcontroller platforms.
//! Easy to write, easy to audit — compile-time security by default.
//!
//! Documentation is evolving, a good entry point is the module `trussed::client`.

// prevent a spurious error message: https://github.com/rust-lang/rust/issues/54010
// UNFORTUNATELY: with #![cfg(test)], no longer compiles for no_std,
// with #[cfg(test)] error still shown
// #[cfg(test)]
// extern crate std;

// Temporarily disabled until documentation coverage is improved.
#![allow(clippy::missing_safety_doc)]
// Generated by flexiber: https://github.com/trussed-dev/flexiber/issues/6
#![allow(non_local_definitions)]

#[macro_use]
extern crate delog;
generate_macros!();

pub use interchange::Interchange;

pub mod api;
pub mod backend;
pub mod client;
pub mod config;
pub mod error;
pub mod interrupt;
pub mod key;
#[cfg(feature = "crypto-client")]
pub mod mechanisms;
pub mod pipe;
pub mod platform;
#[cfg(feature = "serde-extensions")]
pub mod serde_extensions;
pub mod service;
pub mod store;
pub mod types;

#[cfg(feature = "virt")]
#[cfg_attr(docsrs, doc(cfg(feature = "virt")))]
pub mod virt;

pub use api::Reply;
#[cfg(feature = "all-clients")]
pub use client::Client;
pub use client::ClientImplementation;
pub use error::Error;
/// The trait that platforms need to implement to use Trussed.
pub use platform::Platform;
pub use service::Service;

pub use trussed_core::{block, syscall, try_syscall};

pub use cbor_smol::cbor_deserialize;
pub use heapless_bytes::Bytes;

pub fn cbor_serialize_bytes<T: serde::Serialize, const N: usize>(
    object: &T,
) -> cbor_smol::Result<Bytes<N>> {
    let mut data = Bytes::new();
    cbor_smol::cbor_serialize_to(object, &mut data)?;
    Ok(data)
}

pub(crate) use postcard::from_bytes as postcard_deserialize;

pub(crate) fn postcard_serialize_bytes<T: serde::Serialize, const N: usize>(
    object: &T,
) -> postcard::Result<Bytes<N>> {
    let vec = postcard::to_vec(object)?;
    Ok(Bytes::from(vec))
}

#[cfg(all(test, feature = "crypto-client", feature = "filesystem-client"))]
mod tests;

#[cfg(test)]
#[macro_use]
extern crate serial_test;
