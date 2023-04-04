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

#[macro_use]
extern crate delog;
generate_macros!();

pub use interchange::Interchange;

pub mod api;
pub mod backend;
pub mod client;
pub mod config;
pub mod error;
pub mod key;
pub mod mechanisms;
pub mod pipe;
pub mod platform;
#[cfg(feature = "serde-extensions")]
pub mod serde_extensions;
pub mod service;
pub mod store;
pub mod types;
pub mod utils;

#[cfg(feature = "virt")]
#[cfg_attr(docsrs, doc(cfg(feature = "virt")))]
pub mod virt;

pub use api::Reply;
pub use client::{Client, ClientImplementation};
pub use error::Error;
/// The trait that platforms need to implement to use Trussed.
pub use platform::Platform;
pub use service::Service;

pub use cbor_smol::{cbor_deserialize, cbor_serialize, cbor_serialize_bytes};
pub use heapless_bytes::Bytes;
pub use postcard::{from_bytes as postcard_deserialize, to_slice as postcard_serialize};

pub fn postcard_serialize_bytes<T: serde::Serialize, const N: usize>(
    object: &T,
) -> postcard::Result<Bytes<N>> {
    let vec = postcard::to_vec(object)?;
    Ok(Bytes::from(vec))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[macro_use]
extern crate serial_test;
