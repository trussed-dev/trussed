#![cfg_attr(not(test), no_std)]
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

#[macro_use]
extern crate delog;
generate_macros!();

pub use interchange::Interchange;

pub mod api;
pub mod client;
pub mod config;
pub mod error;
pub mod key;
pub mod mechanisms;
pub mod pipe;
pub mod platform;
pub mod service;
pub mod store;
pub mod types;

pub use api::Reply;
pub use error::Error;
pub use client::{Client, ClientImplementation};
/// The trait that platforms need to implement to use Trussed.
pub use platform::Platform;
pub use service::Service;

pub use cbor_smol::{cbor_serialize, cbor_serialize_bytes, cbor_serialize_bytebuf, cbor_deserialize};
pub use heapless_bytes::{ArrayLength, Bytes as ByteBuf, consts};

#[cfg(test)]
mod tests;

#[cfg(test)]
#[macro_use]
extern crate serial_test;

