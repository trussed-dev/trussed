#![no_std]

//! Core types for the [`trussed`][] crate.
//!
//! See the documentation for [`trussed`][] for more information.
//!
//! [`trussed`]: https://docs.rs/trussed

pub mod api;
pub mod client;
pub mod config;
pub mod error;
pub mod interrupt;
#[cfg(feature = "serde-extensions")]
pub mod serde_extensions;
pub mod types;
