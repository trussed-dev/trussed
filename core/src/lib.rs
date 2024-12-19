#![cfg_attr(not(test), no_std)]

//! Core types for the [`trussed`][] crate.
//!
//! See the documentation for [`trussed`][] for more information.
//!
//! [`trussed`]: https://docs.rs/trussed

mod client;
mod error;
mod interrupt;

pub mod api;
pub mod config;
#[cfg(feature = "crypto-client")]
pub mod mechanisms;
#[cfg(feature = "serde-extensions")]
pub mod serde_extensions;
pub mod types;

#[cfg(feature = "attestation-client")]
pub use client::attestation::AttestationClient;
#[cfg(feature = "certificate-client")]
pub use client::certificate::CertificateClient;
#[cfg(feature = "counter-client")]
pub use client::counter::CounterClient;
#[cfg(feature = "crypto-client")]
pub use client::crypto::CryptoClient;
#[cfg(feature = "filesystem-client")]
pub use client::filesystem::FilesystemClient;
#[cfg(feature = "management-client")]
pub use client::management::ManagementClient;
#[cfg(feature = "ui-client")]
pub use client::ui::UiClient;
pub use client::{ClientError, ClientResult, FutureResult, PollClient};
pub use error::{Error, Result};
pub use interrupt::{FromU8Error, InterruptFlag, InterruptState};
