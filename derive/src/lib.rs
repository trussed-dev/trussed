#![deny(unsafe_code, clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#![warn(missing_docs)]

//! Derive macros for [`trussed`](https://docs.rs/trussed).

mod dispatch;
mod extension_dispatch;
mod extension_id;
mod util;

use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput, Error};

use dispatch::Dispatch;
use extension_dispatch::ExtensionDispatch;
use extension_id::ExtensionId;

/// Derives the [`trussed::backend::Dispatch`][] trait.
///
/// This macro can only be used on structs with named fields. Options can be set using the
/// `dispatch` attribute on the struct.
///
/// # Struct Options
///
/// ```rust
/// # use trussed_derive::Dispatch;
/// # enum Backend { A }
/// # struct ABackend {}
/// # impl trussed::backend::Backend for ABackend { type Context = (); }
/// #[derive(Dispatch)]
/// #[dispatch(backend_id = "Backend")]
/// struct Dispatch {
///     // ...
///     # a: ABackend,
/// }
/// ```
///
/// ## `dispatch` attribute
///
/// - `backend_id` (required): the name of the type for `Dispatch::BackendId`.
///   This type must be an enum with one variant per field of the struct.
///   The variant names must be the field names in camel case.
///
/// # Example
///
/// ```rust
/// # use trussed_derive::Dispatch;
/// # struct ManageBackend {}
/// # impl trussed::backend::Backend for ManageBackend { type Context = (); }
/// enum Backend {
///     Rsa,
/// }
///
/// #[derive(Dispatch)]
/// #[dispatch(backend_id = "Backend")]
/// struct Dispatch {
///     rsa: trussed_rsa_alloc::SoftwareRsa,
/// }
/// ```
///
/// This generates the following implementation:
/// ```rust
/// # use trussed_derive::Dispatch;
/// # enum Backend { Rsa }
/// # struct Dispatch {
/// #     rsa: trussed_rsa_alloc::SoftwareRsa,
/// # }
/// use trussed::{
///     backend::{self, Backend as _},
///     platform::Platform, service::ServiceResources, types::Context,
/// };
/// use trussed_core::{api::{Reply, Request}, Error};
///
/// impl backend::Dispatch for Dispatch {
///     type BackendId = Backend;
///     type Context = (
///         <trussed_rsa_alloc::SoftwareRsa as backend::Backend>::Context,
///     );
///
///     fn request<P: Platform>(
///         &mut self,
///         backend: &Self::BackendId,
///         ctx: &mut Context<Self::Context>,
///         request: &Request,
///         resources: &mut ServiceResources<P>,
///     ) -> Result<Reply, Error> {
///         match backend {
///             Backend::Rsa =>
///                 self.rsa.request(&mut ctx.core, &mut ctx.backends.0, request, resources),
///         }
///     }
/// }
/// ```
///
/// [`trussed::backend::Dispatch`]: https://docs.rs/trussed/latest/trussed/backend/trait.Dispatch.html
#[proc_macro_derive(Dispatch, attributes(dispatch))]
pub fn derive_dispatch(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    Dispatch::new(input)
        .map(|d| d.generate())
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

/// Derives the [`trussed::backend::ExtensionDispatch`][] trait.
///
/// This macro can only be used on structs with named fields. Options can be set using the
/// `dispatch` and `extensions` attributes on the struct or on the fields.
///
/// # Struct Options
///
/// ```rust
/// # use trussed_derive::{ExtensionId, ExtensionDispatch};
/// # enum Backend {
/// #     Staging,
/// #     StagingManage,
/// # }
/// # #[derive(ExtensionId)]
/// # enum Extension {
/// #     FsInfo = 0,
/// #     Manage = 1,
/// # }
/// #[derive(ExtensionDispatch)]
/// #[dispatch(backend_id = "Backend", extension_id = "Extension")]
/// #[extensions(
///     FsInfo = "trussed_fs_info::FsInfoExtension",
///     Manage = "trussed_manage::ManageExtension"
/// )]
/// struct Dispatch {
///     // ...
/// #    #[extensions("FsInfo")]
/// #    staging: trussed_staging::StagingBackend,
/// #    #[dispatch(delegate_to = "staging", no_core)]
/// #    #[extensions("Manage")]
/// #    staging_manage: (),
/// }
/// ````
///
/// ## `dispatch` attribute
///
/// - `backend_id` (required): see [`Dispatch`][].
///   Fields with the `#[dispatch(skip)]` attribute don’t need a corresponding enum variant.
/// - `extension_id` (required): the name of the type for `ExtensionDispatch::ExtensionID`.
///   This type must be an enum with one variant per extension defined in the `#[extensions(...)]`
///   attribute.
///
/// ## `extensions` attribute
///
/// The required `extensions` attribute defines a map from extension IDs to their traits.
///
/// # Field Options
///
/// ```rust
/// # use trussed_derive::{ExtensionId, ExtensionDispatch};
/// # enum Backend {
/// #     Staging,
/// # }
/// # #[derive(ExtensionId)]
/// # enum Extension {
/// #     FsInfo = 0,
/// #     Manage = 1,
/// # }
/// #[derive(ExtensionDispatch)]
/// // ...
/// # #[dispatch(backend_id = "Backend", extension_id = "Extension")]
/// # #[extensions(
/// #    FsInfo = "trussed_fs_info::FsInfoExtension",
/// #    Manage = "trussed_manage::ManageExtension"
/// # )]
/// struct Dispatch {
/// #     #[extensions("FsInfo", "Manage")]
/// #     staging: trussed_staging::StagingBackend,
///     #[dispatch(delegate_to = "staging", no_core, skip)]
///     #[extensions("FsInfo", "Manage")]
///     staging_manage: trussed_staging::StagingBackend,
///     // ...
/// }
/// ````
///
/// ## `dispatch` attribute
///
/// - `delegate_to`: if set, send requests to the backend stored in the given field.
/// - `no_core`: if set, let this backend only handle extension requests, not core requests.
/// - `skip`: if set, do not treat this field as a backend.
///
/// ## `extensions` attribute
///
/// The optional `extensions` attribute defines a list of extension IDs for this backend.
///
/// # Example
///
/// ```rust
/// # use trussed_derive::{ExtensionDispatch, ExtensionId};
/// enum Backend {
///     Staging,
///     StagingManage,
///     Rsa,
/// }
///
/// #[derive(ExtensionId)]
/// enum Extension {
///     FsInfo = 0,
///     Manage = 1,
/// }
///
/// #[derive(ExtensionDispatch)]
/// #[dispatch(backend_id = "Backend", extension_id = "Extension")]
/// #[extensions(
///     FsInfo = "trussed_fs_info::FsInfoExtension",
///     Manage = "trussed_manage::ManageExtension"
/// )]
/// struct Dispatch {
///     #[extensions("FsInfo")]
///     staging: trussed_staging::StagingBackend,
///
///     #[dispatch(delegate_to = "staging", no_core)]
///     #[extensions("Manage")]
///     staging_manage: (),
///
///     rsa: trussed_rsa_alloc::SoftwareRsa,
///
///     #[dispatch(skip)]
///     other: String,
/// }
/// ```
///
/// This generates the following implementation:
/// ```rust
/// # use trussed_derive::ExtensionId;
/// # enum Backend {
/// #     Staging,
/// #     StagingManage,
/// #     Rsa,
/// # }
/// # #[derive(ExtensionId)]
/// # enum Extension {
/// #     FsInfo = 0,
/// #     Manage = 1,
/// # }
/// # struct Dispatch {
/// #     staging: trussed_staging::StagingBackend,
/// #     staging_manage: (),
/// #     rsa: trussed_rsa_alloc::SoftwareRsa,
/// #     other: String,
/// # }
/// use trussed::{
///     backend::{self, Backend as _},
///     platform::Platform,
///     serde_extensions::{ExtensionDispatch, ExtensionImpl},
///     service::ServiceResources,
///     types::Context,
/// };
/// use trussed_core::{api::{reply, Reply, request, Request}, Error};
///
/// impl ExtensionDispatch for Dispatch {
///     type BackendId = Backend;
///     type ExtensionId = Extension;
///     type Context = (
///         <trussed_staging::StagingBackend as backend::Backend>::Context,
///         <trussed_rsa_alloc::SoftwareRsa as backend::Backend>::Context,
///     );
///
///     fn core_request<P: Platform>(
///         &mut self,
///         backend: &Self::BackendId,
///         ctx: &mut Context<Self::Context>,
///         request: &Request,
///         resources: &mut ServiceResources<P>,
///     ) -> Result<Reply, Error> {
///         match backend {
///             Backend::Staging =>
///                 self.staging.request(&mut ctx.core, &mut ctx.backends.0, request, resources),
///             Backend::StagingManage => Err(Error::RequestNotAvailable),
///             Backend::Rsa =>
///                 self.rsa.request(&mut ctx.core, &mut ctx.backends.1, request, resources),
///         }
///     }
///
///     fn extension_request<P: Platform>(
///         &mut self,
///         backend: &Self::BackendId,
///         extension: &Self::ExtensionId,
///         ctx: &mut Context<Self::Context>,
///         request: &request::SerdeExtension,
///         resources: &mut ServiceResources<P>,
///     ) -> Result<reply::SerdeExtension, Error> {
///         match backend {
///             Backend::Staging => match extension {
///                 Self::ExtensionId::FsInfo =>
///                     ExtensionImpl::<trussed_fs_info::FsInfoExtension>::extension_request_serialized(
///                         &mut self.staging,
///                         &mut ctx.core,
///                         &mut ctx.backends.0,
///                         request,
///                         resources,
///                     ),
///                 _ => Err(Error::RequestNotAvailable),
///             }
///             Backend::StagingManage => match extension {
///                 Self::ExtensionId::Manage =>
///                     ExtensionImpl::<trussed_manage::ManageExtension>::extension_request_serialized(
///                         &mut self.staging,
///                         &mut ctx.core,
///                         &mut ctx.backends.0,
///                         request,
///                         resources,
///                     ),
///                 _ => Err(Error::RequestNotAvailable),
///             }
///             Backend::Rsa => Err(Error::RequestNotAvailable),
///         }
///     }
/// }
/// ```
///
/// [`trussed::backend::ExtensionDispatch`]: https://docs.rs/trussed/latest/trussed/backend/trait.ExtensionDispatch.html
#[proc_macro_derive(ExtensionDispatch, attributes(dispatch, extensions))]
pub fn derive_extension_dispatch(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    ExtensionDispatch::new(input)
        .map(|ed| ed.generate())
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

/// Derives conversion traits for extension ID enums.
///
/// This macro can only be used on enums. All variants must have an explicit discriminant. The
/// derive macro generates `From<T> for u8` and `TryFrom<u8> for T` when used on `T`.
///
/// # Example
///
/// ```rust
/// # use trussed_derive::ExtensionId;
/// #[derive(ExtensionId)]
/// enum Extension {
///     Auth = 0,
///     Manage = 1,
/// }
/// ```
///
/// This generates the following implementations:
/// ```rust
/// # enum Extension {
/// #     Auth = 0,
/// #     Manage = 1,
/// # }
/// impl From<Extension> for u8 {
///     fn from(extension: Extension) -> u8 {
///         match extension {
///             Extension::Auth => 0,
///             Extension::Manage => 1,
///         }
///     }
/// }
///
/// impl TryFrom<u8> for Extension {
///     type Error = trussed_core::Error;
///
///     fn try_from(value: u8) -> Result<Self, Self::Error> {
///         match value {
///             0 => Ok(Extension::Auth),
///             1 => Ok(Extension::Manage),
///             _ => Err(trussed_core::Error::InternalError),
///         }
///     }
/// }
/// ```
#[proc_macro_derive(ExtensionId)]
pub fn derive_extension_id(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    ExtensionId::new(input)
        .map(|d| d.generate())
        .unwrap_or_else(Error::into_compile_error)
        .into()
}
