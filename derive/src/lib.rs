#![deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod dispatch;
mod extension_dispatch;
mod util;

use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput, Error};

use dispatch::Dispatch;
use extension_dispatch::ExtensionDispatch;

#[proc_macro_derive(Dispatch, attributes(dispatch))]
pub fn derive_dispatch(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    Dispatch::new(input)
        .map(|d| d.generate())
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

#[proc_macro_derive(ExtensionDispatch, attributes(dispatch, extensions))]
pub fn derive_extension_dispatch(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    ExtensionDispatch::new(input)
        .map(|ed| ed.generate())
        .unwrap_or_else(Error::into_compile_error)
        .into()
}
