use std::collections::HashMap;

use proc_macro2::TokenStream;
use quote::quote;
use syn::{
    punctuated::Punctuated, Data, DeriveInput, Error, Field, Generics, Ident, Index, LitStr, Path,
    Result, Token, Type,
};

use super::util;

pub struct ExtensionDispatch {
    name: Ident,
    generics: Generics,
    dispatch_attrs: DispatchAttrs,
    extension_attrs: ExtensionAttrs,
    backends: Vec<Backend>,
    delegated_backends: Vec<DelegatedBackend>,
}

impl ExtensionDispatch {
    pub fn new(input: DeriveInput) -> Result<Self> {
        let Data::Struct(data_struct) = &input.data else {
            return Err(Error::new_spanned(
                input,
                "ExtensionDispatch can only be derived for structs with named fields",
            ));
        };
        let dispatch_attrs = DispatchAttrs::new(&input)?;
        let extension_attrs = ExtensionAttrs::new(&input)?;
        let mut raw_backends = Vec::new();
        for field in &data_struct.fields {
            if let Some(raw_backend) = RawBackend::new(field)? {
                raw_backends.push(raw_backend);
            }
        }
        let mut backends = Vec::new();
        let mut delegated_backends = Vec::new();
        for raw_backend in raw_backends {
            if let Some(delegate_to) = raw_backend.delegate_to.clone() {
                delegated_backends.push((raw_backend, delegate_to));
            } else {
                backends.push(Backend::new(
                    backends.len(),
                    raw_backend,
                    &extension_attrs.extensions,
                )?);
            }
        }
        let delegated_backends = delegated_backends
            .into_iter()
            .map(|(raw, delegate_to)| {
                DelegatedBackend::new(raw, delegate_to, &backends, &extension_attrs.extensions)
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            name: input.ident,
            generics: input.generics,
            dispatch_attrs,
            extension_attrs,
            backends,
            delegated_backends,
        })
    }

    pub fn generate(&self) -> TokenStream {
        let name = &self.name;
        let backend_id = &self.dispatch_attrs.backend_id;
        let extension_id = &self.dispatch_attrs.extension_id;
        let (impl_generics, ty_generics, where_clause) = self.generics.split_for_impl();
        let context = self.backends.iter().map(Backend::context);
        let requests = self.backends.iter().map(Backend::request);
        let delegated_requests = self
            .delegated_backends
            .iter()
            .map(DelegatedBackend::request);
        let extension_requests = self.backends.iter().map(Backend::extension_request);
        let delegated_extension_requests = self
            .delegated_backends
            .iter()
            .map(DelegatedBackend::extension_request);
        let extension_impls = self
            .extension_attrs
            .extensions
            .iter()
            .map(|(id, ty)| self.extension_impl(id, ty));

        quote! {
            impl #impl_generics ::trussed::serde_extensions::ExtensionDispatch for #name #ty_generics #where_clause {
                type BackendId = #backend_id;
                type ExtensionId = #extension_id;
                type Context = (#(#context),*,);

                fn core_request<P: ::trussed::platform::Platform>(
                    &mut self,
                    backend: &Self::BackendId,
                    ctx: &mut ::trussed::types::Context<Self::Context>,
                    request: &::trussed::api::Request,
                    resources: &mut ::trussed::service::ServiceResources<P>,
                ) -> ::core::result::Result<::trussed::api::Reply, ::trussed::error::Error> {
                    match backend {
                        #(#requests)*
                        #(#delegated_requests)*
                    }
                }

                fn extension_request<P: ::trussed::platform::Platform>(
                    &mut self,
                    backend: &Self::BackendId,
                    extension: &Self::ExtensionId,
                    ctx: &mut ::trussed::types::Context<Self::Context>,
                    request: &::trussed::api::request::SerdeExtension,
                    resources: &mut ::trussed::service::ServiceResources<P>,
                ) -> ::core::result::Result<::trussed::api::reply::SerdeExtension, ::trussed::error::Error> {
                    match backend {
                        #(#extension_requests)*
                        #(#delegated_extension_requests)*
                    }
                }
            }

            #(#extension_impls)*
        }
    }

    fn extension_impl(&self, id: &Ident, ty: &Path) -> TokenStream {
        let name = &self.name;
        let extension_id = &self.dispatch_attrs.extension_id;
        let (impl_generics, ty_generics, where_clause) = self.generics.split_for_impl();
        quote! {
            impl #impl_generics ::trussed::serde_extensions::ExtensionId<#ty> for #name #ty_generics #where_clause {
                type Id = #extension_id;
                const ID: Self::Id = Self::Id::#id;
            }
        }
    }
}

struct DispatchAttrs {
    backend_id: Path,
    extension_id: Path,
}

impl DispatchAttrs {
    fn new(input: &DeriveInput) -> Result<Self> {
        let mut backend_id = None;
        let mut extension_id = None;

        let attr = util::require_attr(input, &input.attrs, "dispatch")?;
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("backend_id") {
                let s: LitStr = meta.value()?.parse()?;
                backend_id = Some(s.parse()?);
                Ok(())
            } else if meta.path.is_ident("extension_id") {
                let s: LitStr = meta.value()?.parse()?;
                extension_id = Some(s.parse()?);
                Ok(())
            } else {
                Err(meta.error("unsupported dispatch attribute"))
            }
        })?;

        let backend_id = backend_id.ok_or_else(|| {
            Error::new_spanned(attr, "missing backend_id key in dispatch attribute")
        })?;
        let extension_id = extension_id.ok_or_else(|| {
            Error::new_spanned(attr, "missing extension_id key in dispatch attribute")
        })?;

        Ok(Self {
            backend_id,
            extension_id,
        })
    }
}

struct ExtensionAttrs {
    extensions: HashMap<Ident, Path>,
}

impl ExtensionAttrs {
    fn new(input: &DeriveInput) -> Result<Self> {
        let mut extensions: HashMap<Ident, Path> = Default::default();

        for attr in util::get_attrs(&input.attrs, "extensions") {
            attr.parse_nested_meta(|meta| {
                let ident = meta.path.require_ident()?;
                let s: LitStr = meta.value()?.parse()?;
                extensions.insert(ident.to_owned(), s.parse()?);
                Ok(())
            })?;
        }

        Ok(Self { extensions })
    }
}

struct RawBackend {
    id: Ident,
    field: Ident,
    ty: Type,
    no_core: bool,
    delegate_to: Option<Ident>,
    extensions: Vec<Ident>,
}

impl RawBackend {
    fn new(field: &Field) -> Result<Option<Self>> {
        let mut delegate_to = None;
        let mut no_core = false;
        let mut skip = false;
        for attr in util::get_attrs(&field.attrs, "dispatch") {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("delegate_to") {
                    let s: LitStr = meta.value()?.parse()?;
                    delegate_to = Some(s.parse()?);
                    Ok(())
                } else if meta.path.is_ident("no_core") {
                    no_core = true;
                    Ok(())
                } else if meta.path.is_ident("skip") {
                    skip = true;
                    Ok(())
                } else {
                    Err(meta.error("unsupported dispatch attribute"))
                }
            })?;
        }
        if skip {
            return Ok(None);
        }
        let ident = field.ident.clone().ok_or_else(|| {
            Error::new_spanned(
                field,
                "ExtensionDispatch can only be derived for a struct with named fields",
            )
        })?;
        let mut extensions = Vec::new();
        for attr in util::get_attrs(&field.attrs, "extensions") {
            for s in attr.parse_args_with(Punctuated::<LitStr, Token![,]>::parse_terminated)? {
                extensions.push(s.parse()?);
            }
        }
        Ok(Some(Self {
            id: util::to_camelcase(&ident),
            field: ident,
            ty: field.ty.clone(),
            no_core,
            delegate_to,
            extensions,
        }))
    }
}

#[derive(Clone)]
struct Backend {
    id: Ident,
    field: Ident,
    ty: Type,
    index: Index,
    no_core: bool,
    extensions: Vec<Extension>,
}

impl Backend {
    fn new(i: usize, raw: RawBackend, extensions: &HashMap<Ident, Path>) -> Result<Self> {
        let extensions = raw
            .extensions
            .into_iter()
            .map(|i| Extension::new(i, extensions))
            .collect::<Result<_>>()?;
        Ok(Self {
            id: raw.id,
            field: raw.field,
            ty: raw.ty,
            index: Index::from(i),
            no_core: raw.no_core,
            extensions,
        })
    }

    fn context(&self) -> TokenStream {
        let ty = &self.ty;
        quote! { <#ty as ::trussed::backend::Backend>::Context }
    }

    fn request(&self) -> TokenStream {
        let id = &self.id;
        let request = if self.no_core {
            quote! {
                Err(::trussed::Error::RequestNotAvailable)
            }
        } else {
            let Self { index, field, .. } = self;
            quote! {
                ::trussed::backend::Backend::request(
                    &mut self.#field, &mut ctx.core, &mut ctx.backends.#index, request, resources,
                )
            }
        };
        quote! {
            Self::BackendId::#id => {
                #request
            }
        }
    }

    fn extension_request(&self) -> TokenStream {
        let Self { id, extensions, .. } = self;
        let extension_requests = extensions.iter().map(|e| e.extension_request(self));
        quote! {
            Self::BackendId::#id => match extension {
                #(#extension_requests)*
                _ => Err(::trussed::error::Error::RequestNotAvailable),
            }
        }
    }
}

struct DelegatedBackend {
    id: Ident,
    field: Ident,
    backend: Backend,
    no_core: bool,
    extensions: Vec<Extension>,
}

impl DelegatedBackend {
    fn new(
        raw: RawBackend,
        delegate_to: Ident,
        backends: &[Backend],
        extensions: &HashMap<Ident, Path>,
    ) -> Result<Self> {
        match raw.ty {
            Type::Tuple(tuple) if tuple.elems.is_empty() => (),
            _ => {
                return Err(Error::new_spanned(
                    &raw.ty,
                    "delegated backends must use the unit type ()",
                ));
            }
        }

        let extensions = raw
            .extensions
            .into_iter()
            .map(|i| Extension::new(i, extensions))
            .collect::<Result<_>>()?;
        let backend = backends
            .iter()
            .find(|backend| backend.field == delegate_to)
            .ok_or_else(|| Error::new_spanned(delegate_to, "unknown backend"))?
            .clone();
        Ok(Self {
            id: raw.id,
            field: raw.field,
            backend,
            no_core: raw.no_core,
            extensions,
        })
    }

    fn request(&self) -> TokenStream {
        let id = &self.id;
        let request = if self.no_core {
            quote! {
                Err(::trussed::Error::RequestNotAvailable)
            }
        } else {
            let Self { backend, field, .. } = self;
            let Backend {
                field: delegated_field,
                index: delegated_index,
                ..
            } = backend;
            quote! {
                let _ = self.#field;
                ::trussed::backend::Backend::request(
                    &mut self.#delegated_field, &mut ctx.core, &mut ctx.backends.#delegated_index, request, resources,
                )
            }
        };
        quote! {
            Self::BackendId::#id => {
                #request
            }
        }
    }

    fn extension_request(&self) -> TokenStream {
        let Self {
            id,
            extensions,
            backend,
            field,
            ..
        } = self;
        let extension_requests = extensions.iter().map(|e| e.extension_request(backend));
        quote! {
            Self::BackendId::#id => {
                let _ = self.#field;
                match extension {
                    #(#extension_requests)*
                    _ => Err(::trussed::error::Error::RequestNotAvailable),
                }
            }
        }
    }
}

#[derive(Clone)]
struct Extension {
    id: Ident,
    ty: Path,
}

impl Extension {
    fn new(id: Ident, extensions: &HashMap<Ident, Path>) -> Result<Self> {
        let ty = extensions
            .get(&id)
            .ok_or_else(|| Error::new_spanned(&id, "unknown extension ID"))?
            .clone();
        Ok(Self { id, ty })
    }

    fn extension_request(&self, backend: &Backend) -> TokenStream {
        let Self { id, ty } = self;
        let Backend {
            field: backend_field,
            index: backend_index,
            ..
        } = backend;
        quote! {
            Self::ExtensionId::#id => ::trussed::serde_extensions::ExtensionImpl::<#ty>::extension_request_serialized(
                &mut self.#backend_field, &mut ctx.core, &mut ctx.backends.#backend_index, request, resources
            ),
        }
    }
}
