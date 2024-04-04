use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Error, Field, Generics, Ident, Index, LitStr, Path, Result, Type};

use super::util;

pub struct Dispatch {
    name: Ident,
    generics: Generics,
    attrs: DispatchAttrs,
    backends: Vec<Backend>,
}

impl Dispatch {
    pub fn new(input: DeriveInput) -> Result<Self> {
        let Data::Struct(data_struct) = &input.data else {
            return Err(Error::new_spanned(
                input,
                "Dispatch can only be derived for structs with named fields",
            ));
        };
        let backends = data_struct
            .fields
            .iter()
            .enumerate()
            .map(|(i, field)| Backend::new(i, field))
            .collect::<Result<_>>()?;
        let attrs = DispatchAttrs::new(&input)?;
        Ok(Self {
            name: input.ident,
            generics: input.generics,
            attrs,
            backends,
        })
    }

    pub fn generate(&self) -> TokenStream {
        let name = &self.name;
        let backend_id = &self.attrs.backend_id;
        let (impl_generics, ty_generics, where_clause) = self.generics.split_for_impl();
        let context = self.backends.iter().map(Backend::context);
        let requests = self.backends.iter().map(Backend::request);

        quote! {
            impl #impl_generics ::trussed::backend::Dispatch for #name #ty_generics #where_clause {
                type BackendId = #backend_id;
                type Context = (#(#context),*,);

                fn request<P: ::trussed::platform::Platform>(
                    &mut self,
                    backend: &Self::BackendId,
                    ctx: &mut ::trussed::types::Context<Self::Context>,
                    request: &::trussed::api::Request,
                    resources: &mut ::trussed::service::ServiceResources<P>,
                ) -> ::core::result::Result<::trussed::api::Reply, ::trussed::error::Error> {
                    match backend {
                        #(#requests)*
                    }
                }
            }
        }
    }
}

struct DispatchAttrs {
    backend_id: Path,
}

impl DispatchAttrs {
    fn new(input: &DeriveInput) -> Result<Self> {
        let mut backend_id = None;

        let attr = util::require_attr(input, &input.attrs, "dispatch")?;
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("backend_id") {
                let s: LitStr = meta.value()?.parse()?;
                backend_id = Some(s.parse()?);
                Ok(())
            } else {
                Err(meta.error("unsupported dispatch attribute"))
            }
        })?;

        if let Some(backend_id) = backend_id {
            Ok(Self { backend_id })
        } else {
            Err(Error::new_spanned(
                attr,
                "missing backend_id key in dispatch attribute",
            ))
        }
    }
}

struct Backend {
    id: Ident,
    field: Ident,
    ty: Type,
    index: Index,
}

impl Backend {
    fn new(i: usize, field: &Field) -> Result<Self> {
        let ident = field.ident.clone().ok_or_else(|| {
            Error::new_spanned(
                field,
                "Dispatch can only be derived for a struct with named fields",
            )
        })?;
        Ok(Self {
            id: util::to_camelcase(&ident),
            field: ident,
            ty: field.ty.clone(),
            index: Index::from(i),
        })
    }

    fn context(&self) -> TokenStream {
        let ty = &self.ty;
        quote! { <#ty as ::trussed::backend::Backend>::Context }
    }

    fn request(&self) -> TokenStream {
        let Self {
            index, id, field, ..
        } = self;
        quote! {
            Self::BackendId::#id => ::trussed::backend::Backend::request(
                &mut self.#field, &mut ctx.core, &mut ctx.backends.#index, request, resources,
            ),
        }
    }
}
