use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Error, Expr, Generics, Ident, Result, Variant};

pub struct ExtensionId {
    name: Ident,
    generics: Generics,
    extensions: Vec<Extension>,
}

impl ExtensionId {
    pub fn new(input: DeriveInput) -> Result<Self> {
        let Data::Enum(data_enum) = &input.data else {
            return Err(Error::new_spanned(
                input,
                "ExtensionId can only be derived for enums",
            ));
        };
        let extensions = data_enum
            .variants
            .iter()
            .map(Extension::new)
            .collect::<Result<_>>()?;
        Ok(Self {
            name: input.ident,
            generics: input.generics,
            extensions,
        })
    }

    pub fn generate(&self) -> TokenStream {
        let name = &self.name;
        let (impl_generics, ty_generics, where_clause) = self.generics.split_for_impl();
        let from = self.extensions.iter().map(|e| e.from(name));
        let try_from = self.extensions.iter().map(Extension::try_from);

        quote! {
            impl From<#name> for u8 {
                fn from(extension: #name) -> u8 {
                    match extension {
                        #(#from)*
                    }
                }
            }

            impl #impl_generics ::core::convert::TryFrom<u8> for #name #ty_generics #where_clause {
                type Error = ::trussed::Error;

                fn try_from(value: u8) -> ::core::result::Result<Self, Self::Error> {
                    match value {
                        #(#try_from)*
                        _ => Err(::trussed::Error::InternalError),
                    }
                }
            }
        }
    }
}

struct Extension {
    name: Ident,
    id: Expr,
}

impl Extension {
    fn new(variant: &Variant) -> Result<Self> {
        let discriminant = variant
            .discriminant
            .as_ref()
            .ok_or_else(|| {
                Error::new_spanned(
                    variant,
                    "variants for ExtensionId must have an explicit discriminant",
                )
            })?
            .1
            .clone();
        Ok(Self {
            name: variant.ident.clone(),
            id: discriminant,
        })
    }

    fn from(&self, enum_name: &Ident) -> TokenStream {
        let name = &self.name;
        let id = &self.id;
        quote! {
            #enum_name::#name => #id,
        }
    }

    fn try_from(&self) -> TokenStream {
        let name = &self.name;
        let id = &self.id;
        quote! {
            #id => Ok(Self::#name),
        }
    }
}
