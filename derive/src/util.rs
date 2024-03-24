use quote::ToTokens;
use syn::{Attribute, Error, Ident, Result};

pub fn get_attr<'a>(attrs: &'a [Attribute], name: &str) -> Result<Option<&'a Attribute>> {
    let mut attrs = attrs.iter().filter(|attr| attr.path().is_ident(name));
    let first = attrs.next();
    if let Some(next) = attrs.next() {
        Err(Error::new_spanned(
            next,
            format!("multiple {} attributes are not supported", name),
        ))
    } else {
        Ok(first)
    }
}

pub fn require_attr<'a>(
    span: &dyn ToTokens,
    attrs: &'a [Attribute],
    name: &str,
) -> Result<&'a Attribute> {
    get_attr(attrs, name)?
        .ok_or_else(|| Error::new_spanned(span, format!("missing #[{}(...)] attribute", name)))
}

pub fn to_camelcase(ident: &Ident) -> Ident {
    let mut s = String::new();
    let mut capitalize = true;
    for c in ident.to_string().chars() {
        if c == '_' {
            capitalize = true;
        } else if capitalize {
            s.push(c.to_ascii_uppercase());
            capitalize = false;
        } else {
            s.push(c);
        }
    }
    Ident::new(&s, ident.span())
}
