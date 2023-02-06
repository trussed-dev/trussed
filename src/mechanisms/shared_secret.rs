use crate::api::*;
use crate::error::Error;
use crate::key;
use crate::service::*;
use crate::types::*;

impl SerializeKey for super::SharedSecret {
    #[inline(never)]
    fn serialize_key(
        keystore: &mut impl Keystore,
        request: &request::SerializeKey,
    ) -> Result<reply::SerializeKey, Error> {
        if request.format != KeySerialization::Raw {
            return Err(Error::InvalidSerializationFormat);
        }

        let key = keystore.load_key(key::Secrecy::Secret, None, &request.key)?;
        if !matches!(key.kind, key::Kind::Shared(..)) {
            return Err(Error::MechanismParamInvalid);
        };

        if !key.flags.contains(key::Flags::SERIALIZABLE) {
            return Err(Error::InvalidSerializedKey);
        };
        let mut serialized_key = SerializedKey::new();
        serialized_key.extend_from_slice(&key.material).unwrap();

        Ok(reply::SerializeKey { serialized_key })
    }
}

impl UnsafeInjectKey for super::SharedSecret {
    fn unsafe_inject_key(
        keystore: &mut impl Keystore,
        request: &request::UnsafeInjectKey,
    ) -> Result<reply::UnsafeInjectKey, Error> {
        let key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret,
            key::Kind::Shared(request.raw_key.len()),
            &request.raw_key,
        )?;

        Ok(reply::UnsafeInjectKey { key: key_id })
    }
}
