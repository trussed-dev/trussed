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
        let mut serialized_key = Message::new();
        serialized_key.extend_from_slice(&key.material).unwrap();

        Ok(reply::SerializeKey { serialized_key })
    }
}
