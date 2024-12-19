use super::{ClientError, ClientResult, PollClient};
use crate::{
    api::{reply, request},
    types::{
        Bytes, KeyId, KeySerialization, Location, Mechanism, MediumData, Message, SerializedKey,
        ShortData, Signature, SignatureSerialization, StorageAttributes,
    },
};

/// Trussed Client interface that Trussed apps can rely on.
pub trait CryptoClient: PollClient {
    // call with any of `crate::api::request::*`
    // fn request<'c>(&'c mut self, req: impl Into<Request>)
    // -> core::result::Result<RawFutureResult<'c, Self>, ClientError>;

    fn agree(
        &mut self,
        mechanism: Mechanism,
        private_key: KeyId,
        public_key: KeyId,
        attributes: StorageAttributes,
    ) -> ClientResult<'_, reply::Agree, Self> {
        self.request(request::Agree {
            mechanism,
            private_key,
            public_key,
            attributes,
        })
    }

    fn decrypt<'c>(
        &'c mut self,
        mechanism: Mechanism,
        key: KeyId,
        message: &[u8],
        associated_data: &[u8],
        nonce: &[u8],
        tag: &[u8],
    ) -> ClientResult<'c, reply::Decrypt, Self> {
        let message = Message::from_slice(message).map_err(|_| ClientError::DataTooLarge)?;
        let associated_data =
            Message::from_slice(associated_data).map_err(|_| ClientError::DataTooLarge)?;
        let nonce = ShortData::from_slice(nonce).map_err(|_| ClientError::DataTooLarge)?;
        let tag = ShortData::from_slice(tag).map_err(|_| ClientError::DataTooLarge)?;
        self.request(request::Decrypt {
            mechanism,
            key,
            message,
            associated_data,
            nonce,
            tag,
        })
    }

    fn delete(&mut self, key: KeyId) -> ClientResult<'_, reply::Delete, Self> {
        self.request(request::Delete {
            key,
            // mechanism,
        })
    }

    /// Clear private data from the key
    ///
    /// This will not delete all metadata from storage.
    /// Other backends can retain metadata required for `unwrap_key` to work properly
    /// and delete this metadata only once `delete` is called.
    fn clear(&mut self, key: KeyId) -> ClientResult<'_, reply::Clear, Self> {
        self.request(request::Clear {
            key,
            // mechanism,
        })
    }

    /// Skips deleting read-only / manufacture keys (currently, "low ID").
    fn delete_all(&mut self, location: Location) -> ClientResult<'_, reply::DeleteAllKeys, Self> {
        self.request(request::DeleteAllKeys { location })
    }

    fn derive_key(
        &mut self,
        mechanism: Mechanism,
        base_key: KeyId,
        additional_data: Option<MediumData>,
        attributes: StorageAttributes,
    ) -> ClientResult<'_, reply::DeriveKey, Self> {
        self.request(request::DeriveKey {
            mechanism,
            base_key,
            additional_data,
            attributes,
        })
    }

    fn deserialize_key<'c>(
        &'c mut self,
        mechanism: Mechanism,
        serialized_key: &[u8],
        format: KeySerialization,
        attributes: StorageAttributes,
    ) -> ClientResult<'c, reply::DeserializeKey, Self> {
        let serialized_key =
            SerializedKey::from_slice(serialized_key).map_err(|_| ClientError::DataTooLarge)?;
        self.request(request::DeserializeKey {
            mechanism,
            serialized_key,
            format,
            attributes,
        })
    }

    fn encrypt<'c>(
        &'c mut self,
        mechanism: Mechanism,
        key: KeyId,
        message: &[u8],
        associated_data: &[u8],
        nonce: Option<ShortData>,
    ) -> ClientResult<'c, reply::Encrypt, Self> {
        let message = Message::from_slice(message).map_err(|_| ClientError::DataTooLarge)?;
        let associated_data =
            ShortData::from_slice(associated_data).map_err(|_| ClientError::DataTooLarge)?;
        self.request(request::Encrypt {
            mechanism,
            key,
            message,
            associated_data,
            nonce,
        })
    }

    fn exists(
        &mut self,
        mechanism: Mechanism,
        key: KeyId,
    ) -> ClientResult<'_, reply::Exists, Self> {
        self.request(request::Exists { key, mechanism })
    }

    fn generate_key(
        &mut self,
        mechanism: Mechanism,
        attributes: StorageAttributes,
    ) -> ClientResult<'_, reply::GenerateKey, Self> {
        self.request(request::GenerateKey {
            mechanism,
            attributes,
        })
    }

    fn generate_secret_key(
        &mut self,
        size: usize,
        persistence: Location,
    ) -> ClientResult<'_, reply::GenerateSecretKey, Self> {
        self.request(request::GenerateSecretKey {
            size,
            attributes: StorageAttributes::new().set_persistence(persistence),
        })
    }

    fn hash(
        &mut self,
        mechanism: Mechanism,
        message: Message,
    ) -> ClientResult<'_, reply::Hash, Self> {
        self.request(request::Hash { mechanism, message })
    }

    fn random_bytes(&mut self, count: usize) -> ClientResult<'_, reply::RandomBytes, Self> {
        self.request(request::RandomBytes { count })
    }

    fn serialize_key(
        &mut self,
        mechanism: Mechanism,
        key: KeyId,
        format: KeySerialization,
    ) -> ClientResult<'_, reply::SerializeKey, Self> {
        self.request(request::SerializeKey {
            key,
            mechanism,
            format,
        })
    }

    fn sign<'c>(
        &'c mut self,
        mechanism: Mechanism,
        key: KeyId,
        data: &[u8],
        format: SignatureSerialization,
    ) -> ClientResult<'c, reply::Sign, Self> {
        self.request(request::Sign {
            key,
            mechanism,
            message: Bytes::from_slice(data).map_err(|_| ClientError::DataTooLarge)?,
            format,
        })
    }

    fn verify<'c>(
        &'c mut self,
        mechanism: Mechanism,
        key: KeyId,
        message: &[u8],
        signature: &[u8],
        format: SignatureSerialization,
    ) -> ClientResult<'c, reply::Verify, Self> {
        self.request(request::Verify {
            mechanism,
            key,
            message: Message::from_slice(message).expect("all good"),
            signature: Signature::from_slice(signature).expect("all good"),
            format,
        })
    }

    fn unsafe_inject_key(
        &mut self,
        mechanism: Mechanism,
        raw_key: &[u8],
        persistence: Location,
        format: KeySerialization,
    ) -> ClientResult<'_, reply::UnsafeInjectKey, Self> {
        self.request(request::UnsafeInjectKey {
            mechanism,
            raw_key: SerializedKey::from_slice(raw_key).unwrap(),
            attributes: StorageAttributes::new().set_persistence(persistence),
            format,
        })
    }

    fn unsafe_inject_shared_key(
        &mut self,
        raw_key: &[u8],
        location: Location,
    ) -> ClientResult<'_, reply::UnsafeInjectSharedKey, Self> {
        self.request(request::UnsafeInjectSharedKey {
            raw_key: ShortData::from_slice(raw_key).unwrap(),
            location,
        })
    }

    fn unwrap_key<'c>(
        &'c mut self,
        mechanism: Mechanism,
        wrapping_key: KeyId,
        wrapped_key: Message,
        associated_data: &[u8],
        nonce: &[u8],
        attributes: StorageAttributes,
    ) -> ClientResult<'c, reply::UnwrapKey, Self> {
        let associated_data =
            Message::from_slice(associated_data).map_err(|_| ClientError::DataTooLarge)?;
        let nonce = ShortData::from_slice(nonce).map_err(|_| ClientError::DataTooLarge)?;
        self.request(request::UnwrapKey {
            mechanism,
            wrapping_key,
            wrapped_key,
            associated_data,
            nonce,
            attributes,
        })
    }

    fn wrap_key(
        &mut self,
        mechanism: Mechanism,
        wrapping_key: KeyId,
        key: KeyId,
        associated_data: &[u8],
        nonce: Option<ShortData>,
    ) -> ClientResult<'_, reply::WrapKey, Self> {
        let associated_data =
            Bytes::from_slice(associated_data).map_err(|_| ClientError::DataTooLarge)?;
        self.request(request::WrapKey {
            mechanism,
            wrapping_key,
            key,
            associated_data,
            nonce,
        })
    }
}
