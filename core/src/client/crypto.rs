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

pub trait Aes256Cbc: CryptoClient {
    fn decrypt_aes256cbc<'c>(
        &'c mut self,
        key: KeyId,
        message: &[u8],
        iv: &[u8],
    ) -> ClientResult<'c, reply::Decrypt, Self> {
        self.decrypt(Mechanism::Aes256Cbc, key, message, &[], iv, &[])
    }

    fn wrap_key_aes256cbc(
        &mut self,
        wrapping_key: KeyId,
        key: KeyId,
        iv: Option<&[u8; 16]>,
    ) -> ClientResult<'_, reply::WrapKey, Self> {
        self.wrap_key(
            Mechanism::Aes256Cbc,
            wrapping_key,
            key,
            &[],
            iv.and_then(|iv| ShortData::from_slice(iv).ok()),
        )
    }
}

pub trait Chacha8Poly1305: CryptoClient {
    fn decrypt_chacha8poly1305<'c>(
        &'c mut self,
        key: KeyId,
        message: &[u8],
        associated_data: &[u8],
        nonce: &[u8],
        tag: &[u8],
    ) -> ClientResult<'c, reply::Decrypt, Self> {
        self.decrypt(
            Mechanism::Chacha8Poly1305,
            key,
            message,
            associated_data,
            nonce,
            tag,
        )
    }

    fn encrypt_chacha8poly1305<'c>(
        &'c mut self,
        key: KeyId,
        message: &[u8],
        associated_data: &[u8],
        nonce: Option<&[u8; 12]>,
    ) -> ClientResult<'c, reply::Encrypt, Self> {
        self.encrypt(
            Mechanism::Chacha8Poly1305,
            key,
            message,
            associated_data,
            nonce.and_then(|nonce| ShortData::from_slice(nonce).ok()),
        )
    }

    fn generate_chacha8poly1305_key(
        &mut self,
        persistence: Location,
    ) -> ClientResult<'_, reply::GenerateKey, Self> {
        self.generate_key(
            Mechanism::Chacha8Poly1305,
            StorageAttributes::new().set_persistence(persistence),
        )
    }

    fn unwrap_key_chacha8poly1305<'c>(
        &'c mut self,
        wrapping_key: KeyId,
        wrapped_key: &[u8],
        associated_data: &[u8],
        location: Location,
    ) -> ClientResult<'c, reply::UnwrapKey, Self> {
        self.unwrap_key(
            Mechanism::Chacha8Poly1305,
            wrapping_key,
            Message::from_slice(wrapped_key).map_err(|_| ClientError::DataTooLarge)?,
            associated_data,
            &[],
            StorageAttributes::new().set_persistence(location),
        )
    }

    fn wrap_key_chacha8poly1305<'c>(
        &'c mut self,
        wrapping_key: KeyId,
        key: KeyId,
        associated_data: &[u8],
        nonce: Option<&[u8; 12]>,
    ) -> ClientResult<'c, reply::WrapKey, Self> {
        self.wrap_key(
            Mechanism::Chacha8Poly1305,
            wrapping_key,
            key,
            associated_data,
            nonce.and_then(|nonce| ShortData::from_slice(nonce).ok()),
        )
    }
}

pub trait HmacBlake2s: CryptoClient {
    fn hmacblake2s_derive_key(
        &mut self,
        base_key: KeyId,
        message: &[u8],
        persistence: Location,
    ) -> ClientResult<'_, reply::DeriveKey, Self> {
        self.derive_key(
            Mechanism::HmacBlake2s,
            base_key,
            Some(MediumData::from_slice(message).map_err(|_| ClientError::DataTooLarge)?),
            StorageAttributes::new().set_persistence(persistence),
        )
    }

    fn sign_hmacblake2s<'c>(
        &'c mut self,
        key: KeyId,
        message: &[u8],
    ) -> ClientResult<'c, reply::Sign, Self> {
        self.sign(
            Mechanism::HmacBlake2s,
            key,
            message,
            SignatureSerialization::Raw,
        )
    }
}

pub trait HmacSha1: CryptoClient {
    fn hmacsha1_derive_key(
        &mut self,
        base_key: KeyId,
        message: &[u8],
        persistence: Location,
    ) -> ClientResult<'_, reply::DeriveKey, Self> {
        self.derive_key(
            Mechanism::HmacSha1,
            base_key,
            Some(MediumData::from_slice(message).map_err(|_| ClientError::DataTooLarge)?),
            StorageAttributes::new().set_persistence(persistence),
        )
    }

    fn sign_hmacsha1<'c>(
        &'c mut self,
        key: KeyId,
        message: &[u8],
    ) -> ClientResult<'c, reply::Sign, Self> {
        self.sign(
            Mechanism::HmacSha1,
            key,
            message,
            SignatureSerialization::Raw,
        )
    }
}

pub trait HmacSha256: CryptoClient {
    fn hmacsha256_derive_key(
        &mut self,
        base_key: KeyId,
        message: &[u8],
        persistence: Location,
    ) -> ClientResult<'_, reply::DeriveKey, Self> {
        self.derive_key(
            Mechanism::HmacSha256,
            base_key,
            Some(MediumData::from_slice(message).map_err(|_| ClientError::DataTooLarge)?),
            StorageAttributes::new().set_persistence(persistence),
        )
    }

    fn sign_hmacsha256<'c>(
        &'c mut self,
        key: KeyId,
        message: &[u8],
    ) -> ClientResult<'c, reply::Sign, Self> {
        self.sign(
            Mechanism::HmacSha256,
            key,
            message,
            SignatureSerialization::Raw,
        )
    }
}

pub trait HmacSha512: CryptoClient {
    fn hmacsha512_derive_key(
        &mut self,
        base_key: KeyId,
        message: &[u8],
        persistence: Location,
    ) -> ClientResult<'_, reply::DeriveKey, Self> {
        self.derive_key(
            Mechanism::HmacSha512,
            base_key,
            Some(MediumData::from_slice(message).map_err(|_| ClientError::DataTooLarge)?),
            StorageAttributes::new().set_persistence(persistence),
        )
    }

    fn sign_hmacsha512<'c>(
        &'c mut self,
        key: KeyId,
        message: &[u8],
    ) -> ClientResult<'c, reply::Sign, Self> {
        self.sign(
            Mechanism::HmacSha512,
            key,
            message,
            SignatureSerialization::Raw,
        )
    }
}

pub trait Ed255: CryptoClient {
    fn generate_ed255_private_key(
        &mut self,
        persistence: Location,
    ) -> ClientResult<'_, reply::GenerateKey, Self> {
        self.generate_key(
            Mechanism::Ed255,
            StorageAttributes::new().set_persistence(persistence),
        )
    }

    fn derive_ed255_public_key(
        &mut self,
        private_key: KeyId,
        persistence: Location,
    ) -> ClientResult<'_, reply::DeriveKey, Self> {
        self.derive_key(
            Mechanism::Ed255,
            private_key,
            None,
            StorageAttributes::new().set_persistence(persistence),
        )
    }

    fn deserialize_ed255_key<'c>(
        &'c mut self,
        serialized_key: &[u8],
        format: KeySerialization,
        attributes: StorageAttributes,
    ) -> ClientResult<'c, reply::DeserializeKey, Self> {
        self.deserialize_key(Mechanism::Ed255, serialized_key, format, attributes)
    }

    fn serialize_ed255_key(
        &mut self,
        key: KeyId,
        format: KeySerialization,
    ) -> ClientResult<'_, reply::SerializeKey, Self> {
        self.serialize_key(Mechanism::Ed255, key, format)
    }

    fn sign_ed255<'c>(
        &'c mut self,
        key: KeyId,
        message: &[u8],
    ) -> ClientResult<'c, reply::Sign, Self> {
        self.sign(Mechanism::Ed255, key, message, SignatureSerialization::Raw)
    }

    fn verify_ed255<'c>(
        &'c mut self,
        key: KeyId,
        message: &[u8],
        signature: &[u8],
    ) -> ClientResult<'c, reply::Verify, Self> {
        self.verify(
            Mechanism::Ed255,
            key,
            message,
            signature,
            SignatureSerialization::Raw,
        )
    }
}

pub trait P256: CryptoClient {
    fn generate_p256_private_key(
        &mut self,
        persistence: Location,
    ) -> ClientResult<'_, reply::GenerateKey, Self> {
        self.generate_key(
            Mechanism::P256,
            StorageAttributes::new().set_persistence(persistence),
        )
    }

    fn derive_p256_public_key(
        &mut self,
        private_key: KeyId,
        persistence: Location,
    ) -> ClientResult<'_, reply::DeriveKey, Self> {
        self.derive_key(
            Mechanism::P256,
            private_key,
            None,
            StorageAttributes::new().set_persistence(persistence),
        )
    }

    fn deserialize_p256_key<'c>(
        &'c mut self,
        serialized_key: &[u8],
        format: KeySerialization,
        attributes: StorageAttributes,
    ) -> ClientResult<'c, reply::DeserializeKey, Self> {
        self.deserialize_key(Mechanism::P256, serialized_key, format, attributes)
    }

    fn serialize_p256_key(
        &mut self,
        key: KeyId,
        format: KeySerialization,
    ) -> ClientResult<'_, reply::SerializeKey, Self> {
        self.serialize_key(Mechanism::P256, key, format)
    }

    // generally, don't offer multiple versions of a mechanism, if possible.
    // try using the simplest when given the choice.
    // hashing is something users can do themselves hopefully :)
    //
    // on the other hand: if users need sha256, then if the service runs in secure trustzone
    // domain, we'll maybe need two copies of the sha2 code
    fn sign_p256<'c>(
        &'c mut self,
        key: KeyId,
        message: &[u8],
        format: SignatureSerialization,
    ) -> ClientResult<'c, reply::Sign, Self> {
        self.sign(Mechanism::P256, key, message, format)
    }

    fn verify_p256<'c>(
        &'c mut self,
        key: KeyId,
        message: &[u8],
        signature: &[u8],
    ) -> ClientResult<'c, reply::Verify, Self> {
        self.verify(
            Mechanism::P256,
            key,
            message,
            signature,
            SignatureSerialization::Raw,
        )
    }

    fn agree_p256(
        &mut self,
        private_key: KeyId,
        public_key: KeyId,
        persistence: Location,
    ) -> ClientResult<'_, reply::Agree, Self> {
        self.agree(
            Mechanism::P256,
            private_key,
            public_key,
            StorageAttributes::new().set_persistence(persistence),
        )
    }
}

pub trait P384: CryptoClient {
    fn generate_p384_private_key(
        &mut self,
        persistence: Location,
    ) -> ClientResult<'_, reply::GenerateKey, Self> {
        self.generate_key(
            Mechanism::P384,
            StorageAttributes::new().set_persistence(persistence),
        )
    }

    fn derive_p384_public_key(
        &mut self,
        private_key: KeyId,
        persistence: Location,
    ) -> ClientResult<'_, reply::DeriveKey, Self> {
        self.derive_key(
            Mechanism::P384,
            private_key,
            None,
            StorageAttributes::new().set_persistence(persistence),
        )
    }

    fn deserialize_p384_key<'c>(
        &'c mut self,
        serialized_key: &[u8],
        format: KeySerialization,
        attributes: StorageAttributes,
    ) -> ClientResult<'c, reply::DeserializeKey, Self> {
        self.deserialize_key(Mechanism::P384, serialized_key, format, attributes)
    }

    fn serialize_p384_key(
        &mut self,
        key: KeyId,
        format: KeySerialization,
    ) -> ClientResult<'_, reply::SerializeKey, Self> {
        self.serialize_key(Mechanism::P384, key, format)
    }

    // generally, don't offer multiple versions of a mechanism, if possible.
    // try using the simplest when given the choice.
    // hashing is something users can do themselves hopefully :)
    //
    // on the other hand: if users need sha256, then if the service runs in secure trustzone
    // domain, we'll maybe need two copies of the sha2 code
    fn sign_p384<'c>(
        &'c mut self,
        key: KeyId,
        message: &[u8],
        format: SignatureSerialization,
    ) -> ClientResult<'c, reply::Sign, Self> {
        self.sign(Mechanism::P384, key, message, format)
    }

    fn verify_p384<'c>(
        &'c mut self,
        key: KeyId,
        message: &[u8],
        signature: &[u8],
    ) -> ClientResult<'c, reply::Verify, Self> {
        self.verify(
            Mechanism::P384,
            key,
            message,
            signature,
            SignatureSerialization::Raw,
        )
    }

    fn agree_p384(
        &mut self,
        private_key: KeyId,
        public_key: KeyId,
        persistence: Location,
    ) -> ClientResult<'_, reply::Agree, Self> {
        self.agree(
            Mechanism::P384,
            private_key,
            public_key,
            StorageAttributes::new().set_persistence(persistence),
        )
    }
}

pub trait P521: CryptoClient {
    fn generate_p521_private_key(
        &mut self,
        persistence: Location,
    ) -> ClientResult<'_, reply::GenerateKey, Self> {
        self.generate_key(
            Mechanism::P521,
            StorageAttributes::new().set_persistence(persistence),
        )
    }

    fn derive_p521_public_key(
        &mut self,
        private_key: KeyId,
        persistence: Location,
    ) -> ClientResult<'_, reply::DeriveKey, Self> {
        self.derive_key(
            Mechanism::P521,
            private_key,
            None,
            StorageAttributes::new().set_persistence(persistence),
        )
    }

    fn deserialize_p521_key<'c>(
        &'c mut self,
        serialized_key: &[u8],
        format: KeySerialization,
        attributes: StorageAttributes,
    ) -> ClientResult<'c, reply::DeserializeKey, Self> {
        self.deserialize_key(Mechanism::P521, serialized_key, format, attributes)
    }

    fn serialize_p521_key(
        &mut self,
        key: KeyId,
        format: KeySerialization,
    ) -> ClientResult<'_, reply::SerializeKey, Self> {
        self.serialize_key(Mechanism::P521, key, format)
    }

    // generally, don't offer multiple versions of a mechanism, if possible.
    // try using the simplest when given the choice.
    // hashing is something users can do themselves hopefully :)
    //
    // on the other hand: if users need sha256, then if the service runs in secure trustzone
    // domain, we'll maybe need two copies of the sha2 code
    fn sign_p521<'c>(
        &'c mut self,
        key: KeyId,
        message: &[u8],
        format: SignatureSerialization,
    ) -> ClientResult<'c, reply::Sign, Self> {
        self.sign(Mechanism::P521, key, message, format)
    }

    fn verify_p521<'c>(
        &'c mut self,
        key: KeyId,
        message: &[u8],
        signature: &[u8],
    ) -> ClientResult<'c, reply::Verify, Self> {
        self.verify(
            Mechanism::P521,
            key,
            message,
            signature,
            SignatureSerialization::Raw,
        )
    }

    fn agree_p521(
        &mut self,
        private_key: KeyId,
        public_key: KeyId,
        persistence: Location,
    ) -> ClientResult<'_, reply::Agree, Self> {
        self.agree(
            Mechanism::P521,
            private_key,
            public_key,
            StorageAttributes::new().set_persistence(persistence),
        )
    }
}

pub trait Sha256: CryptoClient {
    fn sha256_derive_key(
        &mut self,
        shared_key: KeyId,
        persistence: Location,
    ) -> ClientResult<'_, reply::DeriveKey, Self> {
        self.derive_key(
            Mechanism::Sha256,
            shared_key,
            None,
            StorageAttributes::new().set_persistence(persistence),
        )
    }

    fn hash_sha256<'c>(&'c mut self, message: &[u8]) -> ClientResult<'c, reply::Hash, Self> {
        self.hash(
            Mechanism::Sha256,
            Message::from_slice(message).map_err(|_| ClientError::DataTooLarge)?,
        )
    }
}

pub trait Tdes: CryptoClient {
    fn decrypt_tdes<'c>(
        &'c mut self,
        key: KeyId,
        message: &[u8],
    ) -> ClientResult<'c, reply::Decrypt, Self> {
        self.decrypt(Mechanism::Tdes, key, message, &[], &[], &[])
    }

    fn encrypt_tdes<'c>(
        &'c mut self,
        key: KeyId,
        message: &[u8],
    ) -> ClientResult<'c, reply::Encrypt, Self> {
        self.encrypt(Mechanism::Tdes, key, message, &[], None)
    }
}

pub trait Totp: CryptoClient {
    fn sign_totp(&mut self, key: KeyId, timestamp: u64) -> ClientResult<'_, reply::Sign, Self> {
        self.sign(
            Mechanism::Totp,
            key,
            timestamp.to_le_bytes().as_ref(),
            SignatureSerialization::Raw,
        )
    }
}

pub trait X255: CryptoClient {
    fn generate_x255_secret_key(
        &mut self,
        persistence: Location,
    ) -> ClientResult<'_, reply::GenerateKey, Self> {
        self.generate_key(
            Mechanism::X255,
            StorageAttributes::new().set_persistence(persistence),
        )
    }

    fn derive_x255_public_key(
        &mut self,
        secret_key: KeyId,
        persistence: Location,
    ) -> ClientResult<'_, reply::DeriveKey, Self> {
        self.derive_key(
            Mechanism::X255,
            secret_key,
            None,
            StorageAttributes::new().set_persistence(persistence),
        )
    }

    fn agree_x255(
        &mut self,
        private_key: KeyId,
        public_key: KeyId,
        persistence: Location,
    ) -> ClientResult<'_, reply::Agree, Self> {
        self.agree(
            Mechanism::X255,
            private_key,
            public_key,
            StorageAttributes::new().set_persistence(persistence),
        )
    }
}
