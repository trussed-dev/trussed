use crate::{
    api::reply,
    client::{crypto::CryptoClient, ClientError, ClientResult},
    types::{
        KeyId, KeySerialization, Location, Mechanism, MediumData, Message, ShortData,
        SignatureSerialization, StorageAttributes,
    },
};

#[cfg(feature = "aes256-cbc")]
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

#[cfg(feature = "chacha8-poly1305")]
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

#[cfg(feature = "hmac-blake2s")]
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

#[cfg(feature = "hmac-sha1")]
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

#[cfg(feature = "hmac-sha256")]
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

#[cfg(feature = "hmac-sha512")]
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

#[cfg(feature = "ed255")]
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

#[cfg(feature = "p256")]
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

#[cfg(feature = "p384")]
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

#[cfg(feature = "p521")]
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

#[cfg(feature = "sha256")]
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

#[cfg(feature = "tdes")]
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

#[cfg(feature = "totp")]
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

#[cfg(feature = "x255")]
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
