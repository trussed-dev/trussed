use libcrux_ml_dsa::ml_dsa_44::{
    generate_key_pair, sign, verify, MLDSA44Signature, MLDSA44VerificationKey,
};
use libcrux_ml_dsa::{KEY_GENERATION_RANDOMNESS_SIZE, SIGNING_RANDOMNESS_SIZE};
use rand_core::RngCore;

use crate::api::{reply, request};
use crate::error::Error;
use crate::key;
use crate::service::MechanismImpl;
use crate::store::keystore::Keystore;
use crate::types::{KeyId, KeySerialization, SerializedKey, Signature, SignatureSerialization};

const SEED_LEN: usize = KEY_GENERATION_RANDOMNESS_SIZE; // 32
const PUBLIC_KEY_LEN: usize = 1312;
const SIGNATURE_LEN: usize = 2420;

#[inline(never)]
fn load_seed(keystore: &mut impl Keystore, key_id: &KeyId) -> Result<[u8; SEED_LEN], Error> {
    let seed: [u8; SEED_LEN] = keystore
        .load_key(key::Secrecy::Secret, Some(key::Kind::Mldsa44Seed), key_id)?
        .material
        .as_slice()
        .try_into()
        .map_err(|_| Error::InternalError)?;
    Ok(seed)
}

#[inline(never)]
fn load_public_encoded(
    keystore: &mut impl Keystore,
    key_id: &KeyId,
) -> Result<crate::Bytes<{ crate::config::MAX_KEY_MATERIAL_LENGTH }>, Error> {
    let key = keystore.load_key(key::Secrecy::Public, Some(key::Kind::Mldsa44Seed), key_id)?;
    Ok(key.material)
}

// Non-inline wrappers around libcrux so its sign/verify machinery
// lives in its own stack frame (not folded into our Mldsa44::sign
// frame, which would force both to coexist on the stack).
#[inline(never)]
fn libcrux_keygen(seed: [u8; SEED_LEN]) -> libcrux_ml_dsa::ml_dsa_44::MLDSA44KeyPair {
    generate_key_pair(seed)
}

#[inline(never)]
fn libcrux_sign(
    sk: &libcrux_ml_dsa::ml_dsa_44::MLDSA44SigningKey,
    message: &[u8],
) -> Result<libcrux_ml_dsa::ml_dsa_44::MLDSA44Signature, Error> {
    sign(sk, message, &[], [0u8; SIGNING_RANDOMNESS_SIZE]).map_err(|_| Error::InternalError)
}

#[inline(never)]
fn libcrux_verify(vk: &MLDSA44VerificationKey, message: &[u8], sig: &MLDSA44Signature) -> bool {
    verify(vk, message, &[], sig).is_ok()
}

impl MechanismImpl for super::Mldsa44 {
    #[inline(never)]
    fn generate_key(
        &self,
        keystore: &mut impl Keystore,
        request: &request::GenerateKey,
    ) -> Result<reply::GenerateKey, Error> {
        let mut seed = [0u8; SEED_LEN];
        keystore.rng().fill_bytes(&mut seed);

        let key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret,
            key::Info::from(key::Kind::Mldsa44Seed).with_local_flag(),
            &seed,
        )?;

        Ok(reply::GenerateKey { key: key_id })
    }

    #[inline(never)]
    fn derive_key(
        &self,
        keystore: &mut impl Keystore,
        request: &request::DeriveKey,
    ) -> Result<reply::DeriveKey, Error> {
        let xi = load_seed(keystore, &request.base_key)?;
        // Re-expand the key pair from the seed; we store only the public
        // verification key and drop the signing key.
        let keypair = libcrux_keygen(xi);

        let public_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Public,
            key::Kind::Mldsa44Seed,
            keypair.verification_key.as_slice(),
        )?;

        Ok(reply::DeriveKey { key: public_id })
    }

    #[inline(never)]
    fn deserialize_key(
        &self,
        keystore: &mut impl Keystore,
        request: &request::DeserializeKey,
    ) -> Result<reply::DeserializeKey, Error> {
        if request.format != KeySerialization::Raw {
            return Err(Error::InternalError);
        }
        if request.serialized_key.len() != PUBLIC_KEY_LEN {
            return Err(Error::InvalidSerializedKey);
        }

        let public_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Public,
            key::Kind::Mldsa44Seed,
            &request.serialized_key,
        )?;

        Ok(reply::DeserializeKey { key: public_id })
    }

    #[inline(never)]
    fn serialize_key(
        &self,
        keystore: &mut impl Keystore,
        request: &request::SerializeKey,
    ) -> Result<reply::SerializeKey, Error> {
        let material = load_public_encoded(keystore, &request.key)?;
        let mut serialized_key = SerializedKey::new();

        match request.format {
            KeySerialization::Raw => {
                serialized_key
                    .extend_from_slice(&material)
                    .map_err(|_| Error::InternalError)?;
            }
            KeySerialization::Cose => {
                // COSE_Key for ML-DSA-44 (draft-ietf-cose-akp):
                //   {1: 7, 3: -50, -1: <1312-byte public key>}
                if material.len() != PUBLIC_KEY_LEN {
                    return Err(Error::InternalError);
                }
                // Fixed CBOR header up to the public-key byte string:
                //   a3        — map(3)
                //   01 07     — key 1 = kty, value 7 = AKP
                //   03 38 31  — key 3 = alg, value -50 = ML-DSA-44 (-50 = ~49 = 0x31)
                //   20        — key -1 = pub
                //   59        — bstr, two-byte length follows
                const HEADER: [u8; 8] = [0xa3, 0x01, 0x07, 0x03, 0x38, 0x31, 0x20, 0x59];
                serialized_key
                    .extend_from_slice(&HEADER)
                    .map_err(|_| Error::InternalError)?;
                serialized_key
                    .extend_from_slice(&(PUBLIC_KEY_LEN as u16).to_be_bytes())
                    .map_err(|_| Error::InternalError)?;
                serialized_key
                    .extend_from_slice(&material)
                    .map_err(|_| Error::InternalError)?;
            }
            _ => return Err(Error::InternalError),
        }

        Ok(reply::SerializeKey { serialized_key })
    }

    #[inline(never)]
    fn exists(
        &self,
        keystore: &mut impl Keystore,
        request: &request::Exists,
    ) -> Result<reply::Exists, Error> {
        let exists = keystore.exists_key(
            key::Secrecy::Secret,
            Some(key::Kind::Mldsa44Seed),
            &request.key,
        );
        Ok(reply::Exists { exists })
    }

    #[inline(never)]
    fn sign(
        &self,
        keystore: &mut impl Keystore,
        request: &request::Sign,
    ) -> Result<reply::Sign, Error> {
        let xi = load_seed(keystore, &request.key)?;
        // Re-derive signing key from the stored 32-byte seed.
        let keypair = libcrux_keygen(xi);
        let sig = libcrux_sign(&keypair.signing_key, &request.message)?;

        let mut signature = Signature::new();
        signature
            .extend_from_slice(sig.as_slice())
            .map_err(|_| Error::InternalError)?;

        Ok(reply::Sign { signature })
    }

    #[inline(never)]
    fn verify(
        &self,
        keystore: &mut impl Keystore,
        request: &request::Verify,
    ) -> Result<reply::Verify, Error> {
        if let SignatureSerialization::Raw = request.format {
        } else {
            return Err(Error::InvalidSerializationFormat);
        }

        let material = load_public_encoded(keystore, &request.key)?;
        if material.len() != PUBLIC_KEY_LEN {
            return Err(Error::InvalidSerializedKey);
        }
        let mut vk_bytes = [0u8; PUBLIC_KEY_LEN];
        vk_bytes.copy_from_slice(&material);
        let vk = MLDSA44VerificationKey::new(vk_bytes);

        if request.signature.len() != SIGNATURE_LEN {
            return Err(Error::WrongSignatureLength);
        }
        let mut sig_bytes = [0u8; SIGNATURE_LEN];
        sig_bytes.copy_from_slice(request.signature.as_ref());
        let sig = MLDSA44Signature::new(sig_bytes);

        // Empty context string matches the deterministic-sign side above.
        Ok(reply::Verify {
            valid: libcrux_verify(&vk, &request.message, &sig),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip: deterministic keygen + sign + verify with a fixed seed.
    #[test]
    fn roundtrip() {
        let seed = [0x42u8; 32];
        let keypair = generate_key_pair(seed);

        let msg = b"hello mldsa44";
        let sig = sign(
            &keypair.signing_key,
            msg,
            &[],
            [0u8; SIGNING_RANDOMNESS_SIZE],
        )
        .expect("sign");
        assert!(verify(&keypair.verification_key, msg, &[], &sig).is_ok());

        // Tampered signature must reject.
        let mut tampered = *sig.as_ref();
        tampered[0] ^= 0x01;
        let bad = MLDSA44Signature::new(tampered);
        assert!(verify(&keypair.verification_key, msg, &[], &bad).is_err());
    }
}
