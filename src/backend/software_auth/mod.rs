use chacha20::ChaCha8Rng;
use cosey::Bytes;
use heapless_bytes::Unsigned;
use littlefs2::path::PathBuf;
pub use rand_core::{RngCore, SeedableRng};

use crate::api::*;
use crate::config::*;
use crate::mechanisms;
use crate::platform::*;
use crate::types::*;

use crate::error::{Error, Result};
pub use crate::pipe::ServiceEndpoint;

pub use crate::store::{self, Store};

use crate::service::*;
pub use crate::store::{
    certstore::{Certstore as _, ClientCertstore},
    counterstore::{ClientCounterstore, Counterstore as _},
    filestore::{ClientFilestore, Filestore, ReadDirFilesState, ReadDirState},
    keystore::{ClientKeystore, Keystore},
};

mod auth_state;
use auth_state::AuthState;

pub struct SoftwareAuthBackend {
    pub rng_state: Option<ChaCha8Rng>,
}

impl SoftwareAuthBackend {
    fn write_policy_for<S: Store>(
        &mut self,
        plat_store: S,
        path: &PathBuf,
        policy: Policy,
    ) -> Result<()> {
        let mut policy_path = PathBuf::new();
        policy_path.push(&path);
        policy_path.push(&PathBuf::from(".policy"));

        let serialized: Bytes<12> =
            crate::cbor_serialize_bytes(&policy).map_err(|_| Error::CborError)?;
        store::store(
            plat_store,
            Location::Internal,
            &policy_path,
            serialized.as_slice(),
        )
    }

    fn read_policy_for<S: Store>(&mut self, plat_store: S, path: &PathBuf) -> Result<Policy> {
        // @TODO: check for existance

        let mut policy_path = PathBuf::new();
        policy_path.push(&path);
        policy_path.push(&PathBuf::from(".policy"));

        let policy: Bytes<12> = store::read(plat_store, Location::Internal, &policy_path)?;
        crate::cbor_deserialize(policy.as_slice()).map_err(|_| Error::CborError)
    }

    fn check_auth_context(&mut self, requested_ctx: &AuthContextID, pin: &PinData) -> bool {
        // @todo: read (saved) context object from filesystem, or create it if not existant
        match requested_ctx {
            AuthContextID::Unauthorized => true,
            AuthContextID::User => pin.eq("1234"), // compare against 1234
            AuthContextID::Admin => pin.eq("123456"), // compare against 123456
        }
    }

    pub fn rng<R: CryptoRng + RngCore, S: Store>(
        &mut self,
        platform_rng: &mut R,
        platform_store: S,
    ) -> Result<ChaCha8Rng> {
        // Check if our RNG is loaded.
        let mut rng = match self.rng_state.take() {
            Some(rng) => rng,
            None => {
                let mut filestore: ClientFilestore<S> =
                    ClientFilestore::new(PathBuf::from("trussed"), platform_store);

                let path = PathBuf::from("rng-state.bin");

                // Load previous seed, e.g., externally injected entropy on first run.
                // Else, default to zeros - will mix in new HW RNG entropy next
                let mixin_seed = if !filestore.exists(&path, Location::Internal) {
                    [0u8; 32]
                } else {
                    // Use the last saved state.
                    let mixin_bytes: Bytes<32> = filestore.read(&path, Location::Internal)?;
                    let mut mixin_seed = [0u8; 32];
                    mixin_seed.clone_from_slice(&mixin_bytes);
                    mixin_seed
                };

                // Generally, the TRNG is fed through a DRBG to whiten its output.
                //
                // In principal seeding a DRBG like Chacha8Rng from "good" HW/external entropy
                // should be good enough for the lifetime of the key.
                //
                // Since we have a TRNG though, we might as well mix in some new entropy
                // on each boot. We do not do so on each DRBG draw to avoid excessive flash writes.
                // (e.g., if some app exposes unlimited "read-entropy" functionality to users).
                //
                // Additionally, we use a twist on the ideas of Haskell's splittable RNGs, and store
                // an input seed for the next boot. In this way, even if the HW entropy "goes bad"
                // (e.g., starts returning all zeros), there are still no cycles or repeats of entropy
                // in the output to apps.

                // 1. First, draw fresh entropy from the HW TRNG.
                let mut entropy = [0u8; 32];
                platform_rng
                    .try_fill_bytes(&mut entropy)
                    .map_err(|_| Error::EntropyMalfunction)?;

                // 2. Mix into our previously stored seed.
                let mut our_seed = [0u8; 32];
                for i in 0..32 {
                    our_seed[i] = mixin_seed[i] ^ entropy[i];
                }

                // 3. Initialize ChaCha8 construction with our seed.
                let mut rng = chacha20::ChaCha8Rng::from_seed(our_seed);

                // 4. Store freshly drawn seed for next boot.
                let mut seed_to_store = [0u8; 32];
                rng.fill_bytes(&mut seed_to_store);
                filestore
                    .write(&path, Location::Internal, seed_to_store.as_ref())
                    .unwrap();

                // 5. Finish
                Ok(rng)
            }?,
        };

        // split off another DRBG
        let split_rng = ChaCha8Rng::from_rng(&mut rng).map_err(|_| Error::EntropyMalfunction);
        self.rng_state = Some(rng);
        split_rng
    }
}

impl<S: Store, R: CryptoRng + RngCore> ServiceBackend<S, R> for SoftwareAuthBackend {
    fn reply_to(
        &mut self,
        plat_store: S,
        plat_rng: &mut R,
        client_ctx: &mut ClientContext,
        request: &Request,
    ) -> Result<Reply> {
        let full_store = plat_store;

        // prepare keystore, bound to client_id, for cryptographic calls
        let mut keystore: ClientKeystore<S> = ClientKeystore::new(
            client_ctx.path.clone(),
            self.rng(plat_rng, plat_store)
                .map_err(|_| Error::EntropyMalfunction)?,
            full_store,
        );
        let keystore = &mut keystore;

        // prepare certstore, bound to client_id, for cert calls
        let mut certstore: ClientCertstore<S> = ClientCertstore::new(
            client_ctx.path.clone(),
            self.rng(plat_rng, plat_store)
                .map_err(|_| Error::EntropyMalfunction)?,
            full_store,
        );
        let certstore = &mut certstore;

        // prepare counterstore, bound to client_id, for counter calls
        let mut counterstore: ClientCounterstore<S> = ClientCounterstore::new(
            client_ctx.path.clone(),
            self.rng(plat_rng, plat_store)
                .map_err(|_| Error::EntropyMalfunction)?,
            full_store,
        );
        let counterstore = &mut counterstore;

        // prepare filestore, bound to client_id, for storage calls
        let mut filestore: ClientFilestore<S> =
            ClientFilestore::new(client_ctx.path.clone(), full_store);
        let filestore = &mut filestore;

        match request {
            Request::DummyRequest => Ok(Reply::DummyReply),

            Request::Wink(request) => {
                //self.platform.user_interface().wink(request.duration);
                debug_now!("was geht ab....");
                Ok(Reply::Wink(reply::Wink {}))
            }

            Request::SetAuthContext(request) => {
                if request.pin.len() > MAX_PIN_LENGTH {
                    return Err(Error::InternalError);
                }
                client_ctx.context = request.context;
                client_ctx.pin.clear();
                client_ctx.pin.extend_from_slice(&request.pin);
                Ok(Reply::SetAuthContext(reply::SetAuthContext {}))
            }

            Request::SetCreationPolicy(request) => {
                client_ctx.creation_policy = request.policy;
                Ok(Reply::SetCreationPolicy(reply::SetCreationPolicy {}))
            }

            Request::CheckAuthContext(request) => Err(Error::RequestNotAvailable),

            Request::WriteAuthContext(request) => Err(Error::RequestNotAvailable),

            Request::Agree(request) => {
                let pub_path = keystore.key_path(key::Secrecy::Public, &request.public_key);
                let sec_path = keystore.key_path(key::Secrecy::Secret, &request.private_key);

                // get policy for pub_path
                // compare policy with Permission::Agree
                // continue or return Error::AuthorizationDenied

                match request.mechanism {
                    Mechanism::P256 => mechanisms::P256::agree(keystore, request),
                    Mechanism::X255 => mechanisms::X255::agree(keystore, request),
                    _ => Err(Error::MechanismNotAvailable),
                }
                .map(Reply::Agree)
            }

            Request::Attest(request) => {
                let mut attn_keystore: ClientKeystore<S> = ClientKeystore::new(
                    PathBuf::from("attn"),
                    self.rng(plat_rng, plat_store)
                        .map_err(|_| Error::EntropyMalfunction)?,
                    full_store,
                );
                attest::try_attest(&mut attn_keystore, certstore, keystore, request)
                    .map(Reply::Attest)
            }

            Request::Decrypt(request) => match request.mechanism {
                Mechanism::Aes256Cbc => mechanisms::Aes256Cbc::decrypt(keystore, request),
                Mechanism::Chacha8Poly1305 => {
                    mechanisms::Chacha8Poly1305::decrypt(keystore, request)
                }
                Mechanism::Tdes => mechanisms::Tdes::decrypt(keystore, request),
                _ => Err(Error::MechanismNotAvailable),
            }
            .map(Reply::Decrypt),

            Request::DeriveKey(request) => match request.mechanism {
                Mechanism::HmacBlake2s => mechanisms::HmacBlake2s::derive_key(keystore, request),
                Mechanism::HmacSha1 => mechanisms::HmacSha1::derive_key(keystore, request),
                Mechanism::HmacSha256 => mechanisms::HmacSha256::derive_key(keystore, request),
                Mechanism::HmacSha512 => mechanisms::HmacSha512::derive_key(keystore, request),
                Mechanism::Ed255 => mechanisms::Ed255::derive_key(keystore, request),
                Mechanism::P256 => mechanisms::P256::derive_key(keystore, request),
                Mechanism::Sha256 => mechanisms::Sha256::derive_key(keystore, request),
                Mechanism::X255 => mechanisms::X255::derive_key(keystore, request),
                _ => Err(Error::MechanismNotAvailable),
            }
            .map(Reply::DeriveKey),

            Request::DeserializeKey(request) => match request.mechanism {
                Mechanism::Ed255 => mechanisms::Ed255::deserialize_key(keystore, request),
                Mechanism::P256 => mechanisms::P256::deserialize_key(keystore, request),
                Mechanism::X255 => mechanisms::X255::deserialize_key(keystore, request),
                _ => Err(Error::MechanismNotAvailable),
            }
            .map(Reply::DeserializeKey),

            Request::Encrypt(request) => match request.mechanism {
                Mechanism::Aes256Cbc => mechanisms::Aes256Cbc::encrypt(keystore, request),
                Mechanism::Chacha8Poly1305 => {
                    mechanisms::Chacha8Poly1305::encrypt(keystore, request)
                }
                Mechanism::Tdes => mechanisms::Tdes::encrypt(keystore, request),
                _ => Err(Error::MechanismNotAvailable),
            }
            .map(Reply::Encrypt),

            Request::Delete(request) => {
                let success = keystore.delete_key(&request.key);
                Ok(Reply::Delete(reply::Delete { success }))
            }

            Request::DeleteAllKeys(request) => {
                let count = keystore.delete_all(request.location)?;
                Ok(Reply::DeleteAllKeys(reply::DeleteAllKeys { count }))
            }

            Request::GenerateKey(request) => match request.mechanism {
                Mechanism::Chacha8Poly1305 => {
                    mechanisms::Chacha8Poly1305::generate_key(keystore, request)
                }
                Mechanism::Ed255 => mechanisms::Ed255::generate_key(keystore, request),
                Mechanism::P256 => mechanisms::P256::generate_key(keystore, request),
                Mechanism::X255 => mechanisms::X255::generate_key(keystore, request),
                _ => Err(Error::MechanismNotAvailable),
            }
            .map(Reply::GenerateKey),

            Request::GenerateSecretKey(request) => {
                let mut secret_key = MediumData::new();
                let size = request.size;
                secret_key
                    .resize_default(request.size)
                    .map_err(|_| Error::ImplementationError)?;
                keystore.rng().fill_bytes(&mut secret_key[..size]);
                let key_id = keystore.store_key(
                    request.attributes.persistence,
                    key::Secrecy::Secret,
                    key::Kind::Symmetric(size),
                    &secret_key[..size],
                )?;
                Ok(Reply::GenerateSecretKey(reply::GenerateSecretKey {
                    key: key_id,
                }))
            }

            Request::SerializeKey(request) => match request.mechanism {
                Mechanism::Ed255 => mechanisms::Ed255::serialize_key(keystore, request),
                Mechanism::P256 => mechanisms::P256::serialize_key(keystore, request),
                Mechanism::X255 => mechanisms::X255::serialize_key(keystore, request),
                Mechanism::SharedSecret => {
                    mechanisms::SharedSecret::serialize_key(keystore, request)
                }
                _ => Err(Error::MechanismNotAvailable),
            }
            .map(Reply::SerializeKey),

            Request::Sign(request) => match request.mechanism {
                Mechanism::Ed255 => mechanisms::Ed255::sign(keystore, request),
                Mechanism::HmacBlake2s => mechanisms::HmacBlake2s::sign(keystore, request),
                Mechanism::HmacSha1 => mechanisms::HmacSha1::sign(keystore, request),
                Mechanism::HmacSha256 => mechanisms::HmacSha256::sign(keystore, request),
                Mechanism::HmacSha512 => mechanisms::HmacSha512::sign(keystore, request),
                Mechanism::P256 => mechanisms::P256::sign(keystore, request),
                Mechanism::P256Prehashed => mechanisms::P256Prehashed::sign(keystore, request),
                Mechanism::Totp => mechanisms::Totp::sign(keystore, request),
                _ => Err(Error::MechanismNotAvailable),
            }
            .map(Reply::Sign),

            Request::UnwrapKey(request) => match request.mechanism {
                Mechanism::Chacha8Poly1305 => {
                    mechanisms::Chacha8Poly1305::unwrap_key(keystore, request)
                }
                _ => Err(Error::MechanismNotAvailable),
            }
            .map(Reply::UnwrapKey),

            Request::Verify(request) => match request.mechanism {
                Mechanism::Ed255 => mechanisms::Ed255::verify(keystore, request),
                Mechanism::P256 => mechanisms::P256::verify(keystore, request),
                _ => Err(Error::MechanismNotAvailable),
            }
            .map(Reply::Verify),

            Request::WrapKey(request) => match request.mechanism {
                Mechanism::Aes256Cbc => mechanisms::Aes256Cbc::wrap_key(keystore, request),
                Mechanism::Chacha8Poly1305 => {
                    mechanisms::Chacha8Poly1305::wrap_key(keystore, request)
                }
                _ => Err(Error::MechanismNotAvailable),
            }
            .map(Reply::WrapKey),

            _ => Err(Error::RequestNotAvailable),
        }
    }
}
