use littlefs2_core::{path, PathBuf};
use rand_chacha::ChaCha8Rng;
pub use rand_core::{RngCore, SeedableRng};

use crate::api::{reply, request, Reply, Request};
use crate::backend::{BackendId, CoreOnly, Dispatch};
use crate::config::MAX_MESSAGE_LENGTH;
use crate::error::{Error, Result};
pub use crate::key;
#[cfg(feature = "crypto-client")]
use crate::mechanisms;
pub use crate::pipe::ServiceEndpoint;
use crate::platform::{consent, ui, Platform, UserInterface};
pub use crate::store::{
    self,
    certstore::{Certstore as _, ClientCertstore},
    counterstore::{ClientCounterstore, Counterstore as _},
    filestore::{ClientFilestore, Filestore, ReadDirFilesState, ReadDirState},
    keystore::{ClientKeystore, Keystore},
};
use crate::types::ui::Status;
use crate::types::{Context, CoreContext, Location, Mechanism, MediumData, Message};
use crate::Bytes;

#[cfg(feature = "attestation-client")]
pub mod attest;

// #[macro_use]
// mod macros;

#[cfg(feature = "crypto-client")]
macro_rules! impl_mechanisms {
    {
        [
            $(
                #[cfg($($cfg_cond:tt)*)]
                $mechanism:ident,
            )*
        ]
    } => {
        pub const IMPLEMENTED_MECHANISMS: &[Mechanism] = &[
            $(
                #[cfg($($cfg_cond)*)]
                Mechanism::$mechanism,
            )*
        ];
    }
}

#[cfg(feature = "crypto-client")]
macro_rules! impl_rpc_method {
    {
        $struct:ident,
        $method:ident,
        mechanisms = [$(
            #[cfg($($cfg_cond:tt)*)]
            $mechanism:ident,
        )*],
    } => {
        #[inline(never)]
        fn $method(
            &self,
            keystore: &mut impl Keystore,
            request: &request::$struct,
        ) -> Result<reply::$struct> {
            match self {
                $(
                    #[cfg($($cfg_cond)*)]
                    Self::$mechanism => mechanisms::$mechanism.$method(keystore, request),
                )*
                _ => Err(Error::MechanismNotAvailable),
            }
        }
    }
}

#[cfg(feature = "crypto-client")]
macro_rules! rpc_trait {
    {
        methods = [$($method:ident: $struct:ident,)*],
        mechanisms = $mechanisms:tt,
    } => {
        pub trait MechanismImpl {
            $(
                fn $method(
                    &self,
                    keystore: &mut impl Keystore,
                    request: &request::$struct,
                ) -> Result<reply::$struct> {
                    let _ = (keystore, request);
                    Err(Error::MechanismNotAvailable)
                }
            )*
        }

        impl MechanismImpl for Mechanism {
            $(
                impl_rpc_method! {
                    $struct,
                    $method,
                    mechanisms = $mechanisms,
                }
            )*
        }

        impl_mechanisms! {
            $mechanisms
        }
    }
}

#[cfg(feature = "crypto-client")]
rpc_trait! {
    methods = [
        agree: Agree,
        decrypt: Decrypt,
        derive_key: DeriveKey,
        deserialize_key: DeserializeKey,
        encrypt: Encrypt,
        exists: Exists,
        generate_key: GenerateKey,
        hash: Hash,
        serialize_key: SerializeKey,
        sign: Sign,
        unsafe_inject_key: UnsafeInjectKey,
        unwrap_key: UnwrapKey,
        verify: Verify,
        // TODO: can the default implementation be implemented in terms of Encrypt?
        wrap_key: WrapKey,
    ],
    mechanisms = [
        #[cfg(feature = "aes256-cbc")]
        Aes256Cbc,
        #[cfg(feature = "chacha8-poly1305")]
        Chacha8Poly1305,
        #[cfg(feature = "ed255")]
        Ed255,
        #[cfg(feature = "hmac-blake2s")]
        HmacBlake2s,
        #[cfg(feature = "hmac-sha1")]
        HmacSha1,
        #[cfg(feature = "hmac-sha256")]
        HmacSha256,
        #[cfg(feature = "hmac-sha512")]
        HmacSha512,
        #[cfg(feature = "p256")]
        P256,
        #[cfg(feature = "p256")]
        P256Prehashed,
        #[cfg(feature = "p384")]
        P384,
        #[cfg(feature = "p384")]
        P384Prehashed,
        #[cfg(feature = "p521")]
        P521,
        #[cfg(feature = "p521")]
        P521Prehashed,
        #[cfg(feature = "sha256")]
        Sha256,
        #[cfg(feature = "shared-secret")]
        SharedSecret,
        #[cfg(feature = "tdes")]
        Tdes,
        #[cfg(feature = "totp")]
        Totp,
        #[cfg(feature = "trng")]
        Trng,
        #[cfg(feature = "x255")]
        X255,
    ],
}

pub struct ServiceResources<P>
where
    P: Platform,
{
    platform: P,
    rng_state: Option<ChaCha8Rng>,
}

impl<P: Platform> ServiceResources<P> {
    pub fn new(platform: P) -> Self {
        Self {
            platform,
            rng_state: None,
        }
    }

    pub fn platform(&self) -> &P {
        &self.platform
    }

    pub fn platform_mut(&mut self) -> &mut P {
        &mut self.platform
    }
}

pub struct Service<P, D = CoreOnly>
where
    P: Platform,
    D: Dispatch,
{
    resources: ServiceResources<P>,
    dispatch: D,
}

// need to be able to send crypto service to an interrupt handler
unsafe impl<P: Platform, D: Dispatch> Send for Service<P, D> {}

impl<P: Platform> ServiceResources<P> {
    pub fn certstore(&mut self, ctx: &CoreContext) -> Result<ClientCertstore<P::S>> {
        self.rng()
            .map(|rng| ClientCertstore::new(ctx.path.clone(), rng, self.platform.store()))
            .map_err(|_| Error::EntropyMalfunction)
    }

    pub fn counterstore(&mut self, ctx: &CoreContext) -> Result<ClientCounterstore<P::S>> {
        self.rng()
            .map(|rng| ClientCounterstore::new(ctx.path.clone(), rng, self.platform.store()))
            .map_err(|_| Error::EntropyMalfunction)
    }

    pub fn filestore(&mut self, client_id: PathBuf) -> ClientFilestore<P::S> {
        ClientFilestore::new(client_id, self.platform.store())
    }

    /// Get access to the filestore for the client without the `dat` intermediary
    pub fn raw_filestore(&mut self, client_id: PathBuf) -> ClientFilestore<P::S> {
        ClientFilestore::new_raw(client_id, self.platform.store())
    }

    pub fn trussed_filestore(&mut self) -> ClientFilestore<P::S> {
        ClientFilestore::new(PathBuf::from(path!("trussed")), self.platform.store())
    }

    pub fn keystore(&mut self, client_id: PathBuf) -> Result<ClientKeystore<P::S>> {
        self.rng()
            .map(|rng| ClientKeystore::new(client_id, rng, self.platform.store()))
            .map_err(|_| Error::EntropyMalfunction)
    }

    pub fn dispatch<D: Dispatch>(
        &mut self,
        dispatch: &mut D,
        backend: &BackendId<D::BackendId>,
        ctx: &mut Context<D::Context>,
        request: &Request,
    ) -> Result<Reply, Error> {
        match backend {
            BackendId::Core => self.reply_to(&mut ctx.core, request),
            BackendId::Custom(backend) => dispatch.request(backend, ctx, request, self),
        }
    }

    #[inline(never)]
    pub fn reply_to(&mut self, ctx: &mut CoreContext, request: &Request) -> Result<Reply> {
        // TODO: what we want to do here is map an enum to a generic type
        // Is there a nicer way to do this?

        /// Coerce an FnMut into a FnOnce to ensure the stores are not created twice by mistake
        fn once<R, P>(
            generator: impl FnMut(&mut ServiceResources<P>, &mut CoreContext) -> R,
        ) -> impl FnOnce(&mut ServiceResources<P>, &mut CoreContext) -> R {
            generator
        }

        #[cfg(feature = "attestation-client")]
        let full_store = self.platform.store();

        #[cfg(any(feature = "attestation-client", feature = "crypto-client"))]
        let keystore = once(|this, ctx| this.keystore(ctx.path.clone()));
        #[cfg(any(feature = "attestation-client", feature = "certificate-client"))]
        let certstore = once(|this, ctx| this.certstore(ctx));
        #[cfg(feature = "counter-client")]
        let counterstore = once(|this, ctx| this.counterstore(ctx));

        #[cfg(feature = "filesystem-client")]
        let filestore = &mut self.filestore(ctx.path.clone());

        debug_now!("TRUSSED {:?}", request);
        match request {
            #[cfg(feature = "filesystem-client")]
            Request::DummyRequest => Ok(Reply::DummyReply),

            #[cfg(feature = "crypto-client")]
            Request::Agree(request) => request
                .mechanism
                .agree(&mut keystore(self, ctx)?, request)
                .map(Reply::Agree),

            #[cfg(feature = "attestation-client")]
            Request::Attest(request) => {
                let mut attn_keystore: ClientKeystore<P::S> = ClientKeystore::new(
                    PathBuf::from(path!("attn")),
                    self.rng().map_err(|_| Error::EntropyMalfunction)?,
                    full_store,
                );
                attest::try_attest(
                    &mut attn_keystore,
                    &mut certstore(self, ctx)?,
                    &mut keystore(self, ctx)?,
                    request,
                )
                .map(Reply::Attest)
            }

            #[cfg(feature = "crypto-client")]
            Request::Decrypt(request) => request
                .mechanism
                .decrypt(&mut keystore(self, ctx)?, request)
                .map(Reply::Decrypt),

            #[cfg(feature = "crypto-client")]
            Request::DeriveKey(request) => request
                .mechanism
                .derive_key(&mut keystore(self, ctx)?, request)
                .map(Reply::DeriveKey),

            #[cfg(feature = "crypto-client")]
            Request::DeserializeKey(request) => request
                .mechanism
                .deserialize_key(&mut keystore(self, ctx)?, request)
                .map(Reply::DeserializeKey),

            #[cfg(feature = "crypto-client")]
            Request::Encrypt(request) => request
                .mechanism
                .encrypt(&mut keystore(self, ctx)?, request)
                .map(Reply::Encrypt),

            #[cfg(feature = "crypto-client")]
            Request::Delete(request) => {
                let success = keystore(self, ctx)?.delete_key(&request.key);
                Ok(Reply::Delete(reply::Delete { success }))
            }

            #[cfg(feature = "crypto-client")]
            Request::Clear(request) => {
                let success = keystore(self, ctx)?.clear_key(&request.key);
                Ok(Reply::Clear(reply::Clear { success }))
            }

            #[cfg(feature = "crypto-client")]
            Request::DeleteAllKeys(request) => {
                let count = keystore(self, ctx)?.delete_all(request.location)?;
                Ok(Reply::DeleteAllKeys(reply::DeleteAllKeys { count }))
            }

            #[cfg(feature = "crypto-client")]
            Request::Exists(request) => request
                .mechanism
                .exists(&mut keystore(self, ctx)?, request)
                .map(Reply::Exists),

            #[cfg(feature = "crypto-client")]
            Request::GenerateKey(request) => request
                .mechanism
                .generate_key(&mut keystore(self, ctx)?, request)
                .map(Reply::GenerateKey),

            #[cfg(feature = "crypto-client")]
            Request::GenerateSecretKey(request) => {
                let mut secret_key = MediumData::new();
                let size = request.size;
                let mut keystore = keystore(self, ctx)?;
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

            // deprecated
            #[cfg(feature = "crypto-client")]
            Request::UnsafeInjectKey(request) => request
                .mechanism
                .unsafe_inject_key(&mut keystore(self, ctx)?, request)
                .map(Reply::UnsafeInjectKey),

            #[cfg(feature = "crypto-client")]
            Request::UnsafeInjectSharedKey(request) => {
                let key_id = keystore(self, ctx)?.store_key(
                    request.location,
                    key::Secrecy::Secret,
                    key::Kind::Shared(request.raw_key.len()),
                    &request.raw_key,
                )?;

                Ok(Reply::UnsafeInjectSharedKey(reply::UnsafeInjectSharedKey {
                    key: key_id,
                }))
            }

            #[cfg(feature = "crypto-client")]
            Request::Hash(request) => request
                .mechanism
                .hash(&mut keystore(self, ctx)?, request)
                .map(Reply::Hash),

            #[cfg(feature = "filesystem-client")]
            Request::LocateFile(request) => {
                let path = filestore.locate_file(
                    request.location,
                    request.dir.as_deref(),
                    &request.filename,
                )?;

                Ok(Reply::LocateFile(reply::LocateFile { path }))
            }

            #[cfg(feature = "filesystem-client")]
            Request::DebugDumpStore(_request) => {
                error!("DebugDumpStore is deprecated");
                Ok(Reply::DebugDumpStore(reply::DebugDumpStore {}))
            }

            #[cfg(feature = "filesystem-client")]
            Request::ReadDirFirst(request) => {
                let maybe_entry = match filestore.read_dir_first(
                    &request.dir,
                    request.location,
                    &request.not_before,
                )? {
                    Some((entry, read_dir_state)) => {
                        ctx.read_dir_state = Some(read_dir_state);
                        Some(entry)
                    }
                    None => {
                        ctx.read_dir_state = None;
                        None
                    }
                };
                Ok(Reply::ReadDirFirst(reply::ReadDirFirst {
                    entry: maybe_entry,
                }))
            }

            #[cfg(feature = "filesystem-client")]
            Request::ReadDirNext(_request) => {
                // ensure next call has nothing to work with, unless we store state again
                let read_dir_state = ctx.read_dir_state.take();

                let maybe_entry = match read_dir_state {
                    None => None,
                    Some(state) => match filestore.read_dir_next(state)? {
                        Some((entry, read_dir_state)) => {
                            ctx.read_dir_state = Some(read_dir_state);
                            Some(entry)
                        }
                        None => {
                            ctx.read_dir_state = None;
                            None
                        }
                    },
                };

                Ok(Reply::ReadDirNext(reply::ReadDirNext {
                    entry: maybe_entry,
                }))
            }

            #[cfg(feature = "filesystem-client")]
            Request::ReadDirFilesFirst(request) => {
                let maybe_data = match filestore.read_dir_files_first(
                    &request.dir,
                    request.location,
                    request.user_attribute.clone(),
                )? {
                    Some((data, state)) => {
                        ctx.read_dir_files_state = Some(state);
                        data
                    }
                    None => {
                        ctx.read_dir_files_state = None;
                        None
                    }
                };
                Ok(Reply::ReadDirFilesFirst(reply::ReadDirFilesFirst {
                    data: maybe_data,
                }))
            }

            #[cfg(feature = "filesystem-client")]
            Request::ReadDirFilesNext(_request) => {
                let read_dir_files_state = ctx.read_dir_files_state.take();

                let maybe_data = match read_dir_files_state {
                    None => None,
                    Some(state) => match filestore.read_dir_files_next(state)? {
                        Some((data, state)) => {
                            ctx.read_dir_files_state = Some(state);
                            data
                        }
                        None => {
                            ctx.read_dir_files_state = None;
                            None
                        }
                    },
                };
                Ok(Reply::ReadDirFilesNext(reply::ReadDirFilesNext {
                    data: maybe_data,
                }))
            }

            #[cfg(feature = "filesystem-client")]
            Request::RemoveDir(request) => {
                filestore.remove_dir(&request.path, request.location)?;
                Ok(Reply::RemoveDir(reply::RemoveDir {}))
            }

            #[cfg(feature = "filesystem-client")]
            Request::RemoveDirAll(request) => {
                let count = filestore.remove_dir_all(&request.path, request.location)?;
                Ok(Reply::RemoveDirAll(reply::RemoveDirAll { count }))
            }

            #[cfg(feature = "filesystem-client")]
            Request::RemoveFile(request) => {
                filestore.remove_file(&request.path, request.location)?;
                Ok(Reply::RemoveFile(reply::RemoveFile {}))
            }

            #[cfg(feature = "filesystem-client")]
            Request::ReadFile(request) => Ok(Reply::ReadFile(reply::ReadFile {
                data: filestore.read(&request.path, request.location)?,
            })),

            #[cfg(feature = "filesystem-client")]
            Request::Metadata(request) => Ok(Reply::Metadata(reply::Metadata {
                metadata: filestore.metadata(&request.path, request.location)?,
            })),

            #[cfg(feature = "filesystem-client")]
            Request::Rename(request) => {
                filestore.rename(&request.from, &request.to, request.location)?;
                Ok(Reply::Rename(reply::Rename {}))
            }

            #[cfg(feature = "crypto-client")]
            Request::RandomBytes(request) => {
                if request.count <= MAX_MESSAGE_LENGTH {
                    let mut bytes = Message::new();
                    bytes.resize_default(request.count).unwrap();
                    self.rng()?.fill_bytes(&mut bytes);
                    Ok(Reply::RandomBytes(reply::RandomBytes { bytes }))
                } else {
                    Err(Error::MechanismNotAvailable)
                }
            }

            #[cfg(feature = "crypto-client")]
            Request::SerializeKey(request) => request
                .mechanism
                .serialize_key(&mut keystore(self, ctx)?, request)
                .map(Reply::SerializeKey),

            #[cfg(feature = "crypto-client")]
            Request::Sign(request) => request
                .mechanism
                .sign(&mut keystore(self, ctx)?, request)
                .map(Reply::Sign),

            #[cfg(feature = "filesystem-client")]
            Request::WriteFile(request) => {
                filestore.write(&request.path, request.location, &request.data)?;
                Ok(Reply::WriteFile(reply::WriteFile {}))
            }

            #[cfg(feature = "crypto-client")]
            Request::UnwrapKey(request) => request
                .mechanism
                .unwrap_key(&mut keystore(self, ctx)?, request)
                .map(Reply::UnwrapKey),

            #[cfg(feature = "crypto-client")]
            Request::Verify(request) => request
                .mechanism
                .verify(&mut keystore(self, ctx)?, request)
                .map(Reply::Verify),

            #[cfg(feature = "crypto-client")]
            Request::WrapKey(request) => request
                .mechanism
                .wrap_key(&mut keystore(self, ctx)?, request)
                .map(Reply::WrapKey),

            #[cfg(feature = "ui-client")]
            Request::RequestUserConsent(request) => {
                // assert_eq!(request.level, consent::Level::Normal);

                let starttime = self.platform.user_interface().uptime();
                let timeout =
                    core::time::Duration::from_millis(request.timeout_milliseconds as u64);

                let previous_status = self.platform.user_interface().status();
                self.platform
                    .user_interface()
                    .set_status(ui::Status::WaitingForUserPresence);
                loop {
                    if ctx.interrupt.map(|i| i.is_interrupted()) == Some(true) {
                        info_now!("User presence request cancelled");
                        return Ok(reply::RequestUserConsent {
                            result: Err(consent::Error::Interrupted),
                        }
                        .into());
                    }

                    self.platform.user_interface().refresh();
                    let nowtime = self.platform.user_interface().uptime();
                    if (nowtime - starttime) > timeout {
                        let result = Err(consent::Error::TimedOut);
                        return Ok(Reply::RequestUserConsent(reply::RequestUserConsent {
                            result,
                        }));
                    }
                    let up = self.platform.user_interface().check_user_presence();
                    match request.level {
                        // If Normal level consent is request, then both Strong and Normal
                        // indications will result in success.
                        consent::Level::Normal => {
                            if up == consent::Level::Normal || up == consent::Level::Strong {
                                break;
                            }
                        }
                        // Otherwise, only strong level indication will work.
                        consent::Level::Strong => {
                            if up == consent::Level::Strong {
                                break;
                            }
                        }
                        _ => {
                            break;
                        }
                    }
                }
                self.platform.user_interface().set_status(previous_status);

                let result = Ok(());
                Ok(Reply::RequestUserConsent(reply::RequestUserConsent {
                    result,
                }))
            }

            #[cfg(feature = "management-client")]
            Request::Reboot(request) => {
                self.platform.user_interface().reboot(request.to);
            }

            #[cfg(feature = "management-client")]
            Request::Uptime(_request) => Ok(Reply::Uptime(reply::Uptime {
                uptime: self.platform.user_interface().uptime(),
            })),

            #[cfg(feature = "ui-client")]
            Request::Wink(request) => {
                self.platform.user_interface().wink(request.duration);
                Ok(Reply::Wink(reply::Wink {}))
            }

            #[cfg(feature = "ui-client")]
            Request::SetCustomStatus(request) => {
                self.platform
                    .user_interface()
                    .set_status(Status::Custom(request.status));
                Ok(Reply::SetCustomStatus(reply::SetCustomStatus {}))
            }

            #[cfg(feature = "counter-client")]
            Request::CreateCounter(request) => counterstore(self, ctx)?
                .create(request.location)
                .map(|id| Reply::CreateCounter(reply::CreateCounter { id })),

            #[cfg(feature = "counter-client")]
            Request::IncrementCounter(request) => counterstore(self, ctx)?
                .increment(request.id)
                .map(|counter| Reply::IncrementCounter(reply::IncrementCounter { counter })),

            #[cfg(feature = "certificate-client")]
            Request::DeleteCertificate(request) => certstore(self, ctx)?
                .delete_certificate(request.id)
                .map(|_| Reply::DeleteCertificate(reply::DeleteCertificate {})),

            #[cfg(feature = "certificate-client")]
            Request::ReadCertificate(request) => certstore(self, ctx)?
                .read_certificate(request.id)
                .map(|der| Reply::ReadCertificate(reply::ReadCertificate { der })),

            #[cfg(feature = "certificate-client")]
            Request::WriteCertificate(request) => certstore(self, ctx)?
                .write_certificate(request.location, &request.der)
                .map(|id| Reply::WriteCertificate(reply::WriteCertificate { id })),

            _ => Err(Error::RequestNotAvailable),
        }
    }

    /// Applies a splitting aka forking construction to the inner DRBG,
    /// returning an independent DRBG.
    pub fn rng(&mut self) -> Result<ChaCha8Rng, Error> {
        // Check if our RNG is loaded.
        let mut rng = match self.rng_state.take() {
            Some(rng) => rng,
            None => {
                let mut filestore = self.trussed_filestore();

                let path = path!("rng-state.bin");

                // Load previous seed, e.g., externally injected entropy on first run.
                // Else, default to zeros - will mix in new HW RNG entropy next
                let mixin_seed = if !filestore.exists(path, Location::Internal) {
                    [0u8; 32]
                } else {
                    // Use the last saved state.
                    let mixin_bytes: Bytes<32> = filestore.read(path, Location::Internal)?;
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
                self.platform
                    .rng()
                    .try_fill_bytes(&mut entropy)
                    .map_err(|_| Error::EntropyMalfunction)?;

                // 2. Mix into our previously stored seed.
                let mut our_seed = [0u8; 32];
                for i in 0..32 {
                    our_seed[i] = mixin_seed[i] ^ entropy[i];
                }

                // 3. Initialize ChaCha8 construction with our seed.
                let mut rng = ChaCha8Rng::from_seed(our_seed);

                // 4. Store freshly drawn seed for next boot.
                let mut seed_to_store = [0u8; 32];
                rng.fill_bytes(&mut seed_to_store);
                filestore
                    .write(path, Location::Internal, seed_to_store.as_ref())
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

    pub fn fill_random_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        self.rng()?.fill_bytes(bytes);
        Ok(())
    }
}

impl<P: Platform> Service<P> {
    pub fn new(platform: P) -> Self {
        Self::with_dispatch(platform, Default::default())
    }
}

impl<P: Platform, D: Dispatch> Service<P, D> {
    pub fn with_dispatch(platform: P, dispatch: D) -> Self {
        let resources = ServiceResources::new(platform);
        Self {
            resources,
            dispatch,
        }
    }
}

impl<P: Platform, D: Dispatch> Service<P, D> {
    pub fn set_seed_if_uninitialized(&mut self, seed: &[u8; 32]) {
        let mut filestore = self.resources.trussed_filestore();
        let path = path!("rng-state.bin");
        if !filestore.exists(path, Location::Internal) {
            filestore
                .write(path, Location::Internal, seed.as_ref())
                .unwrap();
        }
    }

    // currently, this just blinks the green heartbeat LED (former toggle_red in app_rtic.rs)
    //
    // in future, this would
    // - generate more interesting LED visuals
    // - return "when" next to be called
    // - potentially read out button status and return "async"
    pub fn update_ui(&mut self) /* -> u32 */
    {
        self.resources.platform.user_interface().refresh();
    }

    // process one request per client which has any
    pub fn process(&mut self, eps: &mut [ServiceEndpoint<D::BackendId, D::Context>]) {
        for ep in eps {
            if let Ok(request) = ep.interchange.request() {
                self.resources
                    .platform
                    .user_interface()
                    .set_status(ui::Status::Processing);
                // #[cfg(test)] println!("service got request: {:?}", &request);

                // resources.currently_serving = ep.client_id.clone();
                let reply_result = if ep.backends.is_empty() {
                    self.resources.reply_to(&mut ep.ctx.core, request)
                } else {
                    let mut reply_result = Err(Error::RequestNotAvailable);
                    for backend in ep.backends {
                        reply_result = self.resources.dispatch(
                            &mut self.dispatch,
                            backend,
                            &mut ep.ctx,
                            request,
                        );
                        if reply_result != Err(Error::RequestNotAvailable) {
                            break;
                        }
                    }
                    reply_result
                };

                self.resources
                    .platform
                    .user_interface()
                    .set_status(ui::Status::Idle);
                if ep.interchange.respond(reply_result).is_err() && ep.interchange.is_canceled() {
                    info!("Cancelled request");
                    ep.interchange.acknowledge_cancel().ok();
                };
            }
        }

        #[cfg(all(
            any(feature = "log-debug", feature = "log-all"),
            not(feature = "log-none")
        ))]
        use crate::store::Store as _;

        debug_now!(
            "I/E/V : {}/{}/{} >",
            self.resources
                .platform
                .store()
                .fs(Location::Internal)
                .available_blocks()
                .unwrap(),
            self.resources
                .platform
                .store()
                .fs(Location::External)
                .available_blocks()
                .unwrap(),
            self.resources
                .platform
                .store()
                .fs(Location::Volatile)
                .available_blocks()
                .unwrap(),
        );
    }

    pub fn dispatch(&self) -> &D {
        &self.dispatch
    }

    pub fn dispatch_mut(&mut self) -> &mut D {
        &mut self.dispatch
    }
}
