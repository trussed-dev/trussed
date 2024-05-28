use littlefs2::{
    object_safe::DynFilesystem,
    path,
    path::{Path, PathBuf},
};
use rand_chacha::ChaCha8Rng;
pub use rand_core::{RngCore, SeedableRng};

use crate::backend::{BackendId, CoreOnly, Dispatch};
use crate::client::{ClientBuilder, ClientImplementation};
use crate::config::{MAX_MESSAGE_LENGTH, MAX_SERVICE_CLIENTS};
use crate::error::{Error, Result};
pub use crate::key;
use crate::mechanisms;
pub use crate::pipe::ServiceEndpoint;
use crate::pipe::TrussedResponder;
use crate::platform::{consent, ui, Platform, Store, Syscall, UserInterface};
pub use crate::store::{
    self,
    certstore::{Certstore as _, ClientCertstore},
    counterstore::{ClientCounterstore, Counterstore as _},
    filestore::{ClientFilestore, Filestore, ReadDirFilesState, ReadDirState},
    keystore::{ClientKeystore, Keystore},
};
use crate::types::ui::Status;
use crate::types::{Context, CoreContext, Location, Mechanism, MediumData, Message, Vec};
use crate::Bytes;
use crate::{
    api::{reply, request, Reply, Request},
    interrupt::InterruptFlag,
};

pub mod attest;

// #[macro_use]
// mod macros;

macro_rules! rpc_trait { ($($Name:ident, $name:ident,)*) => { $(

    pub trait $Name {
        fn $name(_keystore: &mut impl Keystore, _request: &request::$Name)
        -> Result<reply::$Name> { Err(Error::MechanismNotAvailable) }
    }
)* } }

rpc_trait! {
    Agree, agree,
    Decrypt, decrypt,
    DeriveKey, derive_key,
    DeserializeKey, deserialize_key,
    Encrypt, encrypt,
    Exists, exists,
    GenerateKey, generate_key,
    Hash, hash,
    SerializeKey, serialize_key,
    Sign, sign,
    UnsafeInjectKey, unsafe_inject_key,
    UnwrapKey, unwrap_key,
    Verify, verify,
    // TODO: can the default implementation be implemented in terms of Encrypt?
    WrapKey, wrap_key,
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
    eps: Vec<ServiceEndpoint<D::BackendId, D::Context>, { MAX_SERVICE_CLIENTS }>,
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
        ClientFilestore::new(PathBuf::from("trussed"), self.platform.store())
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

        #[cfg(feature = "crypto-client-attest")]
        let full_store = self.platform.store();

        let keystore = once(|this, ctx| this.keystore(ctx.path.clone()));
        let certstore = once(|this, ctx| this.certstore(ctx));
        #[cfg(feature = "counter-client")]
        let counterstore = once(|this, ctx| this.counterstore(ctx));

        let filestore = &mut self.filestore(ctx.path.clone());

        debug_now!("TRUSSED {:?}", request);
        match request {
            Request::DummyRequest => Ok(Reply::DummyReply),

            Request::Agree(request) => match request.mechanism {
                Mechanism::P256 => mechanisms::P256::agree(&mut keystore(self, ctx)?, request),
                Mechanism::X255 => mechanisms::X255::agree(&mut keystore(self, ctx)?, request),
                _ => Err(Error::MechanismNotAvailable),
            }
            .map(Reply::Agree),

            #[cfg(feature = "crypto-client-attest")]
            Request::Attest(request) => {
                let mut attn_keystore: ClientKeystore<P::S> = ClientKeystore::new(
                    PathBuf::from("attn"),
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

            #[cfg(not(feature = "crypto-client-attest"))]
            Request::Attest(_) => Err(Error::RequestNotAvailable),

            Request::Decrypt(request) => match request.mechanism {
                Mechanism::Aes256Cbc => {
                    mechanisms::Aes256Cbc::decrypt(&mut keystore(self, ctx)?, request)
                }
                Mechanism::Chacha8Poly1305 => {
                    mechanisms::Chacha8Poly1305::decrypt(&mut keystore(self, ctx)?, request)
                }
                Mechanism::Tdes => mechanisms::Tdes::decrypt(&mut keystore(self, ctx)?, request),
                _ => Err(Error::MechanismNotAvailable),
            }
            .map(Reply::Decrypt),

            Request::DeriveKey(request) => match request.mechanism {
                Mechanism::HmacBlake2s => {
                    mechanisms::HmacBlake2s::derive_key(&mut keystore(self, ctx)?, request)
                }
                Mechanism::HmacSha1 => {
                    mechanisms::HmacSha1::derive_key(&mut keystore(self, ctx)?, request)
                }
                Mechanism::HmacSha256 => {
                    mechanisms::HmacSha256::derive_key(&mut keystore(self, ctx)?, request)
                }
                Mechanism::HmacSha512 => {
                    mechanisms::HmacSha512::derive_key(&mut keystore(self, ctx)?, request)
                }
                Mechanism::Ed255 => {
                    mechanisms::Ed255::derive_key(&mut keystore(self, ctx)?, request)
                }
                Mechanism::P256 => mechanisms::P256::derive_key(&mut keystore(self, ctx)?, request),
                Mechanism::Sha256 => {
                    mechanisms::Sha256::derive_key(&mut keystore(self, ctx)?, request)
                }
                Mechanism::X255 => mechanisms::X255::derive_key(&mut keystore(self, ctx)?, request),
                _ => Err(Error::MechanismNotAvailable),
            }
            .map(Reply::DeriveKey),

            Request::DeserializeKey(request) => match request.mechanism {
                Mechanism::Ed255 => {
                    mechanisms::Ed255::deserialize_key(&mut keystore(self, ctx)?, request)
                }
                Mechanism::P256 => {
                    mechanisms::P256::deserialize_key(&mut keystore(self, ctx)?, request)
                }
                Mechanism::X255 => {
                    mechanisms::X255::deserialize_key(&mut keystore(self, ctx)?, request)
                }
                _ => Err(Error::MechanismNotAvailable),
            }
            .map(Reply::DeserializeKey),

            Request::Encrypt(request) => match request.mechanism {
                Mechanism::Aes256Cbc => {
                    mechanisms::Aes256Cbc::encrypt(&mut keystore(self, ctx)?, request)
                }
                Mechanism::Chacha8Poly1305 => {
                    mechanisms::Chacha8Poly1305::encrypt(&mut keystore(self, ctx)?, request)
                }
                Mechanism::Tdes => mechanisms::Tdes::encrypt(&mut keystore(self, ctx)?, request),
                _ => Err(Error::MechanismNotAvailable),
            }
            .map(Reply::Encrypt),

            Request::Delete(request) => {
                let success = keystore(self, ctx)?.delete_key(&request.key);
                Ok(Reply::Delete(reply::Delete { success }))
            }

            Request::Clear(request) => {
                let success = keystore(self, ctx)?.clear_key(&request.key);
                Ok(Reply::Clear(reply::Clear { success }))
            }

            Request::DeleteAllKeys(request) => {
                let count = keystore(self, ctx)?.delete_all(request.location)?;
                Ok(Reply::DeleteAllKeys(reply::DeleteAllKeys { count }))
            }

            Request::Exists(request) => match request.mechanism {
                Mechanism::Ed255 => mechanisms::Ed255::exists(&mut keystore(self, ctx)?, request),
                Mechanism::P256 => mechanisms::P256::exists(&mut keystore(self, ctx)?, request),
                Mechanism::Totp => mechanisms::Totp::exists(&mut keystore(self, ctx)?, request),
                Mechanism::X255 => mechanisms::X255::exists(&mut keystore(self, ctx)?, request),
                _ => Err(Error::MechanismNotAvailable),
            }
            .map(Reply::Exists),

            Request::GenerateKey(request) => match request.mechanism {
                Mechanism::Chacha8Poly1305 => {
                    mechanisms::Chacha8Poly1305::generate_key(&mut keystore(self, ctx)?, request)
                }
                Mechanism::Ed255 => {
                    mechanisms::Ed255::generate_key(&mut keystore(self, ctx)?, request)
                }
                Mechanism::P256 => {
                    mechanisms::P256::generate_key(&mut keystore(self, ctx)?, request)
                }
                Mechanism::X255 => {
                    mechanisms::X255::generate_key(&mut keystore(self, ctx)?, request)
                }
                _ => Err(Error::MechanismNotAvailable),
            }
            .map(Reply::GenerateKey),

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
            Request::UnsafeInjectKey(request) => match request.mechanism {
                Mechanism::P256 => {
                    mechanisms::P256::unsafe_inject_key(&mut keystore(self, ctx)?, request)
                }
                Mechanism::X255 => {
                    mechanisms::X255::unsafe_inject_key(&mut keystore(self, ctx)?, request)
                }
                Mechanism::Ed255 => {
                    mechanisms::Ed255::unsafe_inject_key(&mut keystore(self, ctx)?, request)
                }
                Mechanism::SharedSecret => {
                    mechanisms::SharedSecret::unsafe_inject_key(&mut keystore(self, ctx)?, request)
                }
                Mechanism::Aes256Cbc => {
                    mechanisms::Aes256Cbc::unsafe_inject_key(&mut keystore(self, ctx)?, request)
                }
                Mechanism::Tdes => {
                    mechanisms::Tdes::unsafe_inject_key(&mut keystore(self, ctx)?, request)
                }
                _ => Err(Error::MechanismNotAvailable),
            }
            .map(Reply::UnsafeInjectKey),

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

            Request::Hash(request) => match request.mechanism {
                Mechanism::Sha256 => mechanisms::Sha256::hash(&mut keystore(self, ctx)?, request),
                _ => Err(Error::MechanismNotAvailable),
            }
            .map(Reply::Hash),

            Request::LocateFile(request) => {
                let path = filestore.locate_file(
                    request.location,
                    request.dir.as_deref(),
                    &request.filename,
                )?;

                Ok(Reply::LocateFile(reply::LocateFile { path }))
            }

            // This is now preferably done using littlefs-fuse (when device is not yet locked),
            // and should be removed from firmware completely
            Request::DebugDumpStore(_request) => {
                info_now!(":: PERSISTENT");
                recursively_list(self.platform.store().fs(Location::Internal), path!("/"));

                info_now!(":: VOLATILE");
                recursively_list(self.platform.store().fs(Location::Volatile), path!("/"));

                fn recursively_list(fs: &dyn DynFilesystem, path: &Path) {
                    // let fs = store.vfs();
                    fs.read_dir_and_then(path, &mut |dir| {
                        for (i, entry) in dir.enumerate() {
                            let entry = entry.unwrap();
                            if i < 2 {
                                // info_now!("skipping {:?}", &entry.path()).ok();
                                continue;
                            }
                            info_now!("{:?} p({:?})", entry.path(), &path);
                            if entry.file_type().is_dir() {
                                recursively_list(fs, entry.path());
                            }
                            if entry.file_type().is_file() {
                                let _contents = fs.read::<256>(entry.path()).unwrap();
                                // info_now!("{} ?= {}", entry.metadata().len(), contents.len()).ok();
                                // info_now!("{:?}", &contents).ok();
                            }
                        }
                        Ok(())
                    })
                    .unwrap();
                }

                Ok(Reply::DebugDumpStore(reply::DebugDumpStore {}))
            }

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

            Request::RemoveDir(request) => {
                filestore.remove_dir(&request.path, request.location)?;
                Ok(Reply::RemoveDir(reply::RemoveDir {}))
            }

            Request::RemoveDirAll(request) => {
                let count = filestore.remove_dir_all(&request.path, request.location)?;
                Ok(Reply::RemoveDirAll(reply::RemoveDirAll { count }))
            }

            Request::RemoveFile(request) => {
                filestore.remove_file(&request.path, request.location)?;
                Ok(Reply::RemoveFile(reply::RemoveFile {}))
            }

            Request::ReadFile(request) => Ok(Reply::ReadFile(reply::ReadFile {
                data: filestore.read(&request.path, request.location)?,
            })),

            Request::Metadata(request) => Ok(Reply::Metadata(reply::Metadata {
                metadata: filestore.metadata(&request.path, request.location)?,
            })),

            Request::Rename(request) => {
                filestore.rename(&request.from, &request.to, request.location)?;
                Ok(Reply::Rename(reply::Rename {}))
            }

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

            Request::SerializeKey(request) => match request.mechanism {
                Mechanism::Ed255 => {
                    mechanisms::Ed255::serialize_key(&mut keystore(self, ctx)?, request)
                }
                Mechanism::P256 => {
                    mechanisms::P256::serialize_key(&mut keystore(self, ctx)?, request)
                }
                Mechanism::X255 => {
                    mechanisms::X255::serialize_key(&mut keystore(self, ctx)?, request)
                }
                Mechanism::SharedSecret => {
                    mechanisms::SharedSecret::serialize_key(&mut keystore(self, ctx)?, request)
                }
                _ => Err(Error::MechanismNotAvailable),
            }
            .map(Reply::SerializeKey),

            Request::Sign(request) => match request.mechanism {
                Mechanism::Ed255 => mechanisms::Ed255::sign(&mut keystore(self, ctx)?, request),
                Mechanism::HmacBlake2s => {
                    mechanisms::HmacBlake2s::sign(&mut keystore(self, ctx)?, request)
                }
                Mechanism::HmacSha1 => {
                    mechanisms::HmacSha1::sign(&mut keystore(self, ctx)?, request)
                }
                Mechanism::HmacSha256 => {
                    mechanisms::HmacSha256::sign(&mut keystore(self, ctx)?, request)
                }
                Mechanism::HmacSha512 => {
                    mechanisms::HmacSha512::sign(&mut keystore(self, ctx)?, request)
                }
                Mechanism::P256 => mechanisms::P256::sign(&mut keystore(self, ctx)?, request),
                Mechanism::P256Prehashed => {
                    mechanisms::P256Prehashed::sign(&mut keystore(self, ctx)?, request)
                }
                Mechanism::Totp => mechanisms::Totp::sign(&mut keystore(self, ctx)?, request),
                _ => Err(Error::MechanismNotAvailable),
            }
            .map(Reply::Sign),

            Request::WriteFile(request) => {
                filestore.write(&request.path, request.location, &request.data)?;
                Ok(Reply::WriteFile(reply::WriteFile {}))
            }

            Request::UnwrapKey(request) => match request.mechanism {
                Mechanism::Chacha8Poly1305 => {
                    mechanisms::Chacha8Poly1305::unwrap_key(&mut keystore(self, ctx)?, request)
                }
                _ => Err(Error::MechanismNotAvailable),
            }
            .map(Reply::UnwrapKey),

            Request::Verify(request) => match request.mechanism {
                Mechanism::Ed255 => mechanisms::Ed255::verify(&mut keystore(self, ctx)?, request),
                Mechanism::P256 => mechanisms::P256::verify(&mut keystore(self, ctx)?, request),
                _ => Err(Error::MechanismNotAvailable),
            }
            .map(Reply::Verify),

            Request::WrapKey(request) => match request.mechanism {
                Mechanism::Aes256Cbc => {
                    mechanisms::Aes256Cbc::wrap_key(&mut keystore(self, ctx)?, request)
                }
                Mechanism::Chacha8Poly1305 => {
                    mechanisms::Chacha8Poly1305::wrap_key(&mut keystore(self, ctx)?, request)
                }
                _ => Err(Error::MechanismNotAvailable),
            }
            .map(Reply::WrapKey),

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

            Request::Reboot(request) => {
                self.platform.user_interface().reboot(request.to);
            }

            Request::Uptime(_request) => Ok(Reply::Uptime(reply::Uptime {
                uptime: self.platform.user_interface().uptime(),
            })),

            Request::Wink(request) => {
                self.platform.user_interface().wink(request.duration);
                Ok(Reply::Wink(reply::Wink {}))
            }

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

            #[cfg(not(feature = "counter-client"))]
            Request::CreateCounter(_) => Err(Error::RequestNotAvailable),

            #[cfg(feature = "counter-client")]
            Request::IncrementCounter(request) => counterstore(self, ctx)?
                .increment(request.id)
                .map(|counter| Reply::IncrementCounter(reply::IncrementCounter { counter })),

            #[cfg(not(feature = "counter-client"))]
            Request::IncrementCounter(_) => Err(Error::RequestNotAvailable),

            Request::DeleteCertificate(request) => certstore(self, ctx)?
                .delete_certificate(request.id)
                .map(|_| Reply::DeleteCertificate(reply::DeleteCertificate {})),

            Request::ReadCertificate(request) => certstore(self, ctx)?
                .read_certificate(request.id)
                .map(|der| Reply::ReadCertificate(reply::ReadCertificate { der })),

            Request::WriteCertificate(request) => certstore(self, ctx)?
                .write_certificate(request.location, &request.der)
                .map(|id| Reply::WriteCertificate(reply::WriteCertificate { id })),

            Request::SerdeExtension(_) => Err(Error::RequestNotAvailable),
            // _ => {
            //     // #[cfg(test)]
            //     // println!("todo: {:?} request!", &request);
            //     Err(Error::RequestNotAvailable)
            // },
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
            eps: Vec::new(),
            resources,
            dispatch,
        }
    }
}

impl<P: Platform> Service<P> {
    /// Add a new client, claiming one of the statically configured
    /// interchange pairs.
    pub fn try_new_client<S: Syscall>(
        &mut self,
        client_id: &str,
        syscall: S,
        interrupt: Option<&'static InterruptFlag>,
    ) -> Result<ClientImplementation<S>, Error> {
        ClientBuilder::new(client_id)
            .interrupt(interrupt)
            .prepare(self)
            .map(|p| p.build(syscall))
    }

    /// Specialization of `try_new_client`, using `self`'s implementation of `Syscall`
    /// (directly call self for processing). This method is only useful for single-threaded
    /// single-app runners.
    pub fn try_as_new_client(
        &mut self,
        client_id: &str,
        interrupt: Option<&'static InterruptFlag>,
    ) -> Result<ClientImplementation<&mut Self>, Error> {
        ClientBuilder::new(client_id)
            .interrupt(interrupt)
            .prepare(self)
            .map(|p| p.build(self))
    }

    /// Similar to [try_as_new_client][Service::try_as_new_client] except that the returning client owns the
    /// Service and is therefore `'static`
    pub fn try_into_new_client(
        mut self,
        client_id: &str,
        interrupt: Option<&'static InterruptFlag>,
    ) -> Result<ClientImplementation<Self>, Error> {
        ClientBuilder::new(client_id)
            .interrupt(interrupt)
            .prepare(&mut self)
            .map(|p| p.build(self))
    }
}

impl<P: Platform, D: Dispatch> Service<P, D> {
    pub fn add_endpoint(
        &mut self,
        interchange: TrussedResponder,
        client: impl Into<PathBuf>,
        backends: &'static [BackendId<D::BackendId>],
        interrupt: Option<&'static InterruptFlag>,
    ) -> Result<(), Error> {
        let core_ctx = CoreContext::with_interrupt(client.into(), interrupt);
        if &*core_ctx.path == path!("trussed") {
            panic!("trussed is a reserved client ID");
        }
        self.eps
            .push(ServiceEndpoint {
                interchange,
                ctx: core_ctx.into(),
                backends,
            })
            .map_err(|_| Error::ClientCountExceeded)
    }

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
    pub fn process(&mut self) {
        // split self since we iter-mut over eps and need &mut of the other resources
        let eps = &mut self.eps;
        let resources = &mut self.resources;

        for ep in eps.iter_mut() {
            if let Ok(request) = ep.interchange.request() {
                resources
                    .platform
                    .user_interface()
                    .set_status(ui::Status::Processing);
                // #[cfg(test)] println!("service got request: {:?}", &request);

                // resources.currently_serving = ep.client_id.clone();
                let reply_result = if ep.backends.is_empty() {
                    resources.reply_to(&mut ep.ctx.core, request)
                } else {
                    let mut reply_result = Err(Error::RequestNotAvailable);
                    for backend in ep.backends {
                        reply_result =
                            resources.dispatch(&mut self.dispatch, backend, &mut ep.ctx, request);
                        if reply_result != Err(Error::RequestNotAvailable) {
                            break;
                        }
                    }
                    reply_result
                };

                resources
                    .platform
                    .user_interface()
                    .set_status(ui::Status::Idle);
                if ep.interchange.respond(reply_result).is_err() && ep.interchange.is_canceled() {
                    info!("Cancelled request");
                    ep.interchange.acknowledge_cancel().ok();
                };
            }
        }
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

impl<P, D> Syscall for &mut Service<P, D>
where
    P: Platform,
    D: Dispatch,
{
    fn syscall(&mut self) {
        self.process();
    }
}

impl<P, D> Syscall for Service<P, D>
where
    P: Platform,
    D: Dispatch,
{
    fn syscall(&mut self) {
        self.process();
    }
}
