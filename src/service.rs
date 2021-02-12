pub use rand_core::{RngCore, SeedableRng};
use heapless_bytes::Bytes as ByteBuf;
use interchange::Responder;
use littlefs2::path::PathBuf;
use chacha20::ChaCha8Rng;


use crate::api::*;
use crate::platform::*;
use crate::config::*;
use crate::error::Error;
pub use crate::key::*;
use crate::mechanisms;
use crate::pipe::TrussedInterchange;
pub use crate::store::{
    filestore::{ClientFilestore, Filestore, ReadDirState, ReadDirFilesState},
    keystore::{ClientKeystore, Keystore},
};
use crate::types::*;
pub use crate::pipe::ServiceEndpoint;

// #[macro_use]
// mod macros;

macro_rules! rpc_trait { ($($Name:ident, $name:ident,)*) => { $(

    pub trait $Name {
        fn $name(_keystore: &mut impl Keystore, _request: request::$Name)
        -> Result<reply::$Name, Error> { Err(Error::MechanismNotAvailable) }
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
where P: Platform
{
    pub(crate) platform: P,
    // // Option?
    // currently_serving: ClientId,
    // TODO: how/when to clear
    read_dir_files_state: Option<ReadDirFilesState>,
    read_dir_state: Option<ReadDirState>,
    rng_state: Option<ChaCha8Rng>,
}

impl<P: Platform> ServiceResources<P> {

    pub fn new(platform: P) -> Self {
        Self {
            platform,
            // currently_serving: PathBuf::new(),
            read_dir_files_state: None,
            read_dir_state: None,
            rng_state: None,
        }
    }
}

pub struct Service<P> where P: Platform {
    eps: Vec<ServiceEndpoint, MAX_SERVICE_CLIENTS>,
    resources: ServiceResources<P>,
}

// need to be able to send crypto service to an interrupt handler
unsafe impl<P: Platform> Send for Service<P> {}

impl<P: Platform> ServiceResources<P> {

    pub fn reply_to(&mut self, client_id: PathBuf, request: Request) -> Result<Reply, Error> {
        // TODO: what we want to do here is map an enum to a generic type
        // Is there a nicer way to do this?

        let full_store = self.platform.store();

        // prepare keystore, bound to client_id, for cryptographic calls
        let mut keystore: ClientKeystore<'_, P> = ClientKeystore::new(
            client_id.clone(),
            self.drbg().map_err(|_| Error::EntropyMalfunction)?,
            full_store,
        );
        let keystore = &mut keystore;

        // prepare filestore, bound to client_id, for storage calls
        let mut filestore: ClientFilestore<P::S> = ClientFilestore::new(
            client_id,
            full_store,
        );
        let filestore = &mut filestore;

        match request {
            Request::DummyRequest => {
                Ok(Reply::DummyReply)
            },

            Request::Agree(request) => {
                match request.mechanism {

                    Mechanism::P256 => mechanisms::P256::agree(keystore, request),
                    Mechanism::X255 => mechanisms::X255::agree(keystore, request),
                    _ => Err(Error::MechanismNotAvailable),

                }.map(Reply::Agree)
            },

            Request::Decrypt(request) => {
                match request.mechanism {

                    Mechanism::Aes256Cbc => mechanisms::Aes256Cbc::decrypt(keystore, request),
                    Mechanism::Chacha8Poly1305 => mechanisms::Chacha8Poly1305::decrypt(keystore, request),
                    Mechanism::Tdes => mechanisms::Tdes::decrypt(keystore, request),
                    _ => Err(Error::MechanismNotAvailable),

                }.map(Reply::Decrypt)
            },

            Request::DeriveKey(request) => {
                match request.mechanism {

                    Mechanism::Ed255 => mechanisms::Ed255::derive_key(keystore, request),
                    Mechanism::P256 => mechanisms::P256::derive_key(keystore, request),
                    Mechanism::Sha256 => mechanisms::Sha256::derive_key(keystore, request),
                    Mechanism::X255 => mechanisms::X255::derive_key(keystore, request),
                    _ => Err(Error::MechanismNotAvailable),

                }.map(Reply::DeriveKey)
            },

            Request::DeserializeKey(request) => {
                match request.mechanism {

                    Mechanism::Ed255 => mechanisms::Ed255::deserialize_key(keystore, request),
                    Mechanism::P256 => mechanisms::P256::deserialize_key(keystore, request),
                    Mechanism::X255 => mechanisms::X255::deserialize_key(keystore, request),
                    _ => Err(Error::MechanismNotAvailable),

                }.map(Reply::DeserializeKey)
            }

            Request::Encrypt(request) => {
                match request.mechanism {

                    Mechanism::Aes256Cbc => mechanisms::Aes256Cbc::encrypt(keystore, request),
                    Mechanism::Chacha8Poly1305 => mechanisms::Chacha8Poly1305::encrypt(keystore, request),
                    Mechanism::Tdes => mechanisms::Tdes::encrypt(keystore, request),
                    _ => Err(Error::MechanismNotAvailable),

                }.map(Reply::Encrypt)
            },

            Request::Delete(request) => {
                let success = keystore.delete_key(&request.key.object_id);
                Ok(Reply::Delete(reply::Delete { success } ))
            },

            Request::Exists(request) => {
                match request.mechanism {

                    Mechanism::Ed255 => mechanisms::Ed255::exists(keystore, request),
                    Mechanism::P256 => mechanisms::P256::exists(keystore, request),
                    Mechanism::Totp => mechanisms::Totp::exists(keystore, request),
                    Mechanism::X255 => mechanisms::X255::exists(keystore, request),
                    _ => Err(Error::MechanismNotAvailable),

                }.map(Reply::Exists)
            },

            Request::GenerateKey(request) => {
                match request.mechanism {
                    Mechanism::Chacha8Poly1305 => mechanisms::Chacha8Poly1305::generate_key(keystore, request),
                    Mechanism::Ed255 => mechanisms::Ed255::generate_key(keystore, request),
                    Mechanism::HmacSha256 => mechanisms::HmacSha256::generate_key(keystore, request),
                    Mechanism::P256 => mechanisms::P256::generate_key(keystore, request),
                    Mechanism::X255 => mechanisms::X255::generate_key(keystore, request),
                    _ => Err(Error::MechanismNotAvailable),
                }.map(Reply::GenerateKey)
            },

            Request::UnsafeInjectKey(request) => {
                match request.mechanism {
                    Mechanism::Tdes => mechanisms::Tdes::unsafe_inject_key(keystore, request),
                    Mechanism::Totp => mechanisms::Totp::unsafe_inject_key(keystore, request),
                    _ => Err(Error::MechanismNotAvailable),
                }.map(Reply::UnsafeInjectKey)
            },

            Request::Hash(request) => {
                match request.mechanism {

                    Mechanism::Sha256 => mechanisms::Sha256::hash(keystore, request),
                    _ => Err(Error::MechanismNotAvailable),

                }.map(Reply::Hash)
            },

            Request::LocateFile(request) => {
                let path = filestore.locate_file(request.location, request.dir, request.filename)?;

                Ok(Reply::LocateFile(reply::LocateFile { path }) )
            }

            // This is now preferably done using littlefs-fuse (when device is not yet locked),
            // and should be removed from firmware completely
            Request::DebugDumpStore(_request) => {

                info_now!(":: PERSISTENT");
                recursively_list(self.platform.store().ifs(), PathBuf::from(b"/"));

                info_now!(":: VOLATILE");
                recursively_list(self.platform.store().vfs(), PathBuf::from(b"/"));

                fn recursively_list<S: 'static + crate::types::LfsStorage>(fs: &'static crate::store::Fs<S>, path: PathBuf) {
                    // let fs = store.vfs();
                    fs.read_dir_and_then(&path, |dir| {
                        for (i, entry) in dir.enumerate() {
                            let entry = entry.unwrap();
                            if i < 2 {
                                // info_now!("skipping {:?}", &entry.path()).ok();
                                continue;
                            }
                            info_now!("{:?} p({:?})", entry.path(), &path);
                            if entry.file_type().is_dir() {
                                recursively_list(fs, PathBuf::from(entry.path()));
                            }
                            if entry.file_type().is_file() {
                                let _contents: Vec<u8, consts::U256> = fs.read(entry.path()).unwrap();
                                // info_now!("{} ?= {}", entry.metadata().len(), contents.len()).ok();
                                // info_now!("{:?}", &contents).ok();
                            }
                        }
                        Ok(())
                    }).unwrap();
                }

                Ok(Reply::DebugDumpStore(reply::DebugDumpStore {}) )

            }

            Request::ReadDirFirst(request) => {
                let maybe_entry = match filestore.read_dir_first(&request.dir, request.location, request.not_before_filename.as_ref())? {
                    Some((entry, read_dir_state)) => {
                        self.read_dir_state = Some(read_dir_state);
                        Some(entry)
                    }
                    None => {
                        self.read_dir_state = None;
                        None

                    }
                };
                Ok(Reply::ReadDirFirst(reply::ReadDirFirst { entry: maybe_entry } ))
            }

            Request::ReadDirNext(_request) => {
                // ensure next call has nothing to work with, unless we store state again
                let read_dir_state = self.read_dir_state.take();

                let maybe_entry = match read_dir_state {
                    None => None,
                    Some(state) => {
                        match filestore.read_dir_next(state)? {
                            Some((entry, read_dir_state)) => {
                                self.read_dir_state = Some(read_dir_state);
                                Some(entry)
                            }
                            None => {
                                self.read_dir_state = None;
                                None
                            }
                        }
                    }
                };

                Ok(Reply::ReadDirNext(reply::ReadDirNext { entry: maybe_entry } ))
            }

            Request::ReadDirFilesFirst(request) => {
                let maybe_data = match filestore.read_dir_files_first(&request.dir, request.location, request.user_attribute)? {
                    Some((data, state)) => {
                        self.read_dir_files_state = Some(state);
                        data
                    }
                    None => {
                        self.read_dir_files_state = None;
                        None
                    }
                };
                Ok(Reply::ReadDirFilesFirst(reply::ReadDirFilesFirst { data: maybe_data } ))
            }

            Request::ReadDirFilesNext(_request) => {
                let read_dir_files_state = self.read_dir_files_state.take();

                let maybe_data = match read_dir_files_state {
                    None => None,
                    Some(state) => {
                        match filestore.read_dir_files_next(state)? {
                            Some((data, state)) => {
                                self.read_dir_files_state = Some(state);
                                data
                            }
                            None => {
                                self.read_dir_files_state = None;
                                None
                            }
                        }
                    }
                };
                Ok(Reply::ReadDirFilesNext(reply::ReadDirFilesNext { data: maybe_data } ))
            }

            Request::RemoveDir(request) => {
                filestore.remove_dir(&request.path, request.location)?;
                Ok(Reply::RemoveDir(reply::RemoveDir {} ))
            }

            Request::RemoveFile(request) => {
                filestore.remove_file(&request.path, request.location)?;
                Ok(Reply::RemoveFile(reply::RemoveFile {} ))
            }

            Request::ReadFile(request) => {
                Ok(Reply::ReadFile(reply::ReadFile {
                    data: filestore.read(&request.path, request.location)?
                }))
            }

            Request::RandomByteBuf(request) => {
                if request.count < 1024 {
                    let mut bytes = Message::new();
                    bytes.resize_default(request.count).unwrap();
                    self.drbg()?.fill_bytes(&mut bytes);
                    Ok(Reply::RandomByteBuf(reply::RandomByteBuf { bytes } ))
                } else {
                    Err(Error::MechanismNotAvailable)
                }
            }

            Request::SerializeKey(request) => {
                match request.mechanism {

                    Mechanism::Ed255 => mechanisms::Ed255::serialize_key(keystore, request),
                    Mechanism::P256 => mechanisms::P256::serialize_key(keystore, request),
                    Mechanism::X255 => mechanisms::X255::serialize_key(keystore, request),
                    _ => Err(Error::MechanismNotAvailable),

                }.map(Reply::SerializeKey)
            }

            Request::Sign(request) => {
                match request.mechanism {

                    Mechanism::Ed255 => mechanisms::Ed255::sign(keystore, request),
                    Mechanism::HmacSha256 => mechanisms::HmacSha256::sign(keystore, request),
                    Mechanism::P256 => mechanisms::P256::sign(keystore, request),
                    Mechanism::P256Prehashed => mechanisms::P256Prehashed::sign(keystore, request),
                    Mechanism::Totp => mechanisms::Totp::sign(keystore, request),
                    _ => Err(Error::MechanismNotAvailable),

                }.map(Reply::Sign)
            },

            Request::WriteFile(request) => {
                filestore.write(&request.path, request.location, &request.data)?;
                Ok(Reply::WriteFile(reply::WriteFile {} ))
            }

            Request::UnwrapKey(request) => {
                match request.mechanism {

                    Mechanism::Chacha8Poly1305 => mechanisms::Chacha8Poly1305::unwrap_key(keystore, request),
                    _ => Err(Error::MechanismNotAvailable),

                }.map(Reply::UnwrapKey)
            }

            Request::Verify(request) => {
                match request.mechanism {

                    Mechanism::Ed255 => mechanisms::Ed255::verify(keystore, request),
                    Mechanism::P256 => mechanisms::P256::verify(keystore, request),
                    _ => Err(Error::MechanismNotAvailable),

                }.map(Reply::Verify)
            },

            Request::WrapKey(request) => {
                match request.mechanism {

                    Mechanism::Aes256Cbc => mechanisms::Aes256Cbc::wrap_key(keystore, request),
                    Mechanism::Chacha8Poly1305 => mechanisms::Chacha8Poly1305::wrap_key(keystore, request),
                    _ => Err(Error::MechanismNotAvailable),

                }.map(Reply::WrapKey)
            },

            Request::RequestUserConsent(request) => {
                assert_eq!(request.level, consent::Level::Normal);

                let starttime = self.platform.user_interface().uptime();
                let timeout = core::time::Duration::from_millis(request.timeout_milliseconds as u64);

                self.platform.user_interface().set_status(ui::Status::WaitingForUserPresence);
                loop {
                    let nowtime = self.platform.user_interface().uptime();
                    if (nowtime - starttime) > timeout {
                        let result = Err(consent::Error::TimedOut);
                        return Ok(Reply::RequestUserConsent(reply::RequestUserConsent { result } ));
                    }
                    let up = self.platform.user_interface().check_user_presence();
                    match request.level {
                        // If Normal level consent is request, then both Strong and Normal
                        // indications will result in success.
                        consent::Level::Normal => {
                            if up == consent::Level::Normal ||
                                up == consent::Level::Strong {
                                    break;
                                }
                        },
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
                self.platform.user_interface().set_status(ui::Status::Idle);

                let result = Ok(());
                Ok(Reply::RequestUserConsent(reply::RequestUserConsent { result } ))
            }

            Request::Reboot(request) => {
                self.platform.user_interface().reboot(request.to);
            }

            _ => {
                // #[cfg(test)]
                // println!("todo: {:?} request!", &request);
                Err(Error::RequestNotAvailable)
            },
        }
    }

    pub fn drbg(&mut self) -> Result<&mut ChaCha8Rng, Error> {

        // Check if our RNG is loaded.
        if self.rng_state.is_none() {

            // dogfood our own construction
            let mut filestore: ClientFilestore<P::S> = ClientFilestore::new(
                PathBuf::from(b"trussed\0"),
                self.platform.store(),
            );
            let filestore = &mut filestore;

            let path = PathBuf::from(b"rng-state.bin");

            // If it hasn't been saved to flash yet, generate it from HW RNG.
            let stored_seed = if ! filestore.exists(&path, StorageLocation::Internal) {
                let mut stored_seed = [0u8; 32];
                self.platform.rng().try_fill_bytes(&mut stored_seed)
                    .map_err(|_| Error::EntropyMalfunction)?;
                stored_seed
            } else {
                // Use the last saved state.
                let stored_seed_bytebuf: ByteBuf<consts::U32> = filestore.read(&path, StorageLocation::Internal)?;
                let mut stored_seed = [0u8; 32];
                stored_seed.clone_from_slice(&stored_seed_bytebuf);
                stored_seed
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
            // the hash of the current seed as input seed for the next boot. In this way, even if
            // the HW entropy "goes bad" (e.g., starts returning all zeros), the properties of the
            // hash function should ensure that there are no cycles or repeats of entropy in the
            // output to apps.

            // 1. First, draw fresh entropy from the HW TRNG.
            let mut entropy = [0u8; 32];
            self.platform.rng().try_fill_bytes(&mut entropy)
                .map_err(|_| Error::EntropyMalfunction)?;

            // 2. Mix into our previously stored seed.
            let mut our_seed = [0u8; 32];
            for i in 0..32 {
                our_seed[i] = stored_seed[i] ^ entropy[i];
            }

            // Initialize ChaCha8 construction with our seed.
            self.rng_state = Some(chacha20::ChaCha8Rng::from_seed(our_seed));

            // 3. Store hash of seed for next boot.
            use sha2::digest::Digest;
            let mut hash = sha2::Sha256::new();
            hash.input(&our_seed);
            let seed_to_store = hash.result();

            filestore.write(&path, StorageLocation::Internal, seed_to_store.as_ref()).unwrap();
        }

        // no panic - just ensured existence
        let chacha = self.rng_state.as_mut().unwrap();
        Ok(chacha)
    }

    pub fn fill_random_bytes(&mut self, bytes: &mut[u8]) -> Result<(), Error> {
        self.drbg()?.fill_bytes(bytes);
        Ok(())
    }

}

impl<P: Platform> Service<P> {

    pub fn new(platform: P) -> Self {
        let resources = ServiceResources::new(platform);
        Self { eps: Vec::new(), resources }
    }

    /// Add a new client, claiming one of the statically configured
    /// interchange pairs.
    #[allow(clippy::result_unit_err)]
    pub fn try_new_client<S: crate::platform::Syscall>(&mut self, client_id: &str, syscall: S)
        -> Result<crate::client::ClientImplementation<S>, ()>
    {
        use interchange::Interchange;
        let (requester, responder) = TrussedInterchange::claim().ok_or(())?;
        let client_id = ClientId::from(client_id.as_bytes());
        self.add_endpoint(responder, client_id).map_err(|_service_endpoint| ())?;

        Ok(crate::client::ClientImplementation::new(requester, syscall))
    }

    /// Specialization of `try_new_client`, using `self`'s implementation of `Syscall`
    /// (directly call self for processing). This method is only useful for single-threaded
    /// single-app runners.
    #[allow(clippy::result_unit_err)]
    pub fn try_as_new_client(&mut self, client_id: &str)
        -> Result<crate::client::ClientImplementation<&mut Service<P>>, ()>
    {
        use interchange::Interchange;
        let (requester, responder) = TrussedInterchange::claim().ok_or(())?;
        let client_id = ClientId::from(client_id.as_bytes());
        self.add_endpoint(responder, client_id).map_err(|_service_endpoint| ())?;

        Ok(crate::client::ClientImplementation::new(requester, self))
    }


    pub fn add_endpoint(&mut self, interchange: Responder<TrussedInterchange>, client_id: ClientId) -> Result<(), ServiceEndpoint> {
        if client_id == PathBuf::from(b"trussed\0") {
            panic!("trussed is a reserved client ID");
        }
        self.eps.push(ServiceEndpoint { interchange, client_id })
    }

    pub fn set_seed_if_uninitialized(&mut self, seed: &[u8; 32]) {

        let mut filestore: ClientFilestore<P::S> = ClientFilestore::new(
            PathBuf::from(b"trussed\0"),
            self.resources.platform.store(),
        );
        let filestore = &mut filestore;

        let path = PathBuf::from(b"rng-state.bin");
        if ! filestore.exists(&path, StorageLocation::Internal) {
            filestore.write(&path, StorageLocation::Internal, seed.as_ref()).unwrap();
        }

    }

    // currently, this just blinks the green heartbeat LED (former toggle_red in app_rtic.rs)
    //
    // in future, this would
    // - generate more interesting LED visuals
    // - return "when" next to be called
    // - potentially read out button status and return "async"
    pub fn update_ui(&mut self) /* -> u32 */ {
        self.resources.platform.user_interface().refresh();
    }

    // process one request per client which has any
    pub fn process(&mut self) {
        // split self since we iter-mut over eps and need &mut of the other resources
        let eps = &mut self.eps;
        let resources = &mut self.resources;

        for ep in eps.iter_mut() {
            if let Some(request) = ep.interchange.take_request() {
                // #[cfg(test)] println!("service got request: {:?}", &request);

                // resources.currently_serving = ep.client_id.clone();
                let reply_result = resources.reply_to(ep.client_id.clone(), request);
                ep.interchange.respond(reply_result).ok();

            }
        }
        debug_now!("I/E/V : {}/{}/{} >",
              self.resources.platform.store().ifs().available_blocks().unwrap(),
              self.resources.platform.store().efs().available_blocks().unwrap(),
              self.resources.platform.store().vfs().available_blocks().unwrap(),
        );
    }
}

impl<P> crate::client::Syscall for &mut Service<P>
where P: Platform
{
    fn syscall(&mut self) {
        self.process();
    }
}
