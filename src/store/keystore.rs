use chacha20::ChaCha8Rng;
pub use heapless::consts;
use littlefs2::path::PathBuf;
use rand_core::RngCore as _;

use crate::{
    Bytes,
    error::{Error, Result},
    key,
    Platform,
    store::{self, Store as _},
    types::Location as Location,
};


pub type ClientId = littlefs2::path::PathBuf;
pub type KeyId = crate::types::UniqueId;

pub struct ClientKeystore<P>
where
    P: Platform,
{
    client_id: ClientId,
    drbg: ChaCha8Rng,
    store: P::S,
}

impl<'a, P: Platform> ClientKeystore<P> {
    pub fn new(client_id: ClientId, drbg: ChaCha8Rng, store: P::S) -> Self {
        Self { client_id, drbg, store }
    }
}

pub const SERIALIZATION_VERSION: u8 = 0;

/// Trait intended for use by mechanism implementations.
pub trait Keystore {
    // fn store(&self, key: Key, location: Location) -> Result<KeyId>;
    // fn load(&self, key: KeyId) -> Result<Key>;
    // fn exists(&self, key: KeyId) -> bool;
    fn store_key(&mut self, location: Location, secrecy: key::Secrecy, info: impl Into<key::Info>, material: &[u8]) -> Result<KeyId>;
    fn exists_key(&self, secrecy: key::Secrecy, kind: Option<key::Kind>, id: &KeyId) -> bool;
    /// Return Header of key, if it exists
    fn key_info(&self, secrecy: key::Secrecy, id: &KeyId) -> Option<key::Info>;
    fn delete_key(&self, id: &KeyId) -> bool;
    fn load_key(&self, secrecy: key::Secrecy, kind: Option<key::Kind>, id: &KeyId) -> Result<key::Key>;
    fn overwrite_key(&self, location: Location, secrecy: key::Secrecy, kind: key::Kind, id: &KeyId, material: &[u8]) -> Result<()>;
    fn drbg(&mut self) -> &mut ChaCha8Rng;
    fn location(&self, secrecy: key::Secrecy, id: &KeyId) -> Option<Location>;
}

impl<P: Platform> ClientKeystore<P> {

    pub fn generate_key_id(&mut self) -> KeyId {
        let mut id = [0u8; 16];

        self.drbg.fill_bytes(&mut id);
        crate::types::UniqueId(id)
    }

    pub fn key_path(&self, secrecy: key::Secrecy, id: &KeyId) -> PathBuf {
        let mut path = PathBuf::new();
        path.push(&self.client_id);
        // TODO: huh?!?!
        // If I change these prefixes to shorter,
        // DebugDumpStore skips the directory contents
        path.push(&match secrecy {
            key::Secrecy::Secret => PathBuf::from("sec"),
            key::Secrecy::Public => PathBuf::from("pub"),
        });
        path.push(&PathBuf::from(id.hex().as_ref()));
        path
    }

}

impl<P: Platform> Keystore for ClientKeystore<P> {

    fn drbg(&mut self) -> &mut ChaCha8Rng {
        &mut self.drbg
    }

    #[inline(never)]
    fn store_key(&mut self, location: Location, secrecy: key::Secrecy, info: impl Into<key::Info>, material: &[u8]) -> Result<KeyId> {
        // info_now!("storing {:?} -> {:?}", &key_kind, location);

        let mut info: key::Info = info.into();
        if secrecy == key::Secrecy::Secret {
            info.flags |= key::Flags::SENSITIVE;
        }
        let key = key::Key {
            flags: info.flags,
            kind: info.kind,
            material: key::Material::try_from_slice(material).unwrap(),
        };

        let id = self.generate_key_id();
        let path = self.key_path(secrecy, &id);
        store::store(self.store, location, &path, &key.serialize())?;

        Ok(id)
    }

    fn exists_key(&self, secrecy: key::Secrecy, kind: Option<key::Kind>, id: &KeyId) -> bool {
        self.load_key(secrecy, kind, id).is_ok()
    }

    fn key_info(&self, secrecy: key::Secrecy, id: &KeyId) -> Option<key::Info> {
        self.load_key(secrecy, None, id).map(|key| key::Info { flags: key.flags, kind: key.kind }).ok()
    }

    // TODO: is this an Oracle?
    fn delete_key(&self, id: &KeyId) -> bool {
        let secrecies = [
            key::Secrecy::Secret,
            key::Secrecy::Public,
        ];

        let locations = [
            Location::Internal,
            Location::External,
            Location::Volatile,
        ];

        secrecies.iter().any(|secrecy| {
            let path = self.key_path(*secrecy, &id);
            locations.iter().any(|location| {
                store::delete(self.store, *location, &path)
            })
        })
    }

    fn load_key(&self, secrecy: key::Secrecy, kind: Option<key::Kind>, id: &KeyId) -> Result<key::Key> {
        // info_now!("loading  {:?}", &key_kind);
        let path = self.key_path(secrecy, id);

        let location = self.location(secrecy, id).ok_or(Error::NoSuchKey)?;

        let bytes: Bytes<consts::U128> = store::read(self.store, location, &path)?;

        let key = key::Key::try_deserialize(&bytes)?;

        if let Some(kind) = kind {
            if key.kind != kind {
                return Err(Error::WrongKeyKind);
            }
        }
        Ok(key)
    }

    fn overwrite_key(&self, location: Location, secrecy: key::Secrecy, kind: key::Kind, id: &KeyId, material: &[u8]) -> Result<()> {
        let mut flags = key::Flags::default();
        if secrecy == key::Secrecy::Secret {
            flags |= key::Flags::SENSITIVE;
        }
        let key = key::Key {
            flags: Default::default(),
            kind,
            material: key::Material::try_from_slice(material).unwrap(),
        };

        let path = self.key_path(secrecy, id);
        store::store(self.store, location, &path, &key.serialize())?;

        Ok(())
    }


    fn location(&self, secrecy: key::Secrecy, id: &KeyId) -> Option<Location> {
        let path = self.key_path(secrecy, id);

        if path.exists(&self.store.vfs()) {
            return Some(Location::Volatile);
        }

        if path.exists(&self.store.ifs()) {
            return Some(Location::Internal);
        }

        if path.exists(&self.store.efs()) {
            return Some(Location::External);
        }

        None
    }

}
