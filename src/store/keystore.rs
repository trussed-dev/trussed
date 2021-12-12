use chacha20::ChaCha8Rng;
use littlefs2::path::PathBuf;

use crate::{
    Bytes,
    error::{Error, Result},
    key,
    Platform,
    store::{self, Store as _},
    types::{KeyId, Location},
    config::MAX_SERIALIZED_KEY_LENGTH,
};


pub type ClientId = littlefs2::path::PathBuf;

pub struct ClientKeystore<P>
where
    P: Platform,
{
    client_id: ClientId,
    rng: ChaCha8Rng,
    store: P::S,
}

impl<P: Platform> ClientKeystore<P> {
    pub fn new(client_id: ClientId, rng: ChaCha8Rng, store: P::S) -> Self {
        Self { client_id, rng, store }
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
    fn delete_all(&self, location: Location) -> Result<usize>;
    fn load_key(&self, secrecy: key::Secrecy, kind: Option<key::Kind>, id: &KeyId) -> Result<key::Key>;
    fn overwrite_key(&self, location: Location, secrecy: key::Secrecy, kind: key::Kind, id: &KeyId, material: &[u8]) -> Result<()>;
    fn rng(&mut self) -> &mut ChaCha8Rng;
    fn location(&self, secrecy: key::Secrecy, id: &KeyId) -> Option<Location>;
}

impl<P: Platform> ClientKeystore<P> {

    pub fn generate_key_id(&mut self) -> KeyId {
        KeyId::new(self.rng())
    }

    pub fn key_directory(&self, secrecy: key::Secrecy) -> PathBuf {
        let mut path = PathBuf::new();
        path.push(&self.client_id);
        path.push(&match secrecy {
            key::Secrecy::Secret => PathBuf::from("sec"),
            key::Secrecy::Public => PathBuf::from("pub"),
        });
        path
    }

    pub fn key_path(&self, secrecy: key::Secrecy, id: &KeyId) -> PathBuf {
        let mut path = self.key_directory(secrecy);
        path.push(&PathBuf::from(id.hex().as_slice()));
        path
    }

}

impl<P: Platform> Keystore for ClientKeystore<P> {

    fn rng(&mut self) -> &mut ChaCha8Rng {
        &mut self.rng
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
            material: key::Material::from_slice(material).unwrap(),
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
            let path = self.key_path(*secrecy, id);
            locations.iter().any(|location| {
                store::delete(self.store, *location, &path)
            })
        })
    }

    /// TODO: This uses the predicate "filename.len() >= 4"
    /// Be more principled :)
    fn delete_all(&self, location: Location) -> Result<usize> {
        let path = self.key_directory(key::Secrecy::Secret);
        store::remove_dir_all_where(self.store, location, &path, |dir_entry| {
            dir_entry.file_name().as_ref().len() >= 4
        })?;
        let path = self.key_directory(key::Secrecy::Public);
        store::remove_dir_all_where(self.store, location, &path, |dir_entry| {
            dir_entry.file_name().as_ref().len() >= 4
        })
    }

    fn load_key(&self, secrecy: key::Secrecy, kind: Option<key::Kind>, id: &KeyId) -> Result<key::Key> {
        // info_now!("loading  {:?}", &key_kind);
        let path = self.key_path(secrecy, id);

        let location = self.location(secrecy, id).ok_or(Error::NoSuchKey)?;

        //TODO: This should better be defined in some way, instead of hardcoding.
        //      I've tried referring to MAX_SERIALIZED_KEY_LENGTH, is this a good idea?
        #[cfg(not(feature = "rsa2k-pkcs"))]
        let bytes: Bytes<128> = store::read(self.store, location, &path)?;
        #[cfg(feature = "rsa2k-pkcs")]
        let bytes: Bytes<MAX_SERIALIZED_KEY_LENGTH> = store::read(self.store, location, &path)?;

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
            material: key::Material::from_slice(material).unwrap(),
        };

        let path = self.key_path(secrecy, id);
        store::store(self.store, location, &path, &key.serialize())?;

        Ok(())
    }


    fn location(&self, secrecy: key::Secrecy, id: &KeyId) -> Option<Location> {
        let path = self.key_path(secrecy, id);

        if path.exists(self.store.vfs()) {
            return Some(Location::Volatile);
        }

        if path.exists(self.store.ifs()) {
            return Some(Location::Internal);
        }

        if path.exists(self.store.efs()) {
            return Some(Location::External);
        }

        None
    }

}
