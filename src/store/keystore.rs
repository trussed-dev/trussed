use littlefs2::{path, path::PathBuf};
use rand_chacha::ChaCha8Rng;

use crate::{
    config::MAX_KEY_MATERIAL_LENGTH,
    error::{Error, Result},
    key,
    store::{self, Store},
    types::{KeyId, Location},
    Bytes,
};

pub type ClientId = PathBuf;

pub struct ClientKeystore<S>
where
    S: Store,
{
    client_id: ClientId,
    rng: ChaCha8Rng,
    store: S,
}

impl<S: Store> ClientKeystore<S> {
    pub fn new(client_id: ClientId, rng: ChaCha8Rng, store: S) -> Self {
        Self {
            client_id,
            rng,
            store,
        }
    }
}

pub const SERIALIZATION_VERSION: u8 = 0;

/// Trait intended for use by mechanism implementations.
pub trait Keystore {
    // fn store(&self, key: Key, location: Location) -> Result<KeyId>;
    // fn load(&self, key: KeyId) -> Result<Key>;
    // fn exists(&self, key: KeyId) -> bool;
    fn store_key(
        &mut self,
        location: Location,
        secrecy: key::Secrecy,
        info: impl Into<key::Info>,
        material: &[u8],
    ) -> Result<KeyId>;
    fn exists_key(&self, secrecy: key::Secrecy, kind: Option<key::Kind>, id: &KeyId) -> bool;
    /// Return Header of key, if it exists
    fn key_info(&self, secrecy: key::Secrecy, id: &KeyId) -> Option<key::Info>;
    fn delete_key(&self, id: &KeyId) -> bool;
    fn clear_key(&self, id: &KeyId) -> bool;
    fn delete_all(&self, location: Location) -> Result<usize>;
    fn load_key(
        &self,
        secrecy: key::Secrecy,
        kind: Option<key::Kind>,
        id: &KeyId,
    ) -> Result<key::Key>;
    fn overwrite_key(
        &self,
        location: Location,
        secrecy: key::Secrecy,
        kind: key::Kind,
        id: &KeyId,
        material: &[u8],
    ) -> Result<()>;
    fn rng(&mut self) -> &mut ChaCha8Rng;
    fn location(&self, secrecy: key::Secrecy, id: &KeyId) -> Option<Location>;
}

impl<S: Store> ClientKeystore<S> {
    pub fn generate_key_id(&mut self) -> KeyId {
        KeyId::new(self.rng())
    }

    pub fn key_directory(&self, secrecy: key::Secrecy) -> PathBuf {
        let mut path = PathBuf::new();
        path.push(&self.client_id);
        path.push(match secrecy {
            key::Secrecy::Secret => path!("sec"),
            key::Secrecy::Public => path!("pub"),
        });
        path
    }

    pub fn key_path(&self, secrecy: key::Secrecy, id: &KeyId) -> PathBuf {
        let mut path = self.key_directory(secrecy);
        path.push(&PathBuf::from(id.hex().as_slice()));
        path
    }
}

impl<S: Store> Keystore for ClientKeystore<S> {
    fn rng(&mut self) -> &mut ChaCha8Rng {
        &mut self.rng
    }

    #[inline(never)]
    fn store_key(
        &mut self,
        location: Location,
        secrecy: key::Secrecy,
        info: impl Into<key::Info>,
        material: &[u8],
    ) -> Result<KeyId> {
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
        self.load_key(secrecy, None, id)
            .map(|key| key::Info {
                flags: key.flags,
                kind: key.kind,
            })
            .ok()
    }

    // TODO: is this an Oracle?
    fn delete_key(&self, id: &KeyId) -> bool {
        let secrecies = [key::Secrecy::Secret, key::Secrecy::Public];

        let locations = [Location::Internal, Location::External, Location::Volatile];

        secrecies.iter().any(|secrecy| {
            let path = self.key_path(*secrecy, id);
            locations
                .iter()
                .any(|location| store::delete(self.store, *location, &path))
        })
    }

    fn clear_key(&self, id: &KeyId) -> bool {
        self.delete_key(id)
    }

    /// TODO: This uses the predicate "filename.len() >= 4"
    /// Be more principled :)
    fn delete_all(&self, location: Location) -> Result<usize> {
        let secret_path = self.key_directory(key::Secrecy::Secret);
        let secret_deleted =
            store::remove_dir_all_where(self.store, location, &secret_path, &|dir_entry| {
                dir_entry.file_name().as_ref().len() >= 4
            })?;
        let public_path = self.key_directory(key::Secrecy::Public);
        let public_deleted =
            store::remove_dir_all_where(self.store, location, &public_path, &|dir_entry| {
                dir_entry.file_name().as_ref().len() >= 4
            })?;
        Ok(secret_deleted + public_deleted)
    }

    fn load_key(
        &self,
        secrecy: key::Secrecy,
        kind: Option<key::Kind>,
        id: &KeyId,
    ) -> Result<key::Key> {
        // info_now!("loading  {:?}", &key_kind);
        let path = self.key_path(secrecy, id);

        let location = self.location(secrecy, id).ok_or(Error::NoSuchKey)?;

        let bytes: Bytes<{ MAX_KEY_MATERIAL_LENGTH }> = store::read(self.store, location, &path)?;

        let key = key::Key::try_deserialize(&bytes)?;

        if let Some(kind) = kind {
            if key.kind != kind {
                return Err(Error::WrongKeyKind);
            }
        }
        Ok(key)
    }

    fn overwrite_key(
        &self,
        location: Location,
        secrecy: key::Secrecy,
        kind: key::Kind,
        id: &KeyId,
        material: &[u8],
    ) -> Result<()> {
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

        [Location::Volatile, Location::Internal, Location::External]
            .into_iter()
            .find(|&location| self.store.fs(location).exists(&path))
    }
}
