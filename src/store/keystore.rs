use core::convert::{TryFrom, TryInto};

use chacha20::ChaCha8Rng;
pub use heapless::consts;
use littlefs2::path::PathBuf;
use rand_core::RngCore as _;

use crate::{
    ByteBuf,
    error::{Error, Result},
    key::{
        KeyKind,
        KeyType as Secrecy,
        SerializedKey,
    },
    Platform,
    store::{self, Store as _},
    types::StorageLocation as Location,
};


pub type ClientId = littlefs2::path::PathBuf;
pub type KeyId = crate::types::UniqueId;

pub struct ClientKeystore<'a, P>
where
    P: Platform,
{
    client_id: ClientId,
    drbg: &'a mut ChaCha8Rng,
    store: P::S,
}

impl<'a, P: Platform> ClientKeystore<'a, P> {
    pub fn new(client_id: ClientId, drbg: &'a mut ChaCha8Rng, store: P::S) -> Self {
        Self { client_id, drbg, store }
    }
}

pub const SERIALIZATION_VERSION: u8 = 0;

// pub enum Kind {
//     Shared(u16),
//     Symmetric(u16),
//     SymmetricWithNonce(u16, u8),
// }

// #[derive(Clone,Debug,Eq,PartialEq,SerializeIndexed,DeserializeIndexed)]
// pub struct Key {
//    // r#type: Secrecy,
//    pub kind: Kind,
//    pub flags: Flags,
//    pub raw: Data, //ByteBuf<MAX_SERIALIZED_KEY_LENGTH>,
// }

/// Trait intended for use by mechanism implementations.
pub trait Keystore {
    // fn store(&self, key: Key, location: Location) -> Result<KeyId>;
    // fn load(&self, key: KeyId) -> Result<Key>;
    // fn exists(&self, key: KeyId) -> bool;
    fn store_key(&mut self, location: Location, secret: Secrecy, kind: KeyKind, material: &[u8]) -> Result<KeyId>;
    fn exists_key(&self, secrecy: Secrecy, kind: Option<KeyKind>, id: &KeyId) -> bool;
    fn delete_key(&self, id: &KeyId) -> bool;
    fn load_key(&self, secret: Secrecy, kind: Option<KeyKind>, id: &KeyId) -> Result<SerializedKey>;
    fn overwrite_key(&self, location: Location, secrecy: Secrecy, kind: KeyKind, id: &KeyId, material: &[u8]) -> Result<()>;
    fn drbg(&mut self) -> &mut ChaCha8Rng;
    fn location(&self, secret: Secrecy, id: &KeyId) -> Option<Location>;
}

impl<P: Platform> ClientKeystore<'_, P> {

    pub fn generate_key_id(&mut self) -> KeyId {
        let mut id = [0u8; 16];

        self.drbg.fill_bytes(&mut id);
        crate::types::UniqueId(id)
    }

    pub fn key_path(&self, secret: Secrecy, id: &KeyId) -> PathBuf {
        let mut path = PathBuf::new();
        path.push(&self.client_id);
        // TODO: huh?!?!
        // If I change these prefixes to shorter,
        // DebugDumpStore skips the directory contents
        path.push(match secret {
            Secrecy::Secret => b"sec\0".try_into().unwrap(),
            Secrecy::Public => b"pub\0".try_into().unwrap(),
        });
        path.push(&PathBuf::from(id.hex().as_ref()));
        path
    }

}

impl<P: Platform> Keystore for ClientKeystore<'_, P> {

    fn drbg(&mut self) -> &mut ChaCha8Rng {
        self.drbg
    }

    fn store_key(&mut self, location: Location, secret: Secrecy, kind: KeyKind, material: &[u8]) -> Result<KeyId> {
        // info_now!("storing {:?} -> {:?}", &key_kind, location);
        let serialized_key = SerializedKey::try_from((kind, material))?;

        let mut buf = [0u8; 128];
        let serialized_bytes = crate::cbor_serialize(&serialized_key, &mut buf).map_err(|_| Error::CborError)?;
        let id = self.generate_key_id();
        let path = self.key_path(secret, &id);
        store::store(self.store, location, &path, &serialized_bytes)?;

        Ok(id)
    }

    fn exists_key(&self, secrecy: Secrecy, kind: Option<KeyKind>, id: &KeyId) -> bool {
        self.load_key(secrecy, kind, id).is_ok()
    }

    // TODO: is this an Oracle?
    fn delete_key(&self, id: &KeyId) -> bool {
        let secrecies = [
            Secrecy::Secret,
            Secrecy::Public,
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

    fn load_key(&self, secret: Secrecy, kind: Option<KeyKind>, id: &KeyId) -> Result<SerializedKey> {
        // info_now!("loading  {:?}", &key_kind);
        let path = self.key_path(secret, id);

        let location = self.location(secret, id).ok_or(Error::NoSuchKey)?;

        let bytes: ByteBuf<consts::U128> = store::read(self.store, location, &path)?;

        let serialized_key: SerializedKey = crate::cbor_deserialize(&bytes).map_err(|_| Error::CborError)?;

        if let Some(kind) = kind {
            if serialized_key.kind != kind {
                // info_now!("wrong key kind, expected {:?} got {:?}", &kind, &serialized_key.kind);
                Err(Error::WrongKeyKind)?;
            }
        }
        Ok(serialized_key)
    }

    fn overwrite_key(&self, location: Location, secrecy: Secrecy, kind: KeyKind, id: &KeyId, material: &[u8]) -> Result<()> {
        let serialized_key = SerializedKey::try_from((kind, material))?;

        let mut buf = [0u8; 128];
        let serialized_bytes = crate::cbor_serialize(&serialized_key, &mut buf).map_err(|_| Error::CborError)?;

        let path = self.key_path(secrecy, id);

        store::store(self.store, location, &path, &serialized_bytes)?;

        Ok(())
    }


    fn location(&self, secret: Secrecy, id: &KeyId) -> Option<Location> {
        let path = self.key_path(secret, id);

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
