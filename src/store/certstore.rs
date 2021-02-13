use core::{
    convert::TryInto,
    fmt::Write,
};

use littlefs2::path::PathBuf;

use crate::{
    ByteBuf,
    consts,
    error::{Error, Result},
    store::{self, Store},
    types::{ClientId, Id, Location, Message},
};

use super::counterstore::Counterstore;


pub struct ClientCertstore<S>
where
    S: Store,
{
    client_id: ClientId,
    store: S,
}

pub trait Certstore {
    fn delete_certificate(&mut self, id: Id) -> Result<()>;
    fn read_certificate(&mut self, id: Id) -> Result<Message>;
    /// TODO: feels a bit heavy-weight to pass in the ClientCounterstore here
    /// just to ensure the next global counter ("counter zero") is used, and
    /// not something random.
    fn write_certificate(&mut self, location: Location, der: &Message, counterstore: &mut impl Counterstore) -> Result<Id>;
}

impl<S: Store> Certstore for ClientCertstore<S> {

    fn delete_certificate(&mut self, id: Id) -> Result<()> {
        let path = self.cert_path(id);
        let locations = [
            Location::Internal,
            Location::External,
            Location::Volatile,
        ];
        locations.iter().any(|&location| {
            store::delete(self.store, location, &path)
        }).then(|| ()).ok_or(Error::NoSuchKey)
    }

    fn read_certificate(&mut self, id: Id) -> Result<Message> {
        let path = self.cert_path(id);
        let locations = [
            Location::Internal,
            Location::External,
            Location::Volatile,
        ];
        locations.iter().find_map(|&location| {
            store::read(self.store, location, &path).ok()
        }).ok_or(Error::NoSuchCertificate)
    }

    fn write_certificate(&mut self, location: Location, der: &Message, counterstore: &mut impl Counterstore) -> Result<Id> {
        let id = Id(counterstore.increment_counter_zero());
        let path = self.cert_path(id);
        store::store(self.store, location, &path, &der.as_slice())?;
        Ok(id)
    }
}

impl<S: Store> ClientCertstore<S> {
    pub fn new(client_id: ClientId, store: S) -> Self {
        Self { client_id, store }
    }

    fn cert_path(&self, id: Id) -> PathBuf {
        let mut path = PathBuf::new();
        path.push(&self.client_id);
        path.push(b"x5c\0".try_into().unwrap());
        let mut buf = ByteBuf::<consts::U32>::new();
        write!(&mut buf, "{}", id.0).ok();
        path.push(&PathBuf::from(buf.as_slice()));
        path
    }

    // fn read_cert(&mut self, location: Location, id: u128) -> Result<Message> {
    //     let path = self.cert_path(id);
    //     let mut data: Message = store::read(self.store, location, &path)?;
    //     Ok(data)
    // }

    // fn write_cert(&mut self, location: Location, id: u128, data: Message) -> Result<()> {
    //     let path = self.cert_path(id);
    //     store::store(self.store, location, &path, &data)
    // }

}

