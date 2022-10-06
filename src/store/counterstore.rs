use littlefs2::path::PathBuf;
use rand_chacha::ChaCha8Rng;

use crate::{
    error::{Error, Result},
    store::{self, Store},
    types::{ClientId, CounterId, Location},
};

pub struct ClientCounterstore<S>
where
    S: Store,
{
    client_id: ClientId,
    rng: ChaCha8Rng,
    store: S,
}

pub type Counter = u128;

impl<S: Store> ClientCounterstore<S> {
    pub fn new(client_id: ClientId, rng: ChaCha8Rng, store: S) -> Self {
        Self {
            client_id,
            rng,
            store,
        }
    }

    fn counter_path(&self, id: CounterId) -> PathBuf {
        let mut path = PathBuf::new();
        path.push(&self.client_id);
        path.push(&PathBuf::from("ctr"));
        path.push(&PathBuf::from(id.hex().as_slice()));
        path
    }

    fn read_counter(&mut self, location: Location, id: CounterId) -> Result<Counter> {
        let path = self.counter_path(id);
        let mut bytes: crate::Bytes<16> = store::read(self.store, location, &path)?;
        bytes.resize_default(16).ok();
        Ok(u128::from_le_bytes(bytes.as_slice().try_into().unwrap()))
    }

    fn write_counter(&mut self, location: Location, id: CounterId, value: u128) -> Result<()> {
        let path = self.counter_path(id);
        store::store(self.store, location, &path, &value.to_le_bytes())
    }

    fn increment_location(&mut self, location: Location, id: CounterId) -> Result<Counter> {
        let counter: u128 = self.read_counter(location, id)?;
        let next_counter = counter + 1;
        self.write_counter(location, id, next_counter)?;
        Ok(counter)
    }
}

/// Trait intended for use by mechanism implementations.
pub trait Counterstore {
    const DEFAULT_START_AT: u128 = 0;
    fn create_starting_at(
        &mut self,
        location: Location,
        starting_at: impl Into<Counter>,
    ) -> Result<CounterId>;
    fn create(&mut self, location: Location) -> Result<CounterId> {
        self.create_starting_at(location, Self::DEFAULT_START_AT)
    }
    fn increment(&mut self, id: CounterId) -> Result<u128>;
}

impl<S: Store> Counterstore for ClientCounterstore<S> {
    fn create_starting_at(
        &mut self,
        location: Location,
        starting_at: impl Into<Counter>,
    ) -> Result<CounterId> {
        let id = CounterId::new(&mut self.rng);
        self.write_counter(location, id, starting_at.into())?;
        Ok(id)
    }

    fn increment(&mut self, id: CounterId) -> Result<u128> {
        let locations = [Location::Internal, Location::External, Location::Volatile];

        locations
            .iter()
            .filter_map(|&location| self.increment_location(location, id).ok())
            .next()
            .ok_or(Error::NoSuchKey)
    }
}
