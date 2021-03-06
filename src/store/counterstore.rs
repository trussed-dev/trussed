use core::{
    convert::TryInto,
    fmt::Write,
};

use littlefs2::path::PathBuf;

use crate::{
    Bytes,
    consts,
    error::{Error, Result},
    store::{self, Store},
    types::{ClientId, Id, Location as Location},
};


pub struct ClientCounterstore<S>
where
    S: Store,
{
    client_id: ClientId,
    store: S,
}

pub type Counter = u128;

const COUNTER_ZERO: Id = Id(0);

impl<S: Store> ClientCounterstore<S> {
    pub fn new(client_id: ClientId, store: S) -> Self {
        Self { client_id, store }
    }

    fn counter_path(&self, id: u128) -> PathBuf {
        let mut path = PathBuf::new();
        path.push(&self.client_id);
        path.push(&PathBuf::from("ctr"));
        let mut buf = Bytes::<consts::U32>::new();
        write!(&mut buf, "{}", id).ok();
        path.push(&PathBuf::from(buf.as_slice()));
        path
    }

    fn read_counter(&mut self, location: Location, id: u128) -> Result<Counter> {
        let path = self.counter_path(id);
        let mut bytes: crate::Bytes<crate::consts::U16> = store::read(self.store, location, &path)?;
        bytes.resize_default(16).ok();
        Ok(u128::from_le_bytes(bytes.as_slice().try_into().unwrap()))
    }

    fn write_counter(&mut self, location: Location, id: u128, value: u128) -> Result<()> {
        let path = self.counter_path(id);
        store::store(self.store, location, &path, &value.to_le_bytes())
    }

    fn increment_location(&mut self, location: Location, id: Id) -> Result<Counter> {
        let prev_counter: u128 = self.read_counter(location, id.0)?.into();
        let counter = prev_counter + 1;
        self.write_counter(location, id.0, counter)?;
        Ok(counter)
    }
}

/// Trait intended for use by mechanism implementations.
pub trait Counterstore {
    fn create_starting_at(&mut self, location: Location, starting_at: impl Into<Counter>) -> Result<Id>;
    fn create(&mut self, location: Location) -> Result<Id> {
        self.create_starting_at(location, 0u128)
    }
    fn increment(&mut self, id: Id) -> Result<u128>;
    fn increment_counter_zero(&mut self) -> u128;
}

impl<S: Store> Counterstore for ClientCounterstore<S> {
    fn create_starting_at(&mut self, location: Location, starting_at: impl Into<Counter>) -> Result<Id> {
        let next_id = self.increment_counter_zero();
        self.write_counter(location, next_id, u128::from(starting_at.into()))?;
        Ok(Id(next_id))
    }

    fn increment(&mut self, id: Id) -> Result<u128> {
        let locations = [
            Location::Internal,
            Location::External,
            Location::Volatile,
        ];

        locations.iter().filter_map(|&location| {
            self.increment_location(location, id).ok()
        }).next().ok_or(Error::NoSuchKey)
    }

    fn increment_counter_zero(&mut self) -> Counter {
        self.increment_location(Location::Internal, COUNTER_ZERO)
            .unwrap_or_else(|_| {
                self.write_counter(Location::Internal, 0, 0).map_err(|_| {
                        panic!("writing to {} failed", &self.counter_path(0));
                }).unwrap();
                self.increment_location(Location::Internal, COUNTER_ZERO).unwrap()
            })
    }

}

// #[derive(Copy, Clone, Debug, PartialEq, PartialOrd)]
// pub struct Counter(pub u128);

// impl From<u128> for Counter {
//     fn from(value: u128) -> Self {
//         Self(value)
//     }
// }

// impl From<u64> for Counter {
//     fn from(value: u64) -> Self {
//         Self(value as _)
//     }
// }

// impl From<u32> for Counter {
//     fn from(value: u32) -> Self {
//         Self(value as _)
//     }
// }

// impl From<u16> for Counter {
//     fn from(value: u16) -> Self {
//         Self(value as _)
//     }
// }

// impl From<u8> for Counter {
//     fn from(value: u8) -> Self {
//         Self(value as _)
//     }
// }

// impl From<Counter> for u128 {
//     fn from(counter: Counter) -> Self {
//         counter.0
//     }
// }

