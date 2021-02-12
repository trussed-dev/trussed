use core::convert::TryInto;

mod client;
mod store;

use trussed::{
    client::CounterClient as _,
    error::Result,
    syscall,
    types::Location::*,
    store::counterstore::{
        Counterstore as _,
        ClientCounterstore,
    },
};

#[test]
fn counter_implementation() {
    let result: Result<()> = store::get(|store| {

        let client_id = b"test".try_into().unwrap();
        let mut cstore = ClientCounterstore::new(client_id, *store);

        assert_eq!(cstore.increment_counter_zero(), 1);
        assert_eq!(cstore.increment_counter_zero(), 2);
        assert_eq!(cstore.increment_counter_zero(), 3);

        let id = cstore.create(Volatile).unwrap();  // counter zero is now at 4
        assert_eq!(cstore.increment_counter_zero(), 5);

        assert_eq!(cstore.increment(id)?, 1);
        assert_eq!(cstore.increment(id)?, 2);
        assert_eq!(cstore.increment(id)?, 3);

        assert_eq!(cstore.increment_counter_zero(), 6);
        Ok(())
    });
    result.unwrap();
}

#[test]
fn counter_client() {
    client::get(|client| {
        let id = syscall!(client.create_counter(Volatile)).id;
        assert_eq!(syscall!(client.increment_counter(id)).counter, 1);
        assert_eq!(syscall!(client.increment_counter(id)).counter, 2);
        assert_eq!(syscall!(client.increment_counter(id)).counter, 3);

        let jd = syscall!(client.create_counter(External)).id;
        assert_eq!(syscall!(client.increment_counter(jd)).counter, 1);
        assert_eq!(syscall!(client.increment_counter(jd)).counter, 2);

        assert_eq!(syscall!(client.increment_counter(id)).counter, 4);

        for i in 5..1_000 {
            assert_eq!(syscall!(client.increment_counter(id)).counter, i);
        }
        for j in 3..1_000 {
            assert_eq!(syscall!(client.increment_counter(jd)).counter, j);
        }

    });
}
