mod client;
mod store;

use trussed::{
    client::{
        CounterClient as _,
        // ManagementClient as _,
    },
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

        let client_id = "test".into();
        let mut cstore = ClientCounterstore::new(client_id, *store);

        assert_eq!(cstore.increment_counter_zero(), 257);
        assert_eq!(cstore.increment_counter_zero(), 258);
        assert_eq!(cstore.increment_counter_zero(), 259);

        let id = cstore.create(Volatile).unwrap();  // counter zero is now at 4
        assert_eq!(cstore.increment_counter_zero(), 261);

        assert_eq!(cstore.increment(id)?, 257);
        assert_eq!(cstore.increment(id)?, 258);
        assert_eq!(cstore.increment(id)?, 259);

        assert_eq!(cstore.increment_counter_zero(), 262);
        Ok(())
    });
    result.unwrap();
}

#[test]
fn counter_client() {
    client::get(|client| {
        let id = syscall!(client.create_counter(Volatile)).id;
        assert_eq!(syscall!(client.increment_counter(id)).counter, 257);
        assert_eq!(syscall!(client.increment_counter(id)).counter, 258);
        assert_eq!(syscall!(client.increment_counter(id)).counter, 259);

        let jd = syscall!(client.create_counter(External)).id;
        assert_eq!(syscall!(client.increment_counter(jd)).counter, 257);
        assert_eq!(syscall!(client.increment_counter(jd)).counter, 258);

        assert_eq!(syscall!(client.increment_counter(id)).counter, 260);

        for i in 5..1_000 {
            assert_eq!(syscall!(client.increment_counter(id)).counter, 256 + i);
        }
        for j in 3..1_000 {
            assert_eq!(syscall!(client.increment_counter(jd)).counter, 256 + j);
        }

        // assert_eq!(syscall!(client.uptime()).uptime.as_nanos(), 10);

    });
}
