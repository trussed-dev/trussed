#![cfg(feature = "virt")]
#![cfg(feature = "counter-client")]

mod client;
mod store;

use trussed::{client::CounterClient as _, syscall, types::Location::*};

// #[test]
// fn counter_implementation() {
//     let result: Result<()> = store::get(|store| {

//         let client_id = "test".into();
//         let mut cstore = ClientCounterstore::new(client_id, *store);

//         assert_eq!(cstore.increment_counter_zero(), 257);
//         assert_eq!(cstore.increment_counter_zero(), 258);
//         assert_eq!(cstore.increment_counter_zero(), 259);

//         let id = cstore.create(Volatile).unwrap();  // counter zero is now at 4
//         assert_eq!(cstore.increment_counter_zero(), 261);

//         assert_eq!(cstore.increment(id)?, 257);
//         assert_eq!(cstore.increment(id)?, 258);
//         assert_eq!(cstore.increment(id)?, 259);

//         assert_eq!(cstore.increment_counter_zero(), 262);
//         Ok(())
//     });
//     result.unwrap();
// }

#[test]
fn counter_client() {
    client::get(|client| {
        let id = syscall!(client.create_counter(Volatile)).id;
        assert_eq!(syscall!(client.increment_counter(id)).counter, 0);
        assert_eq!(syscall!(client.increment_counter(id)).counter, 1);
        assert_eq!(syscall!(client.increment_counter(id)).counter, 2);

        let jd = syscall!(client.create_counter(External)).id;
        assert_eq!(syscall!(client.increment_counter(jd)).counter, 0);
        assert_eq!(syscall!(client.increment_counter(jd)).counter, 1);

        assert_eq!(syscall!(client.increment_counter(id)).counter, 3);

        for i in 4..1_000 {
            assert_eq!(syscall!(client.increment_counter(id)).counter, i);
        }
        for j in 2..1_000 {
            assert_eq!(syscall!(client.increment_counter(jd)).counter, j);
        }
    });
}
