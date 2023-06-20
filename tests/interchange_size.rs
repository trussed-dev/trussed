use std::mem::size_of;

use trussed::api::{Reply, Request};

// Used to keep track
#[test]
#[ignore]
fn interchange_size() {
    assert_eq!((size_of::<Reply>(), size_of::<Request>()), (2408, 2416));
}
