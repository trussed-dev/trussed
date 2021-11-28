use generic_array::typenum::assert_type;
use trussed::client::mechanisms::Rsa2kPkcs;
use trussed::syscall;
use trussed::types::KeyId;

mod client;

use trussed::types::Location::*;

#[test]
fn rsa2kpkcs_generate_key() {
    client::get(|client| {
        let sk = syscall!(client.generate_rsa2kpkcs_private_key(Internal)).key;

        // This assumes we don't really get they key with ID 0
        // TODO: make sure the above always holds
        assert_ne!(sk, KeyId::from_special(0));
    })
}
