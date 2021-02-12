use trussed::client::{HmacSha256, X255};
use trussed::syscall;

mod client;

use trussed::types::StorageLocation::*;


#[test]
fn x255_agree() {
    client::get(|client| {
        let sk1 = syscall!(client.generate_x255_secret_key(Internal)).key;
        let pk1 = syscall!(client.derive_x255_public_key(sk1, Volatile)).key;
        let sk2 = syscall!(client.generate_x255_secret_key(Internal)).key;
        let pk2 = syscall!(client.derive_x255_public_key(sk2, Volatile)).key;

        let secret1 = syscall!(client.agree_x255(sk1, pk2, Volatile)).shared_secret;
        let secret2 = syscall!(client.agree_x255(sk2, pk1, Volatile)).shared_secret;

        // Trussed® won't give out secrets, but lets us use them
        let derivative1 = syscall!(client.sign_hmacsha256(secret1, &[])).signature;
        let derivative2 = syscall!(client.sign_hmacsha256(secret2, &[])).signature;
        assert_eq!(derivative1, derivative2);
    })
}
