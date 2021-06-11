#[allow(dead_code)]
mod client;

#[cfg(feature = "p384")]
mod test {
    use super::client;
    use trussed::client::mechanisms::{HmacSha256, P384};
    use trussed::syscall;

    use trussed::types::{Location::*, SignatureSerialization};


    #[test]
    fn p384_agree() {
        client::get(|client| {
            let sk1 = syscall!(client.generate_p384_private_key(Internal)).key;
            let pk1 = syscall!(client.derive_p384_public_key(sk1, Volatile)).key;
            let sk2 = syscall!(client.generate_p384_private_key(Internal)).key;
            let pk2 = syscall!(client.derive_p384_public_key(sk2, Volatile)).key;

            let secret1 = syscall!(client.agree_p384(sk1, pk2, Volatile)).shared_secret;
            let secret2 = syscall!(client.agree_p384(sk2, pk1, Volatile)).shared_secret;

            // Trussed® won't give out secrets, but lets us use them
            let derivative1 = syscall!(client.sign_hmacsha256(secret1, &[])).signature;
            let derivative2 = syscall!(client.sign_hmacsha256(secret2, &[])).signature;
            assert_eq!(derivative1, derivative2);

            let msg = b"It's a miracle!";
            let signature = syscall!(client.sign_p384(sk1, msg, SignatureSerialization::Raw)).signature;
            assert!(syscall!(client.verify_p384(pk1, msg, &signature)).valid);
            assert!(!syscall!(client.verify_p384(pk2, msg, &signature)).valid);
        })
    }
}
