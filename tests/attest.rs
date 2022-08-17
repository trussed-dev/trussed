// use trussed::client::mechanisms::{Ed255, P256};
// use trussed::syscall;

// mod client;

// use trussed::types::Location::*;

// tests not working as no setup of the attn keys in place
// tests were valid for previous implementation using self-signed certificates

// #[test]
// fn ed255_attest() {
//     client::get(|client| {
//         // let _private_key = syscall!(client.generate_ed255_private_key(Internal)).key;
//         // let attn_cert_id = syscall!(client.attest(Mechanism::Ed255, private_key)).certificate;
//         // let _cert = syscall!(client.read_certificate(attn_cert_id)).der;
//         // panic!("DER:\n{:x}", delog::hex_str!(&_cert));
//     })
// }

// #[test]
// fn p256_attest() {
//     client::get(|client| {
//         // let _private_key = syscall!(client.generate_p256_private_key(Internal)).key;
//         // let attn_cert_id = syscall!(client.attest(Mechanism::P256, private_key)).certificate;
//         // let _cert = syscall!(client.read_certificate(attn_cert_id)).der;
//         // panic!("DER:\n{:x}", delog::hex_str!(&_cert));
//     })
// }
