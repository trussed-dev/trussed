mod client;

use trussed_core::{syscall, try_syscall, types::Location::*, CertificateClient as _};

#[test]
fn certificate_client() {
    client::get(|client| {
        let fake_der = &[1u8, 2, 3];
        let id = syscall!(client.write_certificate(Volatile, fake_der)).id;

        let loaded_der = syscall!(client.read_certificate(id)).der;
        assert_eq!(loaded_der, fake_der);

        assert!(try_syscall!(client.read_certificate(id)).is_ok());
        assert!(try_syscall!(client.delete_certificate(id)).is_ok());
        assert!(try_syscall!(client.read_certificate(id)).is_err());
        assert!(try_syscall!(client.delete_certificate(id)).is_err());
    });
}
