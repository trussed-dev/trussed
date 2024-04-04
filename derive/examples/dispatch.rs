mod backends {
    use trussed::backend::Backend;

    #[derive(Default)]
    pub struct ABackend;

    impl Backend for ABackend {
        type Context = ();
    }
}

enum Backend {
    A,
}

#[derive(Default, trussed_derive::Dispatch)]
#[dispatch(backend_id = "Backend")]
struct Dispatch {
    a: backends::ABackend,
}

fn main() {
    use trussed::{
        backend::BackendId,
        client::CryptoClient,
        try_syscall,
        virt::{self, Ram},
        Error,
    };

    fn run(backends: &'static [BackendId<Backend>], expected: Option<Error>) {
        virt::with_platform(Ram::default(), |platform| {
            platform.run_client_with_backends(
                "test",
                Dispatch::default(),
                backends,
                |mut client| {
                    assert_eq!(try_syscall!(client.random_bytes(42)).err(), expected);
                },
            )
        });
    }

    run(&[BackendId::Core], None);
    run(
        &[BackendId::Custom(Backend::A)],
        Some(Error::RequestNotAvailable),
    );
}
