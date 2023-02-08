#![cfg(feature = "virt")]

use trussed::{
    api::{reply::ReadFile, Reply, Request},
    backend::{self, Backend as _, BackendId},
    client::FilesystemClient as _,
    error::Error,
    platform,
    service::{Service, ServiceResources},
    types::{Context, CoreContext, Location, Message, PathBuf},
    virt::{self, Ram},
    ClientImplementation,
};

type Platform = virt::Platform<Ram>;
type Client = ClientImplementation<Service<Platform, Dispatch>, Dispatch>;

const BACKENDS_TEST: &[BackendId<Backend>] = &[BackendId::Custom(Backend::Test), BackendId::Core];

pub enum Backend {
    Test,
}

#[derive(Default)]
struct Dispatch {
    test: TestBackend,
}

impl backend::Dispatch for Dispatch {
    type BackendId = Backend;
    type Context = ();

    fn request<P: platform::Platform>(
        &mut self,
        backend: &Self::BackendId,
        ctx: &mut Context<()>,
        request: &Request,
        resources: &mut ServiceResources<P>,
    ) -> Result<Reply, Error> {
        match backend {
            Backend::Test => {
                self.test
                    .request(&mut ctx.core, &mut ctx.backends, request, resources)
            }
        }
    }
}

#[derive(Default)]
struct TestBackend;

impl backend::Backend for TestBackend {
    type Context = ();

    fn request<P: platform::Platform>(
        &mut self,
        _core_ctx: &mut CoreContext,
        _backend_ctx: &mut Self::Context,
        request: &Request,
        _resources: &mut ServiceResources<P>,
    ) -> Result<Reply, Error> {
        match request {
            Request::ReadFile(_) => {
                let mut data = Message::new();
                data.push(0xff).unwrap();
                Ok(Reply::ReadFile(ReadFile { data }))
            }
            _ => Err(Error::RequestNotAvailable),
        }
    }
}

fn run<F: FnOnce(&mut Client)>(backends: &'static [BackendId<Backend>], f: F) {
    virt::with_platform(Ram::default(), |platform| {
        platform.run_client_with_backends("test", Dispatch::default(), backends, |mut client| {
            f(&mut client)
        })
    })
}

#[test]
fn override_syscall() {
    let path = PathBuf::from("test");
    run(&[], |client| {
        assert!(trussed::try_syscall!(client.read_file(Location::Internal, path.clone())).is_err());
    });
    run(BACKENDS_TEST, |client| {
        assert_eq!(
            trussed::syscall!(client.read_file(Location::Internal, path.clone())).data,
            &[0xff]
        );
    })
}
