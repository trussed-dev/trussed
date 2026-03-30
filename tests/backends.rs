use littlefs2_core::path;
use trussed::{
    backend::{self, BackendId},
    platform,
    service::ServiceResources,
    types::CoreContext,
    virt::{self, StoreConfig},
};
use trussed_core::{
    api::{reply::ReadFile, Reply, Request},
    syscall, try_syscall,
    types::{Location, Message, PathBuf},
    Error, FilesystemClient as _,
};

type Client<'a> = virt::Client<'a, Dispatch>;

const BACKENDS_TEST: &[BackendId<Backend>] = &[BackendId::Custom(Backend::Test), BackendId::Core];

pub enum Backend {
    Test,
}

#[derive(Default, trussed_derive::Dispatch)]
#[dispatch(backend_id = "Backend")]
struct Dispatch {
    test: TestBackend,
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

fn run<F: FnOnce(&mut Client<'_>)>(backends: &'static [BackendId<Backend>], f: F) {
    virt::with_platform(StoreConfig::ram(), |platform| {
        platform.run_client_with_backends("test", Dispatch::default(), backends, |mut client| {
            f(&mut client)
        })
    })
}

#[test]
fn override_syscall() {
    let path = PathBuf::from(path!("test"));
    run(&[], |client| {
        assert!(try_syscall!(client.read_file(Location::Internal, path.clone())).is_err());
    });
    run(BACKENDS_TEST, |client| {
        assert_eq!(
            syscall!(client.read_file(Location::Internal, path.clone())).data,
            &[0xff]
        );
    })
}
