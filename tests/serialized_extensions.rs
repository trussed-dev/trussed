#![cfg(all(feature = "serde-extensions", feature = "virt"))]

use trussed::{
    backend::BackendId,
    service::Service,
    types::ShortData,
    virt::{self, Ram},
    ClientImplementation,
};

use backends::Backends;

type Platform = virt::Platform<Ram>;
type Client = ClientImplementation<Service<Platform, Backends>, Backends>;

mod backends {
    use super::{
        backend::{TestBackend, TestContext},
        ext::TestExtension,
    };

    use trussed::{
        api::{reply, request, Reply, Request},
        backend::{Backend as _, BackendId},
        error::Error,
        platform::Platform,
        serialized_extensions::{ExtensionDispatch, ExtensionId, ExtensionImpl},
        service::ServiceResources,
        types::Context,
    };

    pub const BACKENDS_TEST1: &[BackendId<Backend>] =
        &[BackendId::Custom(Backend::Test), BackendId::Core];
    pub const BACKENDS_TEST2: &[BackendId<Backend>] =
        &[BackendId::Core, BackendId::Custom(Backend::Test)];

    pub enum Backend {
        Test,
    }

    pub enum Extension {
        Test,
    }

    impl From<Extension> for u8 {
        fn from(extension: Extension) -> Self {
            match extension {
                Extension::Test => 0,
            }
        }
    }

    impl TryFrom<u8> for Extension {
        type Error = Error;

        fn try_from(value: u8) -> Result<Self, Self::Error> {
            match value {
                0 => Ok(Self::Test),
                _ => Err(Error::InternalError),
            }
        }
    }

    #[derive(Default)]
    pub struct BackendsContext {
        test: TestContext,
    }

    #[derive(Default)]
    pub struct Backends {
        test: TestBackend,
    }

    impl<P: Platform> ExtensionDispatch<P> for Backends {
        type BackendId = Backend;
        type Context = BackendsContext;
        type ExtensionId = Extension;

        fn core_request(
            &mut self,
            backend: &Self::BackendId,
            ctx: &mut Context<Self::Context>,
            request: &Request,
            resources: &mut ServiceResources<P>,
        ) -> Result<Reply, Error> {
            match backend {
                Backend::Test => {
                    self.test
                        .request(&mut ctx.core, &mut ctx.backends.test, request, resources)
                }
            }
        }
        fn extension_request(
            &mut self,
            backend: &Self::BackendId,
            extension: &Self::ExtensionId,
            ctx: &mut Context<Self::Context>,
            request: &request::Extension,
            resources: &mut ServiceResources<P>,
        ) -> Result<reply::Extension, Error> {
            match backend {
                Backend::Test => match extension {
                    Extension::Test => self.test.extension_request_serialized(
                        &mut ctx.core,
                        &mut ctx.backends.test,
                        request,
                        resources,
                    ),
                },
            }
        }
    }

    impl ExtensionId<TestExtension> for Backends {
        type Id = Extension;

        const ID: Self::Id = Self::Id::Test;
    }
}

mod backend {
    use super::ext::{GetCallsReply, ReverseReply, TestExtension, TestReply, TestRequest};

    use trussed::{
        backend::Backend,
        error::Error,
        platform::Platform,
        serialized_extensions::ExtensionImpl,
        service::ServiceResources,
        types::{CoreContext, ShortData},
    };

    #[derive(Default)]
    pub struct TestContext {
        calls: u64,
    }

    #[derive(Default)]
    pub struct TestBackend;

    impl<P: Platform> Backend<P> for TestBackend {
        type Context = TestContext;
    }

    impl<P: Platform> ExtensionImpl<TestExtension, P> for TestBackend {
        fn extension_request(
            &mut self,
            _core_ctx: &mut CoreContext,
            backend_ctx: &mut TestContext,
            request: &TestRequest,
            _resources: &mut ServiceResources<P>,
        ) -> Result<TestReply, Error> {
            match request {
                TestRequest::GetCalls(_) => Ok(TestReply::GetCalls(GetCallsReply {
                    calls: backend_ctx.calls,
                })),
                TestRequest::Reverse(request) => {
                    backend_ctx.calls += 1;
                    let mut s = ShortData::new();
                    for byte in request.s.iter().rev() {
                        s.push(*byte).unwrap();
                    }
                    Ok(TestReply::Reverse(ReverseReply { s }))
                }
            }
        }
    }
}

mod ext {
    use serde::{Deserialize, Serialize};
    use trussed::{
        error::Error,
        serialized_extensions::{Extension, ExtensionClient, ExtensionResult},
        types::ShortData,
    };

    pub struct TestExtension;

    impl Extension for TestExtension {
        type Request = TestRequest;
        type Reply = TestReply;
    }

    #[derive(Deserialize, Serialize)]
    pub enum TestRequest {
        GetCalls(GetCallsRequest),
        Reverse(ReverseRequest),
    }

    #[derive(Deserialize, Serialize)]
    pub struct GetCallsRequest;

    impl From<GetCallsRequest> for TestRequest {
        fn from(request: GetCallsRequest) -> Self {
            Self::GetCalls(request)
        }
    }

    #[derive(Deserialize, Serialize)]
    pub struct ReverseRequest {
        pub s: ShortData,
    }

    impl From<ReverseRequest> for TestRequest {
        fn from(request: ReverseRequest) -> Self {
            Self::Reverse(request)
        }
    }

    #[derive(Deserialize, Serialize)]
    pub enum TestReply {
        GetCalls(GetCallsReply),
        Reverse(ReverseReply),
    }

    #[derive(Deserialize, Serialize)]
    pub struct GetCallsReply {
        pub calls: u64,
    }

    impl TryFrom<TestReply> for GetCallsReply {
        type Error = Error;

        fn try_from(reply: TestReply) -> Result<Self, Self::Error> {
            match reply {
                TestReply::GetCalls(reply) => Ok(reply),
                _ => Err(Error::InternalError),
            }
        }
    }

    #[derive(Deserialize, Serialize)]
    pub struct ReverseReply {
        pub s: ShortData,
    }

    impl TryFrom<TestReply> for ReverseReply {
        type Error = Error;

        fn try_from(reply: TestReply) -> Result<Self, Self::Error> {
            match reply {
                TestReply::Reverse(reply) => Ok(reply),
                _ => Err(Error::InternalError),
            }
        }
    }

    pub trait TestClient: ExtensionClient<TestExtension> {
        fn calls(&mut self) -> ExtensionResult<'_, TestExtension, GetCallsReply, Self> {
            self.extension(GetCallsRequest)
        }

        fn reverse(
            &mut self,
            s: ShortData,
        ) -> ExtensionResult<'_, TestExtension, ReverseReply, Self> {
            self.extension(ReverseRequest { s })
        }
    }

    impl<C: ExtensionClient<TestExtension>> TestClient for C {}
}

pub fn run<F: FnOnce(&mut Client)>(backends: &'static [BackendId<backends::Backend>], f: F) {
    virt::with_platform(Ram::default(), |platform| {
        platform.run_client_with_backends(
            "test",
            backends::Backends::default(),
            backends,
            |mut client| f(&mut client),
        )
    })
}

#[test]
fn extension() {
    use ext::TestClient as _;

    let msg = ShortData::from_slice(&[0x01, 0x02, 0x03]).unwrap();
    let rev = ShortData::from_slice(&[0x03, 0x02, 0x01]).unwrap();
    run(&[], |client| {
        assert!(trussed::try_syscall!(client.reverse(msg.clone())).is_err());
    });
    run(backends::BACKENDS_TEST1, |client| {
        assert_eq!(trussed::syscall!(client.calls()).calls, 0);
        assert_eq!(trussed::syscall!(client.reverse(msg.clone())).s, rev);
        assert_eq!(trussed::syscall!(client.calls()).calls, 1);
        assert_eq!(trussed::syscall!(client.calls()).calls, 1);
        assert_eq!(trussed::syscall!(client.reverse(msg.clone())).s, rev);
        assert_eq!(trussed::syscall!(client.calls()).calls, 2);
    });
    run(backends::BACKENDS_TEST2, |client| {
        assert_eq!(trussed::syscall!(client.calls()).calls, 0);
        assert_eq!(trussed::syscall!(client.reverse(msg.clone())).s, rev);
        assert_eq!(trussed::syscall!(client.calls()).calls, 1);
    });
}
