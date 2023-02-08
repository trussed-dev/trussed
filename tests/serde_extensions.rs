#![cfg(all(feature = "serde-extensions", feature = "virt"))]

// Example displaying and testing multiple backends and extensions:
//
// Extensions (in module `extensions`):
// - the TestExtension has a "reverse" method (and "calls")
// - the SampleExtension has a "truncate" method (and "calls")
//
// These extensions also define extension traits of ExtensionClient,
// giving methods with useful names to call the extensions.
//
// Backends (in module `backend`):
// - the TestBackend implements the TestExtension
// - the SampleBackend implements both the TestExtension and the SampleExtension
//
// The extensions might be defined in individual crates,
// as could the backends (depending on their respective extension dependencies).
//
// It is then the responsibility of a "runner" to
// - define the Backend and Extension ID types (enums corresponding to a set of u8)
// - define a struct containing the included custom backends (called `Backends` below),
// - implementing ExtensionDispatch for this Backends struct.
//
// This latter implementation is currently a little verbose, and might be lifted into
// the serde_extensions module.
//
// We could also devise of a custom Map type for such backend compositions.

use trussed::{
    backend::BackendId,
    service::Service,
    types::ShortData,
    virt::{self, Ram},
    ClientImplementation,
};

use runner::Backends;

type Platform = virt::Platform<Ram>;
type Client = ClientImplementation<Service<Platform, Backends>, Backends>;

mod extensions {
    use serde::{Deserialize, Serialize};
    use trussed::{
        error::Error,
        serde_extensions::{Extension, ExtensionClient, ExtensionResult},
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
        fn test_calls(&mut self) -> ExtensionResult<'_, TestExtension, GetCallsReply, Self> {
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

    pub struct SampleExtension;

    impl Extension for SampleExtension {
        type Request = SampleRequest;
        type Reply = SampleReply;
    }

    #[derive(Deserialize, Serialize)]
    pub enum SampleRequest {
        GetCalls(GetCallsRequest),
        Truncate(TruncateRequest),
    }

    impl From<GetCallsRequest> for SampleRequest {
        fn from(request: GetCallsRequest) -> Self {
            Self::GetCalls(request)
        }
    }

    #[derive(Deserialize, Serialize)]
    pub struct TruncateRequest {
        pub s: ShortData,
    }

    impl From<TruncateRequest> for SampleRequest {
        fn from(request: TruncateRequest) -> Self {
            Self::Truncate(request)
        }
    }

    #[derive(Deserialize, Serialize)]
    pub enum SampleReply {
        GetCalls(GetCallsReply),
        Truncate(TruncateReply),
    }

    impl TryFrom<SampleReply> for GetCallsReply {
        type Error = Error;

        fn try_from(reply: SampleReply) -> Result<Self, Self::Error> {
            match reply {
                SampleReply::GetCalls(reply) => Ok(reply),
                _ => Err(Error::InternalError),
            }
        }
    }

    #[derive(Deserialize, Serialize)]
    pub struct TruncateReply {
        pub s: ShortData,
    }

    impl TryFrom<SampleReply> for TruncateReply {
        type Error = Error;

        fn try_from(reply: SampleReply) -> Result<Self, Self::Error> {
            match reply {
                SampleReply::Truncate(reply) => Ok(reply),
                _ => Err(Error::InternalError),
            }
        }
    }

    pub trait SampleClient: ExtensionClient<SampleExtension> {
        fn sample_calls(&mut self) -> ExtensionResult<'_, SampleExtension, GetCallsReply, Self> {
            self.extension(GetCallsRequest)
        }

        fn truncate(
            &mut self,
            s: ShortData,
        ) -> ExtensionResult<'_, SampleExtension, TruncateReply, Self> {
            self.extension(TruncateRequest { s })
        }
    }

    impl<C: ExtensionClient<SampleExtension>> SampleClient for C {}
}

mod backends {
    use super::extensions::{
        GetCallsReply, ReverseReply, SampleExtension, SampleReply, SampleRequest, TestExtension,
        TestReply, TestRequest, TruncateReply,
    };

    use trussed::{
        backend::Backend,
        error::Error,
        platform::Platform,
        serde_extensions::ExtensionImpl,
        service::ServiceResources,
        types::{CoreContext, ShortData},
    };

    #[derive(Default)]
    pub struct TestContext {
        calls: u64,
    }

    #[derive(Default)]
    /// Implements TestExtension
    pub struct TestBackend;

    impl Backend for TestBackend {
        type Context = TestContext;
    }

    impl ExtensionImpl<TestExtension> for TestBackend {
        fn extension_request<P: Platform>(
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

    #[derive(Default)]
    pub struct SampleContext {
        calls: u64,
    }

    #[derive(Default)]
    /// Implements SampleExtension and TestExtension
    pub struct SampleBackend;

    impl Backend for SampleBackend {
        type Context = SampleContext;
    }

    impl ExtensionImpl<SampleExtension> for SampleBackend {
        fn extension_request<P: Platform>(
            &mut self,
            _core_ctx: &mut CoreContext,
            backend_ctx: &mut SampleContext,
            request: &SampleRequest,
            _resources: &mut ServiceResources<P>,
        ) -> Result<SampleReply, Error> {
            match request {
                SampleRequest::GetCalls(_) => Ok(SampleReply::GetCalls(GetCallsReply {
                    calls: backend_ctx.calls,
                })),
                SampleRequest::Truncate(request) => {
                    backend_ctx.calls += 1;
                    let mut s = ShortData::new();
                    for byte in request.s.iter().take(3) {
                        s.push(*byte).unwrap();
                    }
                    Ok(SampleReply::Truncate(TruncateReply { s }))
                }
            }
        }
    }

    impl ExtensionImpl<TestExtension> for SampleBackend {
        fn extension_request<P: Platform>(
            &mut self,
            _core_ctx: &mut CoreContext,
            backend_ctx: &mut SampleContext,
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

mod runner {
    use super::{
        backends::{SampleBackend, SampleContext, TestBackend, TestContext},
        extensions::{SampleExtension, TestExtension},
    };

    pub mod id {
        use trussed::error::Error;

        pub enum Backend {
            Test,
            Sample,
        }

        pub enum Extension {
            Test = 37,
            Sample = 42,
        }

        impl From<Extension> for u8 {
            fn from(extension: Extension) -> Self {
                extension as u8
            }
        }

        impl TryFrom<u8> for Extension {
            type Error = Error;

            fn try_from(value: u8) -> Result<Self, Self::Error> {
                match value {
                    37 => Ok(Self::Test),
                    42 => Ok(Self::Sample),
                    _ => Err(Error::InternalError),
                }
            }
        }
    }

    use trussed::{
        api::{reply, request, Reply, Request},
        backend::{Backend as _, BackendId},
        error::Error,
        platform::Platform,
        serde_extensions::{ExtensionDispatch, ExtensionId, ExtensionImpl},
        service::ServiceResources,
        types::Context,
    };

    #[derive(Default)]
    pub struct Backends {
        test: TestBackend,
        sample: SampleBackend,
    }

    #[derive(Default)]
    pub struct BackendsContext {
        test: TestContext,
        sample: SampleContext,
    }

    impl ExtensionDispatch for Backends {
        type BackendId = id::Backend;
        type Context = BackendsContext;
        type ExtensionId = id::Extension;

        fn core_request<P: Platform>(
            &mut self,
            backend: &Self::BackendId,
            ctx: &mut Context<Self::Context>,
            request: &Request,
            resources: &mut ServiceResources<P>,
        ) -> Result<Reply, Error> {
            match backend {
                id::Backend::Test => {
                    self.test
                        .request(&mut ctx.core, &mut ctx.backends.test, request, resources)
                }
                id::Backend::Sample => {
                    self.sample
                        .request(&mut ctx.core, &mut ctx.backends.sample, request, resources)
                }
            }
        }

        fn extension_request<P: Platform>(
            &mut self,
            backend: &Self::BackendId,
            extension: &Self::ExtensionId,
            ctx: &mut Context<Self::Context>,
            request: &request::SerdeExtension,
            resources: &mut ServiceResources<P>,
        ) -> Result<reply::SerdeExtension, Error> {
            match backend {
                id::Backend::Test => match extension {
                    id::Extension::Test => self.test.extension_request_serialized(
                        &mut ctx.core,
                        &mut ctx.backends.test,
                        request,
                        resources,
                    ),
                    id::Extension::Sample => Err(Error::RequestNotAvailable),
                },
                id::Backend::Sample => match extension {
                    id::Extension::Test => <SampleBackend as ExtensionImpl<TestExtension>>::extension_request_serialized(
                        &mut self.sample,
                        &mut ctx.core,
                        &mut ctx.backends.sample,
                        request,
                        resources,
                    ),
                    id::Extension::Sample => <SampleBackend as ExtensionImpl<SampleExtension>>::extension_request_serialized(
                        &mut self.sample,
                        &mut ctx.core,
                        &mut ctx.backends.sample,
                        request,
                        resources,
                    ),
                },
            }
        }
    }

    impl ExtensionId<TestExtension> for Backends {
        type Id = id::Extension;
        const ID: Self::Id = Self::Id::Test;
    }

    impl ExtensionId<SampleExtension> for Backends {
        type Id = id::Extension;
        const ID: Self::Id = Self::Id::Sample;
    }

    pub const BACKENDS_TEST1: &[BackendId<id::Backend>] =
        &[BackendId::Custom(id::Backend::Test), BackendId::Core];
    pub const BACKENDS_TEST2: &[BackendId<id::Backend>] =
        &[BackendId::Core, BackendId::Custom(id::Backend::Test)];

    pub const BACKENDS_SAMPLE1: &[BackendId<id::Backend>] =
        &[BackendId::Custom(id::Backend::Sample), BackendId::Core];
    pub const BACKENDS_SAMPLE2: &[BackendId<id::Backend>] =
        &[BackendId::Core, BackendId::Custom(id::Backend::Sample)];

    pub const BACKENDS_MIXED: &[BackendId<id::Backend>] = &[
        BackendId::Custom(id::Backend::Test),
        BackendId::Custom(id::Backend::Sample),
    ];
}

pub fn run<F: FnOnce(&mut Client)>(backends: &'static [BackendId<runner::id::Backend>], f: F) {
    virt::with_platform(Ram::default(), |platform| {
        platform.run_client_with_backends(
            "test",
            runner::Backends::default(),
            backends,
            |mut client| f(&mut client),
        )
    })
}

#[test]
fn test_extension() {
    use extensions::TestClient as _;

    let msg = ShortData::from_slice(&[0x01, 0x02, 0x03]).unwrap();
    let rev = ShortData::from_slice(&[0x03, 0x02, 0x01]).unwrap();
    run(&[], |client| {
        assert!(trussed::try_syscall!(client.reverse(msg.clone())).is_err());
    });
    run(runner::BACKENDS_TEST1, |client| {
        assert_eq!(trussed::syscall!(client.test_calls()).calls, 0);
        assert_eq!(trussed::syscall!(client.reverse(msg.clone())).s, rev);
        assert_eq!(trussed::syscall!(client.test_calls()).calls, 1);
        assert_eq!(trussed::syscall!(client.test_calls()).calls, 1);
        assert_eq!(trussed::syscall!(client.reverse(msg.clone())).s, rev);
        assert_eq!(trussed::syscall!(client.test_calls()).calls, 2);
    });
    run(runner::BACKENDS_TEST2, |client| {
        assert_eq!(trussed::syscall!(client.test_calls()).calls, 0);
        assert_eq!(trussed::syscall!(client.reverse(msg.clone())).s, rev);
        assert_eq!(trussed::syscall!(client.test_calls()).calls, 1);
    });
}

#[test]
fn sample_extension() {
    use extensions::SampleClient as _;
    use extensions::TestClient as _;

    let msg = ShortData::from_slice(&[1, 2, 3, 4]).unwrap();
    let rev = ShortData::from_slice(&[4, 3, 2, 1]).unwrap();
    let trunc = ShortData::from_slice(&[1, 2, 3]).unwrap();
    run(&[], |client| {
        assert!(trussed::try_syscall!(client.truncate(msg.clone())).is_err());
    });
    run(runner::BACKENDS_SAMPLE1, |client| {
        assert_eq!(trussed::syscall!(client.sample_calls()).calls, 0);
        assert_eq!(trussed::syscall!(client.test_calls()).calls, 0);
        assert_eq!(trussed::syscall!(client.reverse(msg.clone())).s, rev);
        assert_eq!(trussed::syscall!(client.truncate(msg.clone())).s, trunc);
        // the sample backend has but one context that is shared for its
        // implementation of the extensions, so the calls increment together.
        assert_eq!(trussed::syscall!(client.sample_calls()).calls, 2);
        assert_eq!(trussed::syscall!(client.test_calls()).calls, 2);
        assert_eq!(trussed::syscall!(client.sample_calls()).calls, 2);
        assert_eq!(trussed::syscall!(client.truncate(msg.clone())).s, trunc);
        assert_eq!(trussed::syscall!(client.sample_calls()).calls, 3);
    });
    run(runner::BACKENDS_SAMPLE2, |client| {
        assert_eq!(trussed::syscall!(client.sample_calls()).calls, 0);
        assert_eq!(trussed::syscall!(client.truncate(msg.clone())).s, trunc);
        assert_eq!(trussed::syscall!(client.sample_calls()).calls, 1);
    });
}

#[test]
fn mixed_extension() {
    use extensions::SampleClient as _;
    use extensions::TestClient as _;

    let msg = ShortData::from_slice(&[1, 2, 3, 4]).unwrap();
    let rev = ShortData::from_slice(&[4, 3, 2, 1]).unwrap();
    let trunc = ShortData::from_slice(&[1, 2, 3]).unwrap();
    run(runner::BACKENDS_MIXED, |client| {
        assert_eq!(trussed::syscall!(client.sample_calls()).calls, 0);
        assert_eq!(trussed::syscall!(client.test_calls()).calls, 0);
        assert_eq!(trussed::syscall!(client.reverse(msg.clone())).s, rev);
        assert_eq!(trussed::syscall!(client.truncate(msg.clone())).s, trunc);
        // the test backend is placed before the sample backend here,
        // and so it "catches" the reverse call, leading to single incrementations
        // of each call counter.
        assert_eq!(trussed::syscall!(client.sample_calls()).calls, 1);
        assert_eq!(trussed::syscall!(client.test_calls()).calls, 1);
        assert_eq!(trussed::syscall!(client.truncate(msg.clone())).s, trunc);
        assert_eq!(trussed::syscall!(client.sample_calls()).calls, 2);
    });
}
