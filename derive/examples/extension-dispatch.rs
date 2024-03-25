use trussed::Error;

mod backends {
    use super::extensions::{
        SampleExtension, SampleReply, SampleRequest, TestExtension, TestReply, TestRequest,
    };
    use trussed::{
        backend::Backend, platform::Platform, serde_extensions::ExtensionImpl,
        service::ServiceResources, types::CoreContext, Error,
    };

    #[derive(Default)]
    pub struct ABackend;

    impl Backend for ABackend {
        type Context = ();
    }

    impl ExtensionImpl<TestExtension> for ABackend {
        fn extension_request<P: Platform>(
            &mut self,
            _core_ctx: &mut CoreContext,
            _backend_ctx: &mut Self::Context,
            _request: &TestRequest,
            _resources: &mut ServiceResources<P>,
        ) -> Result<TestReply, Error> {
            Ok(TestReply)
        }
    }

    impl ExtensionImpl<SampleExtension> for ABackend {
        fn extension_request<P: Platform>(
            &mut self,
            _core_ctx: &mut CoreContext,
            _backend_ctx: &mut Self::Context,
            _request: &SampleRequest,
            _resources: &mut ServiceResources<P>,
        ) -> Result<SampleReply, Error> {
            Ok(SampleReply)
        }
    }

    #[derive(Default)]
    pub struct BBackend;

    impl Backend for BBackend {
        type Context = ();
    }
}

mod extensions {
    use serde::{Deserialize, Serialize};
    use trussed::{
        serde_extensions::{Extension, ExtensionClient, ExtensionResult},
        Error,
    };

    pub struct TestExtension;

    impl Extension for TestExtension {
        type Request = TestRequest;
        type Reply = TestReply;
    }

    #[derive(Deserialize, Serialize)]
    pub struct TestRequest;

    #[derive(Deserialize, Serialize)]
    pub struct TestReply;

    impl TryFrom<TestReply> for () {
        type Error = Error;

        fn try_from(_reply: TestReply) -> Result<Self, Self::Error> {
            Ok(())
        }
    }

    pub trait TestClient {
        fn test(&mut self) -> ExtensionResult<'_, TestExtension, (), Self>;
    }

    impl<C: ExtensionClient<TestExtension>> TestClient for C {
        fn test(&mut self) -> ExtensionResult<'_, TestExtension, (), Self> {
            self.extension(TestRequest)
        }
    }

    pub struct SampleExtension;

    impl Extension for SampleExtension {
        type Request = SampleRequest;
        type Reply = SampleReply;
    }

    #[derive(Deserialize, Serialize)]
    pub struct SampleRequest;

    #[derive(Deserialize, Serialize)]
    pub struct SampleReply;
}

enum Backend {
    A,
    ASample,
    B,
}

#[derive(trussed_derive::ExtensionId)]
enum Extension {
    Test = 0,
    Sample = 1,
}

#[derive(Default, trussed_derive::ExtensionDispatch)]
#[dispatch(backend_id = "Backend", extension_id = "Extension")]
#[extensions(
    Test = "extensions::TestExtension",
    Sample = "extensions::SampleExtension"
)]
struct Dispatch {
    #[extensions("Test")]
    a: backends::ABackend,

    #[dispatch(delegate_to = "a")]
    #[extensions("Sample")]
    a_sample: (),

    b: backends::BBackend,
}

fn main() {
    use extensions::TestClient;
    use trussed::{
        backend::BackendId,
        try_syscall,
        virt::{self, Ram},
    };

    fn run(backends: &'static [BackendId<Backend>], expected: Option<Error>) {
        virt::with_platform(Ram::default(), |platform| {
            platform.run_client_with_backends(
                "test",
                Dispatch::default(),
                backends,
                |mut client| {
                    assert_eq!(try_syscall!(client.test()).err(), expected);
                },
            )
        });
    }

    run(&[BackendId::Core], Some(Error::RequestNotAvailable));
    run(
        &[BackendId::Custom(Backend::B)],
        Some(Error::RequestNotAvailable),
    );
    run(
        &[BackendId::Custom(Backend::ASample)],
        Some(Error::RequestNotAvailable),
    );
    run(&[BackendId::Custom(Backend::A)], None);
}
