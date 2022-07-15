mod store;
mod ui;

use std::{path::PathBuf, sync::Mutex};

use chacha20::ChaCha8Rng;
use once_cell::sync::Lazy;
use rand_core::SeedableRng as _;

use crate::{
    api::{Reply, Request},
    client::mechanisms::{Ed255 as _, P256 as _},
    pipe::TrussedInterchange,
    platform,
    service::Service,
    syscall,
    types::{ClientContext, Location, ServiceBackends},
    ClientImplementation, Error, Interchange as _,
};

pub use store::{Filesystem, Ram, StoreProvider};
pub use ui::UserInterface;

pub type Client<S> = ClientImplementation<Service<Platform<S>>>;

const CLIENT_ID_ATTN: &str = "attn";

// We need this mutex to make sure that:
// - TrussedInterchange is not used concurrently
// - the Store is not used concurrently
static MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

pub fn with_platform<S, R, F>(store: S, f: F) -> R
where
    S: StoreProvider,
    F: FnOnce(Platform<S>) -> R,
{
    let _guard = MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    // causing a regression again
    // let rng = chacha20::ChaCha8Rng::from_rng(rand_core::OsRng).unwrap();
    let platform = Platform {
        rng: ChaCha8Rng::from_seed([42u8; 32]),
        store,
        ui: UserInterface::new(),
    };
    f(platform)
}

pub fn with_client<S, R, F>(store: S, client_id: &str, f: F) -> R
where
    S: StoreProvider,
    F: FnOnce(Client<S>) -> R,
{
    with_platform(store, |platform| platform.run_client(client_id, f))
}

pub fn with_fs_client<P, R, F>(internal: P, client_id: &str, f: F) -> R
where
    P: Into<PathBuf>,
    F: FnOnce(Client<Filesystem>) -> R,
{
    with_client(Filesystem::new(internal), client_id, f)
}

pub fn with_ram_client<R, F>(client_id: &str, f: F) -> R
where
    F: FnOnce(Client<Ram>) -> R,
{
    with_client(Ram::default(), client_id, f)
}

pub struct Platform<S: StoreProvider> {
    rng: ChaCha8Rng,
    store: S,
    ui: UserInterface,
}

impl<S: StoreProvider> Platform<S> {
    pub fn run_client<R>(
        self,
        client_id: &str,
        test: impl FnOnce(ClientImplementation<Service<Self>>) -> R,
    ) -> R {
        let service = Service::from(self);
        let client = service.try_into_new_client(client_id).unwrap();
        test(client)
    }
}

impl<S: StoreProvider> From<Platform<S>> for Service<Platform<S>> {
    fn from(platform: Platform<S>) -> Self {
        // reset platform
        unsafe {
            TrussedInterchange::reset_claims();
        }
        unsafe {
            platform.store.reset();
        }

        let mut service = Service::new(platform);

        // preparations for attestation
        let mut attn_client = service.try_as_new_client(CLIENT_ID_ATTN).unwrap();
        syscall!(attn_client.generate_ed255_private_key(Location::Internal));
        syscall!(attn_client.generate_p256_private_key(Location::Internal));

        // destroy this attestation client
        unsafe {
            TrussedInterchange::reset_claims();
        }

        service
    }
}

unsafe impl<S: StoreProvider> platform::Platform for Platform<S> {
    type R = ChaCha8Rng;
    type S = S::Store;
    type UI = UserInterface;

    fn user_interface(&mut self) -> &mut Self::UI {
        &mut self.ui
    }

    fn rng(&mut self) -> &mut Self::R {
        &mut self.rng
    }

    fn store(&self) -> Self::S {
        unsafe { self.store.store() }
    }

    fn platform_reply_to(
        &mut self,
        _backend_id: ServiceBackends,
        _client_id: &mut ClientContext,
        _request: &Request,
    ) -> Result<Reply, Error> {
        Err(Error::RequestNotAvailable)
    }
}
