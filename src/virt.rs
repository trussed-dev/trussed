//! Trussed platform implemented in software with RAM storage **FOR TESTING ONLY**
//!
//! The random number generator in this module uses a
//! constant seed for test reproducability and by consequence is **not secure**

mod store;
mod ui;

use std::{path::PathBuf, sync::Mutex};

use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng as _;

use crate::{
    backend::{BackendId, CoreOnly, Dispatch},
    client::ClientBuilder,
    platform,
    service::Service,
    ClientImplementation,
};

pub use store::{Filesystem, Ram, StoreProvider};
pub use ui::UserInterface;

pub type Client<S, D = CoreOnly> = ClientImplementation<Service<Platform<S>, D>, D>;

// We need this mutex to make sure that:
// - TrussedInterchange is not used concurrently (panics if violated)
// - the Store is not used concurrently
static MUTEX: Mutex<()> = Mutex::new(());

pub fn with_platform<S, R, F>(store: S, f: F) -> R
where
    S: StoreProvider,
    F: FnOnce(Platform<S>) -> R,
{
    let _guard = MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    unsafe {
        store.reset();
    }
    // causing a regression again
    // let rng = chacha20::ChaCha8Rng::from_rng(rand_core::OsRng).unwrap();
    let platform = Platform {
        rng: ChaCha8Rng::from_seed([42u8; 32]),
        _store: store,
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
    _store: S,
    ui: UserInterface,
}

impl<S: StoreProvider> Platform<S> {
    pub fn run_client<R>(
        self,
        client_id: &str,
        test: impl FnOnce(ClientImplementation<Service<Self>>) -> R,
    ) -> R {
        let service = Service::new(self);
        let client = service.try_into_new_client(client_id).unwrap();
        test(client)
    }

    pub fn run_client_with_backends<R, D: Dispatch>(
        self,
        client_id: &str,
        dispatch: D,
        backends: &'static [BackendId<D::BackendId>],
        test: impl FnOnce(ClientImplementation<Service<Self, D>, D>) -> R,
    ) -> R {
        let mut service = Service::with_dispatch(self, dispatch);
        let client = ClientBuilder::new(client_id)
            .backends(backends)
            .prepare(&mut service)
            .unwrap()
            .build(service);
        test(client)
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
        unsafe { S::store() }
    }
}
