//! Trussed platform implemented in software with RAM storage **FOR TESTING ONLY**
//!
//! The random number generator in this module uses a
//! constant seed for test reproducability and by consequence is **not secure**

mod store;
mod ui;

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng as _;

use crate::{
    backend::{BackendId, CoreOnly, Dispatch},
    client::ClientBuilder,
    platform::{self, Syscall},
    service::Service,
    ClientImplementation,
};

pub use store::{Filesystem, Ram, StoreProvider};
pub use ui::UserInterface;

pub type Client<S, D = CoreOnly> = ClientImplementation<Service<Platform<S>, D>, D>;
/// Virtual client that can coexist with other clients
pub type MultiClient<S, D = CoreOnly> =
    ClientImplementation<Arc<Mutex<Service<Platform<S>, D>>>, D>;

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

pub fn with_clients<S, R, F, const N: usize>(store: S, client_ids: [&str; N], f: F) -> R
where
    S: StoreProvider,
    F: FnOnce([MultiClient<S>; N]) -> R,
{
    with_platform(store, |platform| platform.run_clients(client_ids, f))
}

pub fn with_fs_clients<P, R, F, const N: usize>(internal: P, client_ids: [&str; N], f: F) -> R
where
    P: Into<PathBuf>,
    F: FnOnce([MultiClient<Filesystem>; N]) -> R,
{
    with_clients(Filesystem::new(internal), client_ids, f)
}

/// Run a function with multiple clients using the RAM for the filesystem.
///
///
/// Const generics are used to allow easy deconstruction in the callback arguments
///
/// ```rust
///# use trussed::client::{Ed255, CryptoClient};
///# use trussed::types::{Location, Mechanism};
///# use trussed::syscall;
///# use trussed::virt::with_ram_clients;
/// with_ram_clients(["client1", "client2"], |[mut client1, mut client2]| {
///     let key = syscall!(client1.generate_ed255_private_key(Location::Internal)).key;
///     // The clients are distinct
///     assert!(!syscall!(client2.exists(Mechanism::Ed255, key)).exists);
/// })    
/// ```
pub fn with_ram_clients<R, F, const N: usize>(client_ids: [&str; N], f: F) -> R
where
    F: FnOnce([MultiClient<Ram>; N]) -> R,
{
    with_clients(Ram::default(), client_ids, f)
}

pub struct Platform<S: StoreProvider> {
    rng: ChaCha8Rng,
    _store: S,
    ui: UserInterface,
}

impl<S: Syscall> Syscall for Arc<Mutex<S>> {
    fn syscall(&mut self) {
        self.lock().unwrap().syscall()
    }
}

impl<S: StoreProvider> Platform<S> {
    pub fn run_client<R>(self, client_id: &str, test: impl FnOnce(Client<S>) -> R) -> R {
        let service = Service::new(self);
        let client = service.try_into_new_client(client_id, None).unwrap();
        test(client)
    }

    pub fn run_client_with_backends<R, D: Dispatch>(
        self,
        client_id: &str,
        dispatch: D,
        backends: &'static [BackendId<D::BackendId>],
        test: impl FnOnce(Client<S, D>) -> R,
    ) -> R {
        let mut service = Service::with_dispatch(self, dispatch);
        let client = ClientBuilder::new(client_id)
            .backends(backends)
            .prepare(&mut service)
            .unwrap()
            .build(service);
        test(client)
    }

    pub fn run_clients<R, const N: usize>(
        self,
        client_ids: [&str; N],
        test: impl FnOnce([MultiClient<S>; N]) -> R,
    ) -> R {
        let mut service = Service::new(self);
        let prepared_clients =
            client_ids.map(|id| ClientBuilder::new(id).prepare(&mut service).unwrap());
        let service = Arc::new(Mutex::new(service));
        test(prepared_clients.map(|builder| builder.build(service.clone())))
    }

    /// Using const generics rather than a `Vec` to allow destructuring in the method
    pub fn run_clients_with_backends<R, D: Dispatch, const N: usize>(
        self,
        client_ids: [(&str, &'static [BackendId<D::BackendId>]); N],
        dispatch: D,
        test: impl FnOnce([MultiClient<S, D>; N]) -> R,
    ) -> R {
        let mut service = Service::with_dispatch(self, dispatch);
        let prepared_clients = client_ids.map(|(id, backends)| {
            ClientBuilder::new(id)
                .backends(backends)
                .prepare(&mut service)
                .unwrap()
        });
        let service = Arc::new(Mutex::new(service));
        test(prepared_clients.map(|builder| builder.build(service.clone())))
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
