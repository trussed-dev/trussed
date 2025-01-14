//! Trussed platform implemented in software with RAM storage **FOR TESTING ONLY**
//!
//! The random number generator in this module uses a
//! constant seed for test reproducability and by consequence is **not secure**

mod store;
mod ui;

use std::{
    iter,
    path::PathBuf,
    sync::{
        mpsc::{self, Receiver, Sender},
        Mutex,
    },
    thread,
};

use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng as _;

use crate::{
    backend::{BackendId, CoreOnly, Dispatch},
    pipe::{ServiceEndpoint, TrussedChannel, TrussedResponder},
    platform,
    service::Service,
    types::CoreContext,
    ClientImplementation,
};

pub use store::{Filesystem, Ram, StoreProvider};
pub use ui::UserInterface;

pub type Client<'a, D = CoreOnly> = ClientImplementation<'a, Syscall, D>;

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
    F: FnOnce(Client) -> R,
{
    with_platform(store, |platform| platform.run_client(client_id, f))
}

pub fn with_fs_client<P, R, F>(internal: P, client_id: &str, f: F) -> R
where
    P: Into<PathBuf>,
    F: FnOnce(Client) -> R,
{
    with_client(Filesystem::new(internal), client_id, f)
}

pub fn with_ram_client<R, F>(client_id: &str, f: F) -> R
where
    F: FnOnce(Client) -> R,
{
    with_client(Ram::default(), client_id, f)
}

pub fn with_clients<S, R, F, const N: usize>(store: S, client_ids: [&str; N], f: F) -> R
where
    S: StoreProvider,
    F: FnOnce([Client; N]) -> R,
{
    with_platform(store, |platform| platform.run_clients(client_ids, f))
}

pub fn with_fs_clients<P, R, F, const N: usize>(internal: P, client_ids: [&str; N], f: F) -> R
where
    P: Into<PathBuf>,
    F: FnOnce([Client; N]) -> R,
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
    F: FnOnce([Client; N]) -> R,
{
    with_clients(Ram::default(), client_ids, f)
}

pub struct Syscall(Sender<()>);

impl platform::Syscall for Syscall {
    fn syscall(&mut self) {
        self.0.send(()).unwrap();
    }
}

struct Runner<'a, I: 'static, C> {
    syscall_tx: Sender<()>,
    syscall_rx: Receiver<()>,
    eps: Vec<ServiceEndpoint<'a, I, C>>,
}

impl<'a, I: 'static, C: Default> Runner<'a, I, C> {
    fn new() -> Self {
        let (syscall_tx, syscall_rx) = mpsc::channel();
        Self {
            syscall_tx,
            syscall_rx,
            eps: Vec::new(),
        }
    }

    fn syscall(&self) -> Syscall {
        Syscall(self.syscall_tx.clone())
    }

    fn add_endpoint(
        &mut self,
        responder: TrussedResponder<'a>,
        client_id: &str,
        backends: &'static [BackendId<I>],
    ) {
        let context = CoreContext::new(client_id.try_into().unwrap());
        self.eps
            .push(ServiceEndpoint::new(responder, context, backends));
    }

    fn run<P, D, F, R>(self, platform: P, dispatch: D, f: F) -> R
    where
        P: platform::Platform,
        D: Dispatch<Context = C, BackendId = I>,
        C: Send + Sync,
        I: Send + Sync,
        F: FnOnce() -> R,
    {
        let (stop_tx, stop_rx) = mpsc::channel();
        let mut service = Service::with_dispatch(platform, dispatch);
        thread::scope(|s| {
            s.spawn(move || {
                let mut eps = self.eps;
                while stop_rx.try_recv().is_err() {
                    if self.syscall_rx.try_recv().is_ok() {
                        service.process(&mut eps);
                    }
                }
            });
            let result = f();
            stop_tx.send(()).unwrap();
            result
        })
    }
}

pub struct Platform<S: StoreProvider> {
    rng: ChaCha8Rng,
    _store: S,
    ui: UserInterface,
}

impl<S: StoreProvider> Platform<S> {
    pub fn run_client<R>(self, client_id: &str, test: impl FnOnce(Client) -> R) -> R {
        self.run_client_with_backends(client_id, CoreOnly, &[], test)
    }

    pub fn run_client_with_backends<R, D: Dispatch>(
        self,
        client_id: &str,
        dispatch: D,
        backends: &'static [BackendId<D::BackendId>],
        test: impl FnOnce(Client<'_, D>) -> R,
    ) -> R
    where
        D::Context: Send + Sync,
        D::BackendId: Send + Sync,
    {
        let channel = TrussedChannel::new();
        let mut runner = Runner::new();
        let (requester, responder) = channel.split().unwrap();
        runner.add_endpoint(responder, client_id, backends);
        let client = Client::new(requester, runner.syscall(), None);
        runner.run(self, dispatch, || test(client))
    }

    pub fn run_clients<R, const N: usize>(
        self,
        client_ids: [&str; N],
        test: impl FnOnce([Client; N]) -> R,
    ) -> R {
        let channels = [const { TrussedChannel::new() }; N];
        let mut runner = Runner::new();
        let clients: Vec<_> = iter::zip(client_ids, &channels)
            .map(|(id, channel)| {
                let (requester, responder) = channel.split().unwrap();
                runner.add_endpoint(responder, id, &[]);
                Client::new(requester, runner.syscall(), None)
            })
            .collect();
        runner.run(self, CoreOnly, || test(clients.try_into().ok().unwrap()))
    }

    /// Using const generics rather than a `Vec` to allow destructuring in the method
    pub fn run_clients_with_backends<R, D: Dispatch, const N: usize>(
        self,
        client_ids: [(&str, &'static [BackendId<D::BackendId>]); N],
        dispatch: D,
        test: impl FnOnce([Client<'_, D>; N]) -> R,
    ) -> R
    where
        D::Context: Send + Sync,
        D::BackendId: Send + Sync,
    {
        let channels = [const { TrussedChannel::new() }; N];
        let mut runner = Runner::new();
        let clients: Vec<_> = iter::zip(client_ids, &channels)
            .map(|((id, backends), channel)| {
                let (requester, responder) = channel.split().unwrap();
                runner.add_endpoint(responder, id, backends);
                Client::new(requester, runner.syscall(), None)
            })
            .collect();
        runner.run(self, dispatch, || test(clients.try_into().ok().unwrap()))
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
