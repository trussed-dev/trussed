mod ui;
mod store;

use std::sync::Mutex;

use chacha20::ChaCha8Rng;
use once_cell::sync::Lazy;
use rand_core::SeedableRng as _;

use crate::{
    client::mechanisms::{Ed255 as _, P256 as _},
    pipe::TrussedInterchange,
    service::Service,
    store::Store,
    types::Location,
    ClientImplementation,
    Interchange as _,
    platform,
    syscall,
};

pub use ui::UserInterface;
pub use store::{RamStore, Reset};

const CLIENT_ID_ATTN: &str = "attn";

// We need this mutex to make sure that:
// - TrussedInterchange is not used concurrently
// - the Store is not used concurrently
static MUTEX: Lazy<Mutex<()>> = Lazy::new(|| {
    Mutex::new(())
});

pub fn with_platform<S: Store + Reset, R>(store: S, f: impl FnOnce(Platform<S>) -> R) -> R {
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
    S: Store + Reset,
    F: FnOnce(ClientImplementation<Service<Platform<S>>>) -> R,
{
    with_platform(store, |platform| platform.run_client(client_id, f))
}

pub fn with_ram_client<R, F>(client_id: &str, f: F) -> R
where
    F: FnOnce(ClientImplementation<Service<Platform<RamStore>>>) -> R,
{
    with_client(RamStore::default(), client_id, f)
}

pub struct Platform<S: Store> {
    rng: ChaCha8Rng,
    store: S,
    ui: UserInterface,
}

impl<S: Store + Reset> Platform<S> {
    pub fn run_client<R>(
        self,
        client_id: &str,
        test: impl FnOnce(ClientImplementation<Service<Self>>) -> R
    ) -> R {
        let service = Service::from(self);
        let client = service.try_into_new_client(client_id).unwrap();
        test(client)
    }
}

impl<S: Store + Reset> From<Platform<S>> for Service<Platform<S>> {
    fn from(platform: Platform<S>) -> Self {
        // reset platform
        unsafe { TrussedInterchange::reset_claims(); }
        platform.store.reset();

        let mut service = Service::new(platform);

        // preparations for attestation
        let mut attn_client = service.try_as_new_client(CLIENT_ID_ATTN).unwrap();
        syscall!(attn_client.generate_ed255_private_key(Location::Internal));
        syscall!(attn_client.generate_p256_private_key(Location::Internal));

        // destroy this attestation client
        unsafe { TrussedInterchange::reset_claims(); }
        
        service
    }
}

unsafe impl<S: Store> platform::Platform for Platform<S> {
    type R = ChaCha8Rng;
    type S = S;
    type UI = UserInterface;

    fn user_interface(&mut self) -> &mut Self::UI {
        &mut self.ui
    }

    fn rng(&mut self) -> &mut Self::R {
        &mut self.rng
    }

    fn store(&self) -> Self::S {
        self.store
    }
}
