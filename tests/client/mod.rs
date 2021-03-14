trussed::platform!(Platform,
    R: chacha20::ChaCha8Rng,
    S: store::Store,
    UI: ui::UserInterface,
);

pub fn get<R>(
        test: impl FnOnce(&mut trussed::ClientImplementation<&mut trussed::service::Service<Platform>>) -> R
    )
        -> R
{
    use trussed::Interchange as _;
    unsafe { trussed::pipe::TrussedInterchange::reset_claims(); }
    let trussed_platform = init_platform();
    let mut trussed_service = trussed::service::Service::new(trussed_platform);

    // preparations for attestation
    let client_id = "attn";
    let mut attn_client = trussed_service.try_as_new_client(client_id).unwrap();

    use trussed::client::mechanisms::Ed255;
    let attn_ed255_key = trussed::syscall!(attn_client.generate_ed255_private_key(trussed::types::Location::Internal)).key;
    use trussed::client::mechanisms::P256;
    let attn_p256_key = trussed::syscall!(attn_client.generate_p256_private_key(trussed::types::Location::Internal)).key;

    // destroy this attestation client
    unsafe { trussed::pipe::TrussedInterchange::reset_claims(); }

    let client_id = "test";
    let mut trussed_client = trussed_service.try_as_new_client(client_id).unwrap();
    test(&mut trussed_client)
}

pub fn init_platform() -> Platform {
    use rand_core::SeedableRng as _;
    // causing a regression again
    // let rng = chacha20::ChaCha8Rng::from_rng(rand_core::OsRng).unwrap();
    let rng = chacha20::ChaCha8Rng::from_seed([42u8; 32]);
    let store = store::Store::format(
        store::InternalStorage::new(),
        store::ExternalStorage::new(),
        store::VolatileStorage::new(),
        );
    let ui = ui::UserInterface::new();

    let platform = Platform::new(rng, store, ui);

    platform
}

pub mod ui {
    use trussed::platform::{consent, reboot, ui};
    pub struct UserInterface { start_time: std::time::Instant }

    impl UserInterface { pub fn new() -> Self { Self { start_time: std::time::Instant::now() } } }

    impl trussed::platform::UserInterface for UserInterface {
        fn check_user_presence(&mut self) -> consent::Level { consent::Level::Normal }
        fn set_status(&mut self, _status: ui::Status) {}
        fn refresh(&mut self) {}
        fn uptime(&mut self) -> core::time::Duration { self.start_time.elapsed() }
        fn reboot(&mut self, _to: reboot::To) -> ! { loop { continue; } }
    }
}

pub mod store {
    pub use generic_array::typenum::consts;
    use littlefs2::const_ram_storage;
    use trussed::types::{LfsResult, LfsStorage};

    const_ram_storage!(InternalStorage, 16384);
    const_ram_storage!(ExternalStorage, 16384);
    const_ram_storage!(VolatileStorage, 16384);

    trussed::store!(Store,
        Internal: InternalStorage,
        External: ExternalStorage,
        Volatile: VolatileStorage
    );
}
