pub fn get<R>(
        test: impl FnOnce(&mut trussed::ClientImplementation<trussed::service::Service<trussed::virt::Platform<trussed::virt::RamStore>>>) -> R
    )
        -> R
{
    trussed::virt::with_ram_client("test", |mut client| test(&mut client))
}
