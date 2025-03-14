# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added `init_raw` constructor for types generated by the `store!` macro.
- Added `FilesystemClient::entry_metadata` syscall.
- Added `FilesystemClient::rename` syscall.
- Added serializable flag to `StorageAttributes` for key agreement.
- Added virtual platform in `virt` module.
- Added methods for creating the client stores to `ServiceResources`.
- Implemented `unsafe_inject_key` for Aes256Cbc, Ed255, X255, P256.
- Added support for custom backends in `backend` module.
- Added optional support for API extensions in `serde_extensions` module
  behind the `serde-extensions` feature.
- Added `types::Path` re-export of `littlefs2::path::Path`.
- Reduced stack usage of `Service::process`.

### Changed

- Made `StorageAttributes` non-exhaustive.
- Changed `KeyStore<P: Platform>` to `KeyStore<S: Store>`.
- Replaced the client ID with a `ClientContext` struct.
- Always trigger syscall in `PollClient::request` and remove
  `PollClient::syscall`.
- Upgrade the `interchange` dependency to version 0.3.0 ([#99][])
  - As a consequence the type `pipe::TrussedInterchange` becomes a const`pipe::TRUSSED_INTERCHANGE`
- Updated `littlefs2` to 0.6.0.
- Made `Request`, `Reply`, `Error`, `Context`, `CoreContext`, `Mechanism`,
  `KeySerialization`, `SignatureSerialization`, `consent::Error`, `ui::Status` non-exhaustive.
- Made `postcard_deserialize`, `postcard_serialize` and
  `postcard_serialize_bytes` private.
- Changed `&PathBuf` to `&Path` where possible.
- Change store implementations to use littlefs2’s `DynFilesystem` trait instead
  of being generic over the storage implementation.
- Add `nonce` argument to `wrap_key` and `unwrap_key` syscalls.
- Use nonce as IV for Aes256Cbc mechanism.
- Updated `cbor-smol` to 0.5.0.
- Removed `serde::{Deserialize, Serialize}` implementations for the API request
  and reply structs, `types::{consent::{Error, Level}, reboot::To, StorageAttributes,
  KeySerialization, SignatureSerialization}`.
- Improved hex formatting of `types::Id`:
  - Removed the unused `Id::hex`.
  - Deprecated `Id::hex_path` and added `Id::legacy_hex_path` as a replacement.
  - Added `Id::clean_hex_path` as an alternative to `Id::legacy_hex_path`.
  - Changed `Id::hex_clean` to format zero as `"00"`.
- Change client and mechanism selection:
  - Put all client traits, requests, replies and implementations behind feature flags.
  - Put all mechanisms behind feature flags.
  - Move `CryptoClient::attest` into new `AttestationClient`.
- Pass endpoints to `Service::process` instead of storing them in the service.
- Added support for non-static channels:
  - Added lifetimes to `ClientImplementation` and `ServiceEndpoints`.
  - Added the `pipe::TrussedChannel` type.
- Refactored the `Store` trait:
  - Removed the requirement for a static lifetime.
  - Removed the `Fs` wrapper type.
  - Removed the storage types to return `&dyn DynFilesystem` instead.
  - Removed the `Copy` requirement.
  - Removed the `unsafe` keyword for the `Store` trait.
- Removed the `unsafe` keyword for the `Platform` trait.
- Replaced the mechanism RPC traits in `service` with a single `MechanismImpl` trait.
- Made the `mechanisms` module private.  Mechanism implementation can still be accessed via the `Mechanism` enum.

### Fixed

- Fixed off-by-one error in `RandomBytes` request.
- Fixed a race condition when iterating over the filesystem in more than one
  client ([#64]).
- Fixed missing path validation in `Filestore` that allowed clients to escape
  their namespace ([#65]).
- wrap_key: Don't replace associated data with an empty array

### Removed

- Removed unused items:
  - `config`: `MAX_APPLICATION_NAME_LENGTH`, `MAX_LABEL_LENGTH`, `MAX_LONG_DATA_LENGTH`, `MAX_OBJECT_HANDLES`, `MAX_PATH_LENGTH`
  - `types`: `Attributes`, `CertificateType` `DataAttributes`, `KeyAttributes`, `Letters`, `LongData`, `ObjectType`, `consent::Urgency`
- Removed the `Syscall` implementations for `Service` and the `Syscall::try_as_new_client` and `Syscall::try_new_client` methods.
- Removed `TrussedInterchange` and `TRUSSED_INTERCHANGE` from `pipe`.
- Removed the `clients-?` features.
- Removed the `store!` macro.  Embedded runners should provide their own implementation.  Software runners can use `virt::StoreConfig` to create a `virt::Store`.

[#64]: https://github.com/trussed-dev/trussed/issues/64
[#65]: https://github.com/trussed-dev/trussed/issues/65
[#99]: https://github.com/trussed-dev/trussed/issues/99

## [0.1.0] - 2022-01-26

Initial release.

[Unreleased]: https://github.com/trussed-dev/trussed/compare/0.1.0...HEAD
[0.1.0]: https://github.com/trussed-dev/trussed/releases/tag/v0.1.0
