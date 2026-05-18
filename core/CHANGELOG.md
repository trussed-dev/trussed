# Changelog

## Unreleased

### Added

- Add `UiClient::confirm_user_present_with_level`.
- Add `Mechanism::Mldsa44` and the `Mldsa44` trait behind the `mldsa44` feature flag and bump `MAX_MESSAGE_LENGTH` and `MAX_SIGNATURE_LENGTH` if `mldsa44` is enabled.

## [v0.2.0](https://github.com/trussed-dev/trussed/releases/tag/core-v0.2.0) (2025-03-20)

### Changed

- Deprecate `FilesystemClient::debug_dump_store`.  Instead, a debugger should be used to extract the filesystem from a development device.
- Update to `heapless-bytes` v0.5.

## [v0.1.0](https://github.com/trussed-dev/trussed/releases/tag/core-v0.1.0) (2025-01-08)

Initial release extracting the core types from `trussed`: the client traits,
the API definition and the types used in the API.
