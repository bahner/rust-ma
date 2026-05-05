# Changelog

All notable changes to this project are documented in this file.

## 0.5.0 - 2026-05-03

### Changed

- Added `generate_identity_from_secret` and `ipns_from_secret` so applications can keep ownership of their Ed25519 secret while deriving the `did:ma` IPNS identifier inside the crate.
- Added `#[must_use]` on selected public functions and methods to reduce accidental ignored return values.
- Simplified DID parse arm matching in `Did::parse`.
- Switched internal clone assignment in message headers to `clone_from`.
- Refined internal multibase encode flow to avoid unnecessary wrapping.

### Fixed

- Fixed `f64` timestamp test assignments in message tests.
- Verified clean status with `cargo test` and `cargo clippy --all-targets --all-features`.

### Compatibility

- Crate root public API is source-compatible for typical consumers.
- `src/multiformat.rs` is internal and not exported from crate root, so direct external usage is not part of the semver contract.
- Downstream builds that treat warnings as errors may need to handle new `#[must_use]` warnings.
