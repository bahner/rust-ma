# did-ma

A Rust library for DID- and message-oriented identity primitives used by the ma actor stack.

## What It Provides

- DID parsing/validation (`did:ma:*`) with root and fragment handling
- DID document model (`Document`, `VerificationMethod`, `Proof`, `Host`, `Topic`)
- Signing/encryption key helpers (`SigningKey`, `EncryptionKey`)
- Envelope/message primitives with replay protection (`Message`, `Envelope`, `ReplayGuard`)
- Serialization helpers owned by the crate:
  - `Document::marshal()` / `Document::unmarshal()` for JSON
  - `Document::to_cbor()` / `Document::from_cbor()` for CBOR

## Project Layout

- `src/did.rs`: DID model and validation
- `src/doc.rs`: DID document + proof model
- `src/key.rs`: key generation and multibase handling
- `src/msg.rs`: envelope/message structures and replay guard
- `src/error.rs`: crate error types
- `src/lib.rs`: public exports

## Build and Cleanup

Use the Makefile:

```bash
make build
make clean
make distclean
```

Equivalent cargo commands:

```bash
cargo build
cargo test
```

## Usage (Library)

Add as dependency:

```toml
[dependencies]
did-ma = { path = "../rust-ma" }
```

Example flow:

1. Create a root DID and method DIDs.
2. Generate signing/encryption keys.
3. Build a `Document` and add verification methods.
4. Sign document proof.
5. Marshal/unmarshal via crate APIs.

## Notes

- This is a library crate; consumer crates compile it transitively.
- Direct document formatting should remain inside `did-ma` APIs.
