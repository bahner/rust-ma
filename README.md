# ma-did

A Rust implementation of the [間 (`did:ma`) DID method](https://github.com/bahner/ma-spec) — a modern, lean decentralized identifier method providing secure identities as a foundation for secure messaging.

## What It Provides

- **DID parsing and validation** — `did:ma:<ipns>` with optional `#fragment` for sub-identities within a namespace
- **DID documents** — `Document`, `VerificationMethod`, and `Proof` types conforming to [W3C DID v1.1](https://www.w3.org/TR/did-1.1/)
- **Cryptographic key types** — Ed25519 signing keys (`SigningKey`) and X25519 encryption keys (`EncryptionKey`) with `Multikey` encoding
- **Multiformat pipeline** — multibase (Base58btc) + multicodec encoding/decoding for public keys and signatures
- **Identity generation** — one-call `generate_identity()` produces keys, verification methods, and a signed document
- **Document proofs** — `MultiformatSignature2023` proof type (BLAKE3 + Ed25519 over CBOR)
- **Signed messages** — `Message` with BLAKE3 content hashing, Ed25519 signature, TTL, and replay-window freshness checks
- **Encrypted envelopes** — `Envelope` using ephemeral X25519 key agreement + XChaCha20-Poly1305 AEAD
- **Serialization** — JSON (`marshal`/`unmarshal`) and CBOR (`to_cbor`/`from_cbor`) for both documents and messages
- **Method-specific extension** — optional `ma` namespace on documents for application-defined fields
- **WASM support** — compiles to `wasm32-unknown-unknown` with JS time sources

## Specification

This crate implements the formal `did:ma` method specification documents at [bahner/ma-spec](https://github.com/bahner/ma-spec):

- [DID Method Specification](https://github.com/bahner/ma-spec/blob/main/did-method-spec.md) — method syntax, CRUD operations, verifiable data registry
- [DID Document Format](https://github.com/bahner/ma-spec/blob/main/did-document-format.md) — document structure, `Multikey` verification methods, proof type
- [Extension Fields Format](https://github.com/bahner/ma-spec/blob/main/did-ma-fields-format.md) — method-specific `ma` namespace
- [Messaging Format](https://github.com/bahner/ma-spec/blob/main/messaging-format.md) — signed CBOR messages, encryption envelopes, replay protection

## Project Layout

- `src/constants.rs`: method name, version, BLAKE3 labels
- `src/did.rs`: DID model and validation
- `src/doc.rs`: DID document, proof, and verification method model
- `src/error.rs`: crate error types
- `src/identity.rs`: key + document generation helper
- `src/key.rs`: key generation, multibase encoding, Ed25519/X25519 key types
- `src/lib.rs`: public exports
- `src/msg.rs`: message, headers, envelope, and replay guard
- `src/multiformat.rs`: multibase/multicodec encoding and decoding pipeline

## Build

```bash
cargo build
cargo test
```

## Usage

```toml
[dependencies]
ma-did = { path = "../did" }
```

### Identity and documents

1. Generate signing and encryption keys.
2. Build a `Document` with verification methods.
3. Sign the document proof.
4. Marshal/unmarshal via JSON or CBOR.

### Messages

1. Create a `Message` with sender DID, recipient DID, content type, and content bytes.
2. The message is signed automatically on creation using the sender's `SigningKey`.
3. Verify a received message with `message.verify_with_document(&sender_document)`.
4. Wrap in an `Envelope` for encrypted transport (X25519 + XChaCha20-Poly1305).

## License

GPL-3.0-only
