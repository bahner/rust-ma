# ma-did

A Rust library for DID- and message-oriented identity primitives used by the ma actor stack.

## What It Provides

- DID parsing/validation (`did:ma:*`) with root and fragment handling
- DID document model (`Document`, `VerificationMethod`, `Proof`)
- Opaque `ma` extension namespace on documents (`Option<serde_json::Value>`)
- Signing/encryption key helpers (`SigningKey`, `EncryptionKey`) using Ed25519 and X25519
- Multiformat encoding pipeline (multibase + multicodec) for public keys and signatures
- Message and envelope primitives with replay protection (`Message`, `Envelope`, `ReplayGuard`)
- Proof type: `MultiformatSignature2023` (BLAKE3 + Ed25519 over CBOR-serialized documents)
- Serialization:
  - `Document::marshal()` / `Document::unmarshal()` for JSON
  - `Document::to_cbor()` / `Document::from_cbor()` for CBOR

## Project Layout

- `src/constants.rs`: method name, version, BLAKE3 labels
- `src/did.rs`: DID model and validation
- `src/doc.rs`: DID document, proof, and verification method model
- `src/error.rs`: crate error types
- `src/identity.rs`: key+document generation helper
- `src/key.rs`: key generation, multibase encoding, Ed25519/X25519 key types
- `src/lib.rs`: public exports
- `src/msg.rs`: message, headers, envelope, and replay guard
- `src/multiformat.rs`: multibase/multicodec encoding and decoding pipeline

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
ma-did = "0.1"
```

Local path dependency during development:

```toml
[dependencies]
ma-did = { path = "../did" }
```

Example — identity and document:

1. Create a root DID and method DIDs.
2. Generate signing/encryption keys.
3. Build a `Document` and add verification methods.
4. Sign document proof.
5. Marshal/unmarshal via crate APIs.

Example — messages:

1. Create a `Message` with sender DID, recipient DID, content type, and content bytes.
2. The message is signed automatically on creation using the sender's `SigningKey`.
3. Verify a received message with `message.verify_with_document(&sender_document)`.
4. Wrap in an `Envelope` for encrypted transport (X25519 + XChaCha20-Poly1305).

## Notes

- This is a library crate; consumer crates compile it transitively.
- Direct document formatting should remain inside `ma-did` APIs.
- See [ma-spec](https://github.com/bahner/ma-spec) for the formal DID method specification intended for W3C registration.
