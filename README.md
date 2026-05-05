# ma-did

A Rust implementation of the
[間 (`did:ma`) DID method](https://github.com/bahner/ma-spec)
— a modern, lean decentralized identifier method providing
secure identities as a foundation for secure messaging.

## What It Provides

- **DID parsing and validation** —
  `did:ma:<ipns>` with optional `#fragment`
  for sub-identities within a namespace
- **DID documents** —
  `Document`, `VerificationMethod`, and `Proof` types
  conforming to [W3C DID v1.1](https://www.w3.org/TR/did-1.1/)
- **Cryptographic key types** —
  Ed25519 signing keys (`SigningKey`) and
  X25519 encryption keys (`EncryptionKey`)
  with `Multikey` encoding
- **Multiformat pipeline** —
  multibase (Base58btc) + multicodec encoding/decoding
  for public keys and signatures
- **Identity generation** —
  one-call `generate_identity()` or
  `generate_identity_from_secret()` produces keys,
  verification methods, and a signed document
- **Document proofs** —
  `MultiformatSignature2023` proof type
  (BLAKE3 + Ed25519 over CBOR)
- **Signed messages** —
  `Message` with BLAKE3 content hashing,
  Ed25519 signature, TTL,
  and replay-window freshness checks
- **Encrypted envelopes** —
  `Envelope` using ephemeral X25519 key agreement
  with XChaCha20-Poly1305 AEAD
- **Serialization** —
  JSON (`marshal`/`unmarshal`) and
  CBOR (`to_cbor`/`from_cbor`)
  for both documents and messages
- **Method-specific extension** —
  optional `ma` namespace on documents
  for application-defined fields
- **WASM support** —
  compiles to `wasm32-unknown-unknown`
  with JS time sources

## Specification

This crate implements the formal `did:ma` method
specification documents at
[bahner/ma-spec](https://github.com/bahner/ma-spec):

- [DID Method Specification][method-spec] —
  method syntax, CRUD operations, verifiable data registry
- [DID Document Format][doc-format] —
  document structure, `Multikey` verification methods,
  proof type
- [Extension Fields Format][fields-format] —
  method-specific `ma` namespace
- [Messaging Format][msg-format] —
  signed CBOR messages, encryption envelopes,
  replay protection

[method-spec]: https://github.com/bahner/ma-spec/blob/main/did-method-spec.md
[doc-format]: https://github.com/bahner/ma-spec/blob/main/did-document-format.md
[fields-format]: https://github.com/bahner/ma-spec/blob/main/did-ma-fields-format.md
[msg-format]: https://github.com/bahner/ma-spec/blob/main/messaging-format.md

## References

- [W3C DID Core v1.1](https://www.w3.org/TR/did-1.1/) —
  Decentralized Identifiers specification
- [Nano ID](https://github.com/ai/nanoid) —
  DID URL fragment generation and validation
  (`[A-Za-z0-9_-]+`)
- [Multibase][mb] / [Multicodec][mc] —
  key and signature encoding
- [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) —
  content hashing for proofs and messages
- [IPNS](https://docs.ipfs.tech/concepts/ipns/) —
  DID method-specific identifier

[mb]: https://github.com/multiformats/multibase
[mc]: https://github.com/multiformats/multicodec

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
ma-did = "0.5"
```

## Release Notes

### 0.5.0

- Improved API safety with `#[must_use]` on commonly dropped return values.
- Fixed message timestamp tests and aligned examples with current behavior.
- Internal multiformat encoding cleanup for clearer error boundaries.

### Migration Notes (0.4 -> 0.5)

- If your project uses `-D warnings`, new `#[must_use]` attributes may surface ignored-result warnings.
  Update call sites to use, store, or explicitly discard return values as needed.
- Public crate API remains source-compatible for normal `ma_did` usage.
  The `multiformat` module is internal (`mod multiformat`) and not exported from crate root.

### Identity and documents

```rust
use ma_did::{generate_identity_from_secret, Did};

// Generate a complete identity from an application-managed secret
let secret = [7u8; 32];
let identity = generate_identity_from_secret(secret).unwrap();

// The document is already signed and valid
identity.document.verify().unwrap();
identity.document.validate().unwrap();

// Serialize to JSON or CBOR
let json = identity.document.marshal().unwrap();
let cbor = identity.document.to_cbor().unwrap();
```

If you already have an IPNS identifier from elsewhere, you can still call
`generate_identity(ipns)` directly as the explicit lower-level path. If not,
let the application supply the secret and use
`generate_identity_from_secret(secret)` to derive it.

### DID validation

```rust
use ma_did::Did;

// Validate any DID (bare or URL)
Did::validate("did:ma:k51qzi5uqu5abc").unwrap();
Did::validate("did:ma:k51qzi5uqu5abc#lobby").unwrap();

// Validate specifically a bare DID identity (no fragment)
Did::validate_identity("did:ma:k51qzi5uqu5abc").unwrap();

// Validate specifically a DID URL (requires fragment)
Did::validate_url("did:ma:k51qzi5uqu5abc#lobby").unwrap();
```

### Messages

```rust
use ma_did::{generate_identity_from_secret, Message, SigningKey, Did};

let alice = generate_identity_from_secret([1u8; 32]).unwrap();
let bob = generate_identity_from_secret([2u8; 32]).unwrap();

// Reconstruct signing key from stored private key bytes
let alice_sign_url = Did::new_url(&alice.subject_url.ipns, None::<String>).unwrap();
let alice_signing_key = SigningKey::from_private_key_bytes(
    alice_sign_url,
    hex::decode(&alice.signing_private_key_hex).unwrap().try_into().unwrap(),
).unwrap();

// Create a signed message
let msg = Message::new(
    alice.document.id.clone(),
    bob.document.id.clone(),
    "text/plain",
    b"hello".to_vec(),
    &alice_signing_key,
).unwrap();

// Verify message signature against sender's document
msg.verify_with_document(&alice.document).unwrap();

// Encrypt for recipient as an Envelope
let envelope = msg.enclose_for(&bob.document).unwrap();
```

## License

GPL-3.0-only
