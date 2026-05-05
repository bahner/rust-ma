#![forbid(unsafe_code)]
//! # ma-did
//!
//! DID and message primitives for the `did:ma:` method.
//!
//! This crate provides everything needed to create, sign, and verify DID
//! documents and encrypted actor-to-actor messages.
//!
//! ## Quick Start — Identity
//!
//! ```rust
//! use ma_did::{generate_identity_from_secret, Did};
//!
//! // Generate a complete identity from an application-managed secret
//! let secret = [7u8; 32];
//! let identity = generate_identity_from_secret(secret).unwrap();
//!
//! // The document is already signed and valid
//! identity.document.verify().unwrap();
//! identity.document.validate().unwrap();
//!
//! // Serialize to JSON or CBOR
//! let json = identity.document.marshal().unwrap();
//! let cbor = identity.document.to_cbor().unwrap();
//! ```
//!
//! If your application already has a resolved IPNS identifier, use
//! `generate_identity(ipns)` as the explicit low-level path.
//!
//! ## Quick Start — Messages
//!
//! ```rust
//! use ma_did::{generate_identity_from_secret, Message, SigningKey, Did};
//!
//! let alice = generate_identity_from_secret([1u8; 32]).unwrap();
//! let bob = generate_identity_from_secret([2u8; 32]).unwrap();
//!
//! // Reconstruct signing key from stored private key bytes
//! let alice_sign_url = Did::new_url(&alice.subject_url.ipns, None::<String>).unwrap();
//! let alice_signing_key = SigningKey::from_private_key_bytes(
//!     alice_sign_url,
//!     hex::decode(&alice.signing_private_key_hex).unwrap().try_into().unwrap(),
//! ).unwrap();
//!
//! // Create a signed message
//! let msg = Message::new(
//!     alice.document.id.clone(),
//!     bob.document.id.clone(),
//!     "text/plain",
//!     b"hello".to_vec(),
//!     &alice_signing_key,
//! ).unwrap();
//!
//! // Verify message signature against sender's document
//! msg.verify_with_document(&alice.document).unwrap();
//!
//! // Encrypt for recipient as an Envelope
//! let envelope = msg.enclose_for(&bob.document).unwrap();
//! ```

pub mod constants;
pub mod did;
pub mod doc;
pub mod error;
pub mod identity;
pub mod key;
pub mod msg;
mod multiformat;

pub use did::{DID_PREFIX, Did};
pub use doc::{
    DEFAULT_DID_CONTEXT, DEFAULT_PROOF_PURPOSE, DEFAULT_PROOF_TYPE, Document, Proof,
    VerificationMethod, now_iso_utc,
};
pub use error::{MaError, Result};
pub use identity::{
    GeneratedIdentity, generate_identity, generate_identity_from_secret, ipns_from_secret,
};
pub use ipld_core::ipld::Ipld;
pub use key::{
    ASSERTION_METHOD_KEY_TYPE, ED25519_PUB_CODEC, EDDSA_SIG_CODEC, EncryptionKey,
    KEY_AGREEMENT_KEY_TYPE, SigningKey, X25519_PUB_CODEC,
};
pub use msg::{
    DEFAULT_MAX_CLOCK_SKEW_SECS, DEFAULT_MESSAGE_TTL_SECS, DEFAULT_REPLAY_WINDOW_SECS, Envelope,
    Headers, MESSAGE_PREFIX, Message, ReplayGuard,
};
