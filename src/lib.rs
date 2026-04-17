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
//! use ma_did::{generate_identity, Did};
//!
//! // Generate a complete identity (keys + signed document)
//! let ipns = "k51qzi5uqu5dj9807pbuod1pplf0vxh8m4lfy3ewl9qbm2s8dsf9ugdf9gedhr";
//! let identity = generate_identity(ipns).unwrap();
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
//! ## Quick Start — Messages
//!
//! ```rust
//! use ma_did::{generate_identity, Message, SigningKey, Did};
//!
//! let alice = generate_identity("k51qzi5uqu5dj9807pbuod1pplf0vxh8m4lfy3ewl9qbm2s8dsf9ugdf9gedhr").unwrap();
//! let bob = generate_identity("k51qzi5uqu5dl96qbq93mwl5drvk2z83fk4s6h4n7xgqnwrxlscs11i1bja7uk").unwrap();
//!
//! // Reconstruct signing key from stored private key bytes
//! let alice_sign_did = Did::new_root(&alice.root_did.ipns).unwrap();
//! let alice_signing_key = SigningKey::from_private_key_bytes(
//!     alice_sign_did,
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
pub use identity::{GeneratedIdentity, generate_identity};
pub use key::{
    ASSERTION_METHOD_KEY_TYPE, ED25519_PUB_CODEC, EDDSA_SIG_CODEC, EncryptionKey,
    KEY_AGREEMENT_KEY_TYPE, SigningKey, X25519_PUB_CODEC,
};
pub use msg::{
    DEFAULT_MAX_CLOCK_SKEW_SECS, DEFAULT_MESSAGE_TTL_SECS, DEFAULT_REPLAY_WINDOW_SECS, Envelope,
    Headers, MESSAGE_PREFIX, Message, ReplayGuard,
};
