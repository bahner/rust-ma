#![forbid(unsafe_code)]

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
    VerificationMethod,
};
pub use error::{MaError, Result};
pub use identity::{GeneratedIdentity, generate_agent_identity};
pub use key::{
    ASSERTION_METHOD_KEY_TYPE, ED25519_PUB_CODEC, EncryptionKey, KEY_AGREEMENT_KEY_TYPE,
    SigningKey, X25519_PUB_CODEC,
};
pub use msg::{
    Envelope, Headers, Message, ReplayGuard,
    DEFAULT_MAX_CLOCK_SKEW_SECS, DEFAULT_MESSAGE_TTL_SECS, DEFAULT_REPLAY_WINDOW_SECS,
    MESSAGE_PREFIX,
};
