use thiserror::Error;

pub type Result<T> = std::result::Result<T, MaError>;

#[derive(Debug, Error)]
pub enum MaError {
    #[error("empty DID")]
    EmptyDid,
    #[error("invalid DID prefix, expected did:ma:")]
    InvalidDidPrefix,
    #[error("missing DID identifier")]
    MissingIdentifier,
    #[error("missing DID fragment")]
    MissingFragment,
    #[error("invalid DID format")]
    InvalidDidFormat,
    #[error("invalid DID fragment: {0}")]
    InvalidFragment(String),
    #[error("invalid DID identifier")]
    InvalidIdentifier,
    #[error("invalid message id")]
    InvalidMessageId,
    #[error("empty message id")]
    EmptyMessageId,
    #[error("invalid message type")]
    InvalidMessageType,
    #[error("invalid key type")]
    InvalidKeyType,
    #[error("invalid recipient")]
    InvalidRecipient,
    #[error("missing message content")]
    MissingContent,
    #[error("missing message content type")]
    MissingContentType,
    #[error("missing sender")]
    MissingSender,
    #[error("missing signature")]
    MissingSignature,
    #[error("message timestamp is invalid")]
    InvalidMessageTimestamp,
    #[error("message is too old")]
    MessageTooOld,
    #[error("message timestamp is too far in the future")]
    MessageFromFuture,
    #[error("replay detected")]
    ReplayDetected,
    #[error("sender and recipient must differ")]
    SameActor,
    #[error("context missing")]
    EmptyContext,
    #[error("controller missing")]
    EmptyController,
    #[error("verification method missing type")]
    VerificationMethodMissingType,
    #[error("unknown verification method: {0}")]
    UnknownVerificationMethod(String),
    #[error("public key multibase is empty")]
    EmptyPublicKeyMultibase,
    #[error("invalid public key multibase")]
    InvalidPublicKeyMultibase,
    #[error("invalid multicodec, expected {expected}, got {actual}")]
    InvalidMulticodec { expected: u64, actual: u64 },
    #[error("invalid key length, expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("proof is missing")]
    MissingProof,
    #[error("document signature is invalid")]
    InvalidDocumentSignature,
    #[error("message signature is invalid")]
    InvalidMessageSignature,
    #[error("presence hint is empty")]
    EmptyPresenceHint,
    #[error("lang is empty")]
    EmptyLang,
    #[error("language preference list is empty")]
    EmptyLanguagePreference,
    #[error("language preference must follow GNU LANGUAGE format (colon-separated language list)")]
    InvalidLanguagePreferenceFormat,
    #[error("invalid ma.type value: {0}. allowed values: avatar, agent, world, room, object")]
    InvalidMaType(String),
    #[error("invalid ma.world DID: {0}")]
    InvalidMaWorld(String),
    #[error("invalid ma.currentInbox value: {0}")]
    InvalidMaCurrentInbox(String),
    #[error("invalid ma.transports value: expected object or array")]
    InvalidMaTransports,
    #[error("invalid ma.link value: {0}")]
    InvalidMaLink(String),
    #[error("invalid ma.stateCid: {0}")]
    InvalidMaStateCid(String),
    #[error("invalid ma.worldRootCid: {0}")]
    InvalidMaWorldRootCid(String),
    #[error("invalid ma.created timestamp: {0}")]
    InvalidMaCreated(String),
    #[error("invalid ma.updated timestamp: {0}")]
    InvalidMaUpdated(String),
    #[error("invalid ma.deactivated timestamp: {0}")]
    InvalidMaDeactivated(String),
    #[error("invalid ma.versionId: {0}")]
    InvalidMaVersionId(String),
    #[error("identity CID is invalid")]
    InvalidIdentity,
    #[error("missing envelope field: {0}")]
    MissingEnvelopeField(&'static str),
    #[error("invalid ephemeral key length")]
    InvalidEphemeralKeyLength,
    #[error("ciphertext too short")]
    CiphertextTooShort,
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("CBOR encode failed: {0}")]
    CborEncode(String),
    #[error("CBOR decode failed: {0}")]
    CborDecode(String),
    #[error("JSON encode failed: {0}")]
    JsonEncode(String),
    #[error("JSON decode failed: {0}")]
    JsonDecode(String),
}
