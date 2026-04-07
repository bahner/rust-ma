use cid::Cid;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{
    did::Did,
    error::{MaError, Result},
    key::{ED25519_PUB_CODEC, EncryptionKey, SigningKey, X25519_PUB_CODEC},
    multiformat::{multibase_decode, multibase_encode, public_key_multibase_decode},
};

pub const DEFAULT_DID_CONTEXT: &[&str] = &["https://w3id.org/did/v1"];
pub const DEFAULT_PROOF_TYPE: &str = "MultiformatSignature2023";
pub const DEFAULT_PROOF_PURPOSE: &str = "assertionMethod";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub key_type: String,
    pub controller: Vec<String>,
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

impl VerificationMethod {
    pub fn new(
        id: impl AsRef<str>,
        controller: impl Into<String>,
        key_type: impl Into<String>,
        fragment: impl AsRef<str>,
        public_key_multibase: impl Into<String>,
    ) -> Result<Self> {
        let base_id = id
            .as_ref()
            .split('#')
            .next()
            .ok_or(MaError::MissingIdentifier)?;

        let method = Self {
            id: format!("{base_id}#{}", fragment.as_ref()),
            key_type: key_type.into(),
            controller: vec![controller.into()],
            public_key_multibase: public_key_multibase.into(),
        };
        method.validate()?;
        Ok(method)
    }

    pub fn fragment(&self) -> Result<String> {
        let did = Did::try_from(self.id.as_str())?;
        did.fragment.ok_or(MaError::MissingFragment)
    }

    pub fn add_controller(&mut self, controller: impl Into<String>) -> Result<()> {
        let controller = controller.into();
        Did::validate(&controller)?;
        if !self.controller.contains(&controller) {
            self.controller.push(controller);
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        Did::validate_has_fragment(&self.id)?;

        if self.key_type.is_empty() {
            return Err(MaError::VerificationMethodMissingType);
        }

        if self.controller.is_empty() {
            return Err(MaError::EmptyController);
        }

        for controller in &self.controller {
            Did::validate(controller)?;
        }

        if self.public_key_multibase.is_empty() {
            return Err(MaError::EmptyPublicKeyMultibase);
        }

        public_key_multibase_decode(&self.public_key_multibase)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    #[serde(rename = "type")]
    pub proof_type: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

impl Proof {
    pub fn new(proof_value: impl Into<String>, verification_method: impl Into<String>) -> Self {
        Self {
            proof_type: DEFAULT_PROOF_TYPE.to_string(),
            verification_method: verification_method.into(),
            proof_purpose: DEFAULT_PROOF_PURPOSE.to_string(),
            proof_value: proof_value.into(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.proof_value.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaFields {
    #[serde(rename = "/", skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    #[serde(rename = "presenceHint", skip_serializing_if = "Option::is_none")]
    pub presence_hint: Option<String>,
    #[serde(rename = "currentInbox", skip_serializing_if = "Option::is_none")]
    pub current_inbox: Option<String>,
    #[serde(rename = "lang", skip_serializing_if = "Option::is_none")]
    pub lang: Option<String>,
    #[serde(rename = "language", skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(rename = "world", skip_serializing_if = "Option::is_none")]
    pub world: Option<String>,
    #[serde(rename = "requestedTTL", skip_serializing_if = "Option::is_none")]
    pub requested_ttl: Option<u64>,
    #[serde(rename = "transports", skip_serializing_if = "Option::is_none")]
    pub transports: Option<serde_json::Value>,
    #[serde(rename = "stateCid", skip_serializing_if = "Option::is_none")]
    pub state_cid: Option<String>,
    #[serde(rename = "worldRootCid", skip_serializing_if = "Option::is_none")]
    pub world_root_cid: Option<String>,
    #[serde(rename = "created", skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(rename = "updated", skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,
    #[serde(rename = "deactivated", skip_serializing_if = "Option::is_none")]
    pub deactivated: Option<String>,
    #[serde(rename = "versionId", skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
}

impl MaFields {
    fn is_empty(&self) -> bool {
        self.presence_hint.is_none()
            && self.current_inbox.is_none()
            && self.lang.is_none()
            && self.language.is_none()
            && self.kind.is_none()
            && self.world.is_none()
            && self.requested_ttl.is_none()
            && self.transports.is_none()
            && self.link.is_none()
            && self.state_cid.is_none()
            && self.world_root_cid.is_none()
            && self.created.is_none()
            && self.updated.is_none()
            && self.deactivated.is_none()
            && self.version_id.is_none()
    }
}

fn is_valid_gnu_language_token(token: &str) -> bool {
    if token.eq_ignore_ascii_case("c") || token.eq_ignore_ascii_case("posix") {
        return true;
    }
    !token.is_empty()
        && token
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '@'))
}

fn is_valid_gnu_language_list(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }
    let mut saw_any = false;
    for token in trimmed.split(':').map(str::trim) {
        if token.is_empty() || !is_valid_gnu_language_token(token) {
            return false;
        }
        saw_any = true;
    }
    saw_any
}

fn is_valid_ma_type(value: &str) -> bool {
    matches!(value, "avatar" | "agent" | "world" | "room" | "object")
}

fn is_hex_64(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn is_valid_inbox_hint(value: &str) -> bool {
    let trimmed = value.trim();
    if is_hex_64(trimmed) {
        return true;
    }
    for prefix in ["/iroh/", "/ma-iroh/", "/iroh-ma/", "/iroh+ma/"] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            let endpoint = rest.split('/').next().unwrap_or_default();
            return is_hex_64(endpoint);
        }
    }
    false
}

fn is_valid_ma_link(value: &str) -> bool {
    let trimmed = value.trim();
    if let Some(ipfs) = trimmed.strip_prefix("/ipfs/") {
        return Cid::try_from(ipfs).is_ok();
    }
    if let Some(ipns) = trimmed.strip_prefix("/ipns/") {
        return !ipns.trim().is_empty() && !ipns.contains(char::is_whitespace);
    }
    false
}

fn is_valid_rfc3339_utc(value: &str) -> bool {
    let trimmed = value.trim();
    // Strict enough for ISO-8601 UTC produced by current implementations.
    if !trimmed.ends_with('Z') {
        return false;
    }
    let bytes = trimmed.as_bytes();
    if bytes.len() < 20 {
        return false;
    }
    let expected_punct = [
        (4usize, b'-'),
        (7usize, b'-'),
        (10usize, b'T'),
        (13usize, b':'),
        (16usize, b':'),
    ];
    if expected_punct
        .iter()
        .any(|(idx, punct)| bytes.get(*idx).copied() != Some(*punct))
    {
        return false;
    }
    let core_digits = [0usize, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18];
    if core_digits.iter().any(|idx| {
        !bytes
            .get(*idx)
            .copied()
            .unwrap_or_default()
            .is_ascii_digit()
    }) {
        return false;
    }
    let tail = &trimmed[19..trimmed.len() - 1];
    if tail.is_empty() {
        return true;
    }
    if let Some(frac) = tail.strip_prefix('.') {
        return !frac.is_empty() && frac.chars().all(|ch| ch.is_ascii_digit());
    }
    false
}

fn is_valid_version_id(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '+'))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Document {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    pub controller: Vec<String>,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    #[serde(rename = "assertionMethod")]
    pub assertion_method: String,
    #[serde(rename = "keyAgreement")]
    pub key_agreement: String,
    pub proof: Proof,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ma: Option<MaFields>,
}

impl Document {
    pub fn new(identity: &Did, controller: &Did) -> Self {
        Self {
            context: DEFAULT_DID_CONTEXT
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            id: identity.id(),
            controller: vec![controller.id()],
            verification_method: Vec::new(),
            assertion_method: String::new(),
            key_agreement: String::new(),
            proof: Proof::default(),
            identity: None,
            ma: None,
        }
    }

    fn ensure_ma_mut(&mut self) -> &mut MaFields {
        self.ma.get_or_insert_with(MaFields::default)
    }

    fn clear_ma_if_empty(&mut self) {
        if self.ma.as_ref().is_some_and(MaFields::is_empty) {
            self.ma = None;
        }
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(self, &mut out)
            .map_err(|error| MaError::CborEncode(error.to_string()))?;
        Ok(out)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        ciborium::de::from_reader(bytes).map_err(|error| MaError::CborDecode(error.to_string()))
    }

    pub fn marshal(&self) -> Result<String> {
        self.to_json()
    }

    pub fn unmarshal(s: &str) -> Result<Self> {
        Self::from_json(s)
    }

    fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|error| MaError::JsonEncode(error.to_string()))
    }

    fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(|error| MaError::JsonDecode(error.to_string()))
    }

    pub fn add_controller(&mut self, controller: impl Into<String>) -> Result<()> {
        let controller = controller.into();
        Did::validate(&controller)?;
        if !self.controller.contains(&controller) {
            self.controller.push(controller);
        }
        Ok(())
    }

    pub fn add_verification_method(&mut self, method: VerificationMethod) -> Result<()> {
        method.validate()?;
        let duplicate = self.verification_method.iter().any(|existing| {
            existing.id == method.id || existing.public_key_multibase == method.public_key_multibase
        });

        if !duplicate {
            self.verification_method.push(method);
        }

        Ok(())
    }

    pub fn get_verification_method_by_id(&self, method_id: &str) -> Result<&VerificationMethod> {
        self.verification_method
            .iter()
            .find(|method| method.id == method_id)
            .ok_or_else(|| MaError::UnknownVerificationMethod(method_id.to_string()))
    }

    pub fn set_identity(&mut self, identity: impl Into<String>) -> Result<()> {
        let identity = identity.into();
        Cid::try_from(identity.as_str()).map_err(|_| MaError::InvalidIdentity)?;
        self.identity = Some(identity);
        Ok(())
    }

    pub fn set_presence_hint(&mut self, hint: impl Into<String>) -> Result<()> {
        let hint = hint.into().trim().to_string();
        if hint.is_empty() {
            return Err(MaError::EmptyPresenceHint);
        }
        self.ensure_ma_mut().presence_hint = Some(hint);
        Ok(())
    }

    pub fn clear_presence_hint(&mut self) {
        if let Some(ma) = &mut self.ma {
            ma.presence_hint = None;
        }
        self.clear_ma_if_empty();
    }

    pub fn set_ma_current_inbox(&mut self, inbox: impl Into<String>) {
        let inbox = inbox.into().trim().to_string();
        if inbox.is_empty() {
            if let Some(ma) = &mut self.ma {
                ma.current_inbox = None;
            }
            self.clear_ma_if_empty();
            return;
        }
        self.ensure_ma_mut().current_inbox = Some(inbox);
    }

    pub fn clear_ma_current_inbox(&mut self) {
        if let Some(ma) = &mut self.ma {
            ma.current_inbox = None;
        }
        self.clear_ma_if_empty();
    }

    pub fn set_lang(&mut self, lang: impl Into<String>) -> Result<()> {
        let lang = lang.into().trim().to_string();
        if lang.is_empty() {
            return Err(MaError::EmptyLang);
        }
        self.ensure_ma_mut().lang = Some(lang);
        Ok(())
    }

    pub fn clear_lang(&mut self) {
        if let Some(ma) = &mut self.ma {
            ma.lang = None;
        }
        self.clear_ma_if_empty();
    }

    pub fn set_language(&mut self, language: impl Into<String>) -> Result<()> {
        let language = language.into().trim().to_string();
        if language.is_empty() {
            return Err(MaError::EmptyLanguagePreference);
        }
        if !is_valid_gnu_language_list(&language) {
            return Err(MaError::InvalidLanguagePreferenceFormat);
        }
        self.ensure_ma_mut().language = Some(language);
        Ok(())
    }

    pub fn clear_language(&mut self) {
        if let Some(ma) = &mut self.ma {
            ma.language = None;
        }
        self.clear_ma_if_empty();
    }

    pub fn set_ma_type(&mut self, kind: impl Into<String>) -> Result<()> {
        let kind = kind.into().trim().to_string();
        if kind.is_empty() {
            if let Some(ma) = &mut self.ma {
                ma.kind = None;
            }
            self.clear_ma_if_empty();
            return Ok(());
        }
        if !is_valid_ma_type(&kind) {
            return Err(MaError::InvalidMaType(kind));
        }
        self.ensure_ma_mut().kind = Some(kind);
        Ok(())
    }

    pub fn clear_ma_type(&mut self) {
        if let Some(ma) = &mut self.ma {
            ma.kind = None;
        }
        self.clear_ma_if_empty();
    }

    pub fn set_ma_world(&mut self, world_did: impl Into<String>) {
        let world_did = world_did.into().trim().to_string();
        if world_did.is_empty() {
            if let Some(ma) = &mut self.ma {
                ma.world = None;
            }
            self.clear_ma_if_empty();
            return;
        }
        self.ensure_ma_mut().world = Some(world_did);
    }

    pub fn clear_ma_world(&mut self) {
        if let Some(ma) = &mut self.ma {
            ma.world = None;
        }
        self.clear_ma_if_empty();
    }

    pub fn set_ma_requested_ttl(&mut self, requested_ttl: u64) {
        self.ensure_ma_mut().requested_ttl = Some(requested_ttl);
    }

    pub fn clear_ma_requested_ttl(&mut self) {
        if let Some(ma) = &mut self.ma {
            ma.requested_ttl = None;
        }
        self.clear_ma_if_empty();
    }

    pub fn set_ma_transports(&mut self, transports: serde_json::Value) {
        self.ensure_ma_mut().transports = Some(transports);
    }

    pub fn clear_ma_transports(&mut self) {
        if let Some(ma) = &mut self.ma {
            ma.transports = None;
        }
        self.clear_ma_if_empty();
    }

    pub fn set_ma_link(&mut self, link: impl Into<String>) {
        let value = link.into().trim().to_string();
        if value.is_empty() {
            if let Some(ma) = &mut self.ma {
                ma.link = None;
            }
            self.clear_ma_if_empty();
            return;
        }
        self.ensure_ma_mut().link = Some(value);
    }

    pub fn clear_ma_link(&mut self) {
        if let Some(ma) = &mut self.ma {
            ma.link = None;
        }
        self.clear_ma_if_empty();
    }

    pub fn set_ma_state_cid(&mut self, cid: impl Into<String>) {
        let value = cid.into().trim().to_string();
        if value.is_empty() {
            if let Some(ma) = &mut self.ma {
                ma.state_cid = None;
            }
            self.clear_ma_if_empty();
            return;
        }
        self.ensure_ma_mut().state_cid = Some(value);
    }

    pub fn clear_ma_state_cid(&mut self) {
        if let Some(ma) = &mut self.ma {
            ma.state_cid = None;
        }
        self.clear_ma_if_empty();
    }

    pub fn set_ma_world_root_cid(&mut self, cid: impl Into<String>) {
        let value = cid.into().trim().to_string();
        if value.is_empty() {
            if let Some(ma) = &mut self.ma {
                ma.world_root_cid = None;
            }
            self.clear_ma_if_empty();
            return;
        }
        self.ensure_ma_mut().world_root_cid = Some(value);
    }

    pub fn clear_ma_world_root_cid(&mut self) {
        if let Some(ma) = &mut self.ma {
            ma.world_root_cid = None;
        }
        self.clear_ma_if_empty();
    }

    pub fn set_ma_created(&mut self, created: impl Into<String>) {
        let value = created.into().trim().to_string();
        if value.is_empty() {
            if let Some(ma) = &mut self.ma {
                ma.created = None;
            }
            self.clear_ma_if_empty();
            return;
        }
        self.ensure_ma_mut().created = Some(value);
    }

    pub fn set_ma_updated(&mut self, updated: impl Into<String>) {
        let value = updated.into().trim().to_string();
        if value.is_empty() {
            if let Some(ma) = &mut self.ma {
                ma.updated = None;
            }
            self.clear_ma_if_empty();
            return;
        }
        self.ensure_ma_mut().updated = Some(value);
    }

    pub fn set_ma_deactivated(&mut self, deactivated: impl Into<String>) {
        let value = deactivated.into().trim().to_string();
        if value.is_empty() {
            if let Some(ma) = &mut self.ma {
                ma.deactivated = None;
            }
            self.clear_ma_if_empty();
            return;
        }
        self.ensure_ma_mut().deactivated = Some(value);
    }

    pub fn clear_ma_deactivated(&mut self) {
        if let Some(ma) = &mut self.ma {
            ma.deactivated = None;
        }
        self.clear_ma_if_empty();
    }

    pub fn set_ma_version_id(&mut self, version_id: impl Into<String>) {
        let value = version_id.into().trim().to_string();
        if value.is_empty() {
            if let Some(ma) = &mut self.ma {
                ma.version_id = None;
            }
            self.clear_ma_if_empty();
            return;
        }
        self.ensure_ma_mut().version_id = Some(value);
    }

    pub fn assertion_method_public_key(&self) -> Result<VerifyingKey> {
        let vm = self.get_verification_method_by_id(&self.assertion_method)?;
        let (codec, public_key_bytes) = public_key_multibase_decode(&vm.public_key_multibase)?;
        if codec != ED25519_PUB_CODEC {
            return Err(MaError::InvalidMulticodec {
                expected: ED25519_PUB_CODEC,
                actual: codec,
            });
        }

        let key_len = public_key_bytes.len();
        let bytes: [u8; 32] =
            public_key_bytes
                .try_into()
                .map_err(|_| MaError::InvalidKeyLength {
                    expected: 32,
                    actual: key_len,
                })?;

        VerifyingKey::from_bytes(&bytes).map_err(|_| MaError::Crypto)
    }

    pub fn key_agreement_public_key_bytes(&self) -> Result<[u8; 32]> {
        let vm = self.get_verification_method_by_id(&self.key_agreement)?;
        let (codec, public_key_bytes) = public_key_multibase_decode(&vm.public_key_multibase)?;
        if codec != X25519_PUB_CODEC {
            return Err(MaError::InvalidMulticodec {
                expected: X25519_PUB_CODEC,
                actual: codec,
            });
        }

        let key_len = public_key_bytes.len();
        public_key_bytes
            .try_into()
            .map_err(|_| MaError::InvalidKeyLength {
                expected: 32,
                actual: key_len,
            })
    }

    pub fn payload_document(&self) -> Self {
        let mut payload = self.clone();
        payload.proof = Proof::default();
        payload
    }

    pub fn payload_bytes(&self) -> Result<Vec<u8>> {
        self.payload_document().to_cbor()
    }

    pub fn payload_hash(&self) -> Result<[u8; 32]> {
        Ok(blake3::hash(&self.payload_bytes()?).into())
    }

    pub fn sign(
        &mut self,
        signing_key: &SigningKey,
        verification_method: &VerificationMethod,
    ) -> Result<()> {
        if signing_key.public_key_multibase != verification_method.public_key_multibase {
            return Err(MaError::InvalidPublicKeyMultibase);
        }

        let signature = signing_key.sign(&self.payload_hash()?);
        let proof_value = multibase_encode(&signature)?;
        self.proof = Proof::new(proof_value, verification_method.id.clone());
        Ok(())
    }

    pub fn verify(&self) -> Result<()> {
        if self.proof.is_empty() {
            return Err(MaError::MissingProof);
        }

        let proof_bytes = multibase_decode(&self.proof.proof_value)?;
        let signature =
            Signature::from_slice(&proof_bytes).map_err(|_| MaError::InvalidDocumentSignature)?;
        let public_key = self.assertion_method_public_key()?;
        public_key
            .verify(&self.payload_hash()?, &signature)
            .map_err(|_| MaError::InvalidDocumentSignature)
    }

    pub fn validate(&self) -> Result<()> {
        if self.context.is_empty() {
            return Err(MaError::EmptyContext);
        }

        Did::validate(&self.id)?;

        if self.controller.is_empty() {
            return Err(MaError::EmptyController);
        }

        for controller in &self.controller {
            Did::validate(controller)?;
        }

        if let Some(identity) = &self.identity {
            Cid::try_from(identity.as_str()).map_err(|_| MaError::InvalidIdentity)?;
        }

        if let Some(hint) = self.ma.as_ref().and_then(|ma| ma.presence_hint.as_ref()) {
            if hint.trim().is_empty() {
                return Err(MaError::EmptyPresenceHint);
            }
        }

        if let Some(lang) = self.ma.as_ref().and_then(|ma| ma.lang.as_ref()) {
            if lang.trim().is_empty() {
                return Err(MaError::EmptyLang);
            }
        }

        if let Some(language) = self.ma.as_ref().and_then(|ma| ma.language.as_ref()) {
            if language.trim().is_empty() {
                return Err(MaError::EmptyLanguagePreference);
            }
            if !is_valid_gnu_language_list(language) {
                return Err(MaError::InvalidLanguagePreferenceFormat);
            }
        }

        if let Some(inbox) = self.ma.as_ref().and_then(|ma| ma.current_inbox.as_ref()) {
            if !is_valid_inbox_hint(inbox) {
                return Err(MaError::InvalidMaCurrentInbox(inbox.clone()));
            }
        }

        if let Some(world) = self.ma.as_ref().and_then(|ma| ma.world.as_ref()) {
            if Did::validate(world).is_err() {
                return Err(MaError::InvalidMaWorld(world.clone()));
            }
        }

        if let Some(transports) = self.ma.as_ref().and_then(|ma| ma.transports.as_ref()) {
            if !transports.is_object() && !transports.is_array() {
                return Err(MaError::InvalidMaTransports);
            }
        }

        if let Some(link) = self.ma.as_ref().and_then(|ma| ma.link.as_ref()) {
            if !is_valid_ma_link(link) {
                return Err(MaError::InvalidMaLink(link.clone()));
            }
        }

        if let Some(state_cid) = self.ma.as_ref().and_then(|ma| ma.state_cid.as_ref()) {
            if Cid::try_from(state_cid.as_str()).is_err() {
                return Err(MaError::InvalidMaStateCid(state_cid.clone()));
            }
        }

        if let Some(world_root_cid) = self.ma.as_ref().and_then(|ma| ma.world_root_cid.as_ref()) {
            if Cid::try_from(world_root_cid.as_str()).is_err() {
                return Err(MaError::InvalidMaWorldRootCid(world_root_cid.clone()));
            }
        }

        if let Some(created) = self.ma.as_ref().and_then(|ma| ma.created.as_ref()) {
            if !is_valid_rfc3339_utc(created) {
                return Err(MaError::InvalidMaCreated(created.clone()));
            }
        }

        if let Some(kind) = self.ma.as_ref().and_then(|ma| ma.kind.as_ref()) {
            if !is_valid_ma_type(kind) {
                return Err(MaError::InvalidMaType(kind.clone()));
            }
        }

        if let Some(updated) = self.ma.as_ref().and_then(|ma| ma.updated.as_ref()) {
            if !is_valid_rfc3339_utc(updated) {
                return Err(MaError::InvalidMaUpdated(updated.clone()));
            }
        }

        if let Some(deactivated) = self.ma.as_ref().and_then(|ma| ma.deactivated.as_ref()) {
            if !is_valid_rfc3339_utc(deactivated) {
                return Err(MaError::InvalidMaDeactivated(deactivated.clone()));
            }
        }

        if let Some(version_id) = self.ma.as_ref().and_then(|ma| ma.version_id.as_ref()) {
            if !is_valid_version_id(version_id) {
                return Err(MaError::InvalidMaVersionId(version_id.clone()));
            }
        }

        for method in &self.verification_method {
            method.validate()?;
        }

        if self.assertion_method.is_empty() {
            return Err(MaError::UnknownVerificationMethod(
                "assertionMethod".to_string(),
            ));
        }

        if self.key_agreement.is_empty() {
            return Err(MaError::UnknownVerificationMethod(
                "keyAgreement".to_string(),
            ));
        }

        Ok(())
    }
}

impl TryFrom<&EncryptionKey> for VerificationMethod {
    type Error = MaError;

    fn try_from(value: &EncryptionKey) -> Result<Self> {
        let fragment = value.did.fragment.clone().ok_or(MaError::MissingFragment)?;
        VerificationMethod::new(
            value.did.base_id(),
            value.did.base_id(),
            value.key_type.clone(),
            fragment,
            value.public_key_multibase.clone(),
        )
    }
}

impl TryFrom<&SigningKey> for VerificationMethod {
    type Error = MaError;

    fn try_from(value: &SigningKey) -> Result<Self> {
        let fragment = value.did.fragment.clone().ok_or(MaError::MissingFragment)?;
        VerificationMethod::new(
            value.did.base_id(),
            value.did.base_id(),
            value.key_type.clone(),
            fragment,
            value.public_key_multibase.clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_ma_type_accepts_allowed_value() {
        let root = Did::new_root("k51qzi5uqu5dj9807pbuod1pplf0vxh8m4lfy3ewl9qbm2s8dsf9ugdf9gedhr")
            .expect("valid test did");
        let mut document = Document::new(&root, &root);

        document
            .set_ma_type("agent")
            .expect("agent should be accepted as ma.type");
        assert_eq!(
            document
                .ma
                .as_ref()
                .and_then(|ma| ma.kind.as_ref())
                .map(String::as_str),
            Some("agent")
        );
    }

    #[test]
    fn set_ma_type_rejects_invalid_values() {
        let root = Did::new_root("k51qzi5uqu5dj9807pbuod1pplf0vxh8m4lfy3ewl9qbm2s8dsf9ugdf9gedhr")
            .expect("valid test did");
        let mut document = Document::new(&root, &root);

        let err = document
            .set_ma_type("bot")
            .expect_err("bot should be rejected in ma.type");

        match err {
            MaError::InvalidMaType(value) => assert_eq!(value, "bot"),
            other => panic!("unexpected error variant: {other}"),
        }

        let err = document
            .set_ma_type("bahner")
            .expect_err("bahner should be rejected in ma.type");

        match err {
            MaError::InvalidMaType(value) => assert_eq!(value, "bahner"),
            other => panic!("unexpected error variant: {other}"),
        }
    }

    #[test]
    fn validate_rejects_invalid_existing_ma_type() {
        let root = Did::new_root("k51qzi5uqu5dj9807pbuod1pplf0vxh8m4lfy3ewl9qbm2s8dsf9ugdf9gedhr")
            .expect("valid test did");
        let mut document = Document::new(&root, &root);
        let ma = MaFields {
            kind: Some("bahner".to_string()),
            ..Default::default()
        };
        document.ma = Some(ma);

        let err = document
            .validate()
            .expect_err("validate should reject non-enum ma.type");
        match err {
            MaError::InvalidMaType(value) => assert_eq!(value, "bahner"),
            other => panic!("unexpected error variant: {other}"),
        }
    }
}
