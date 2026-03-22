use cid::Cid;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{
    did::Did,
    error::{MaError, Result},
    key::{EncryptionKey, SigningKey, ED25519_PUB_CODEC, X25519_PUB_CODEC},
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
    #[serde(rename = "ma:presenceHint", skip_serializing_if = "Option::is_none")]
    pub ma_presence_hint: Option<String>,
    #[serde(rename = "ma:locale", skip_serializing_if = "Option::is_none")]
    pub ma_locale: Option<String>,
}

impl Document {
    pub fn new(identity: &Did, controller: &Did) -> Self {
        Self {
            context: DEFAULT_DID_CONTEXT.iter().map(|value| (*value).to_string()).collect(),
            id: identity.id(),
            controller: vec![controller.id()],
            verification_method: Vec::new(),
            assertion_method: String::new(),
            key_agreement: String::new(),
            proof: Proof::default(),
            identity: None,
            ma_presence_hint: None,
            ma_locale: None,
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
        let duplicate = self
            .verification_method
            .iter()
            .any(|existing| existing.id == method.id || existing.public_key_multibase == method.public_key_multibase);

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
        self.ma_presence_hint = Some(hint);
        Ok(())
    }

    pub fn clear_presence_hint(&mut self) {
        self.ma_presence_hint = None;
    }

    pub fn set_locale(&mut self, locale: impl Into<String>) -> Result<()> {
        let locale = locale.into().trim().to_string();
        if locale.is_empty() {
            return Err(MaError::EmptyLocale);
        }
        self.ma_locale = Some(locale);
        Ok(())
    }

    pub fn clear_locale(&mut self) {
        self.ma_locale = None;
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
        let bytes: [u8; 32] = public_key_bytes
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
        public_key_bytes.try_into().map_err(|_| MaError::InvalidKeyLength {
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

    pub fn sign(&mut self, signing_key: &SigningKey, verification_method: &VerificationMethod) -> Result<()> {
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
        let signature = Signature::from_slice(&proof_bytes).map_err(|_| MaError::InvalidDocumentSignature)?;
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

        if let Some(hint) = &self.ma_presence_hint {
            if hint.trim().is_empty() {
                return Err(MaError::EmptyPresenceHint);
            }
        }

        if let Some(locale) = &self.ma_locale {
            if locale.trim().is_empty() {
                return Err(MaError::EmptyLocale);
            }
        }

        for method in &self.verification_method {
            method.validate()?;
        }

        if self.assertion_method.is_empty() {
            return Err(MaError::UnknownVerificationMethod("assertionMethod".to_string()));
        }

        if self.key_agreement.is_empty() {
            return Err(MaError::UnknownVerificationMethod("keyAgreement".to_string()));
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