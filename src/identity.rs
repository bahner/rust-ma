use libp2p_identity::PeerId;

use crate::{Did, Document, EncryptionKey, MaError, Result, SigningKey, VerificationMethod};

/// A generated DID identity with keys and a signed document.
///
/// Private keys are hex-encoded for storage. Use [`SigningKey::from_private_key_bytes`]
/// and [`EncryptionKey::from_private_key_bytes`] to reconstruct key objects.
#[derive(Debug, Clone)]
pub struct GeneratedIdentity {
    pub subject_url: Did,
    pub document: Document,
    pub signing_private_key_hex: String,
    pub encryption_private_key_hex: String,
}

fn build_identity(ipns: &str) -> Result<GeneratedIdentity> {
    let subject_url = Did::new_url(ipns, None::<String>)?;
    let sign_url = Did::new_url(ipns, None::<String>)?;
    let enc_url = Did::new_url(ipns, None::<String>)?;

    let signing_key = SigningKey::generate(sign_url)?;
    let encryption_key = EncryptionKey::generate(enc_url)?;

    let mut document = Document::new(&subject_url, &subject_url);

    let assertion_vm = VerificationMethod::new(
        subject_url.base_id(),
        subject_url.base_id(),
        signing_key.key_type.clone(),
        signing_key.did.fragment.as_deref().unwrap_or_default(),
        signing_key.public_key_multibase.clone(),
    )?;

    let key_agreement_vm = VerificationMethod::new(
        subject_url.base_id(),
        subject_url.base_id(),
        encryption_key.key_type.clone(),
        encryption_key.did.fragment.as_deref().unwrap_or_default(),
        encryption_key.public_key_multibase.clone(),
    )?;

    let assertion_vm_id = assertion_vm.id.clone();
    document.add_verification_method(assertion_vm.clone())?;
    document.add_verification_method(key_agreement_vm.clone())?;
    document.assertion_method = vec![assertion_vm_id];
    document.key_agreement = vec![key_agreement_vm.id.clone()];
    document.sign(&signing_key, &assertion_vm)?;

    Ok(GeneratedIdentity {
        subject_url,
        document,
        signing_private_key_hex: hex::encode(signing_key.private_key_bytes()),
        encryption_private_key_hex: hex::encode(encryption_key.private_key_bytes()),
    })
}

/// Derive the `did:ma` IPNS identifier from a caller-managed Ed25519 secret.
///
/// The secret must be a valid 32-byte libp2p Ed25519 secret key. Secret storage,
/// rotation, and recovery remain the caller's responsibility.
pub fn ipns_from_secret(secret: [u8; 32]) -> Result<String> {
    let keypair = libp2p_identity::Keypair::ed25519_from_bytes(secret)
        .map_err(|_| MaError::InvalidIdentitySecret)?;
    let peer_id = PeerId::from_public_key(&keypair.public());
    Ok(peer_id.to_string())
}

/// Generate a base DID identity with keys and a signed document.
///
/// Use this when the application already has an IPNS identifier and wants to
/// supply it explicitly. For the default flow where the application owns only
/// the secret material, prefer [`generate_identity_from_secret`].
///
/// No `ma` extension fields are set — those are application-specific.
///
/// # Examples
///
/// ```
/// use ma_did::generate_identity;
///
/// let id = generate_identity(
///     "k51qzi5uqu5dj9807pbuod1pplf0vxh8m4lfy3ewl9qbm2s8dsf9ugdf9gedhr"
/// ).unwrap();
///
/// // Document is signed and valid
/// id.document.verify().unwrap();
/// id.document.validate().unwrap();
///
/// // Private keys available for storage
/// assert!(!id.signing_private_key_hex.is_empty());
/// assert!(!id.encryption_private_key_hex.is_empty());
/// ```
pub fn generate_identity(ipns: &str) -> Result<GeneratedIdentity> {
    build_identity(ipns)
}

/// Generate a base DID identity where the `did:ma` IPNS identifier is derived
/// from a caller-managed Ed25519 secret.
///
/// This keeps the secret under application control while removing the need for
/// callers to precompute the IPNS/PeerId string themselves.
///
/// # Examples
///
/// ```
/// use ma_did::{generate_identity_from_secret, ipns_from_secret};
///
/// let secret = [7u8; 32];
/// let identity = generate_identity_from_secret(secret).unwrap();
/// let expected_ipns = ipns_from_secret(secret).unwrap();
///
/// assert_eq!(identity.subject_url.ipns, expected_ipns);
/// identity.document.verify().unwrap();
/// ```
pub fn generate_identity_from_secret(secret: [u8; 32]) -> Result<GeneratedIdentity> {
    let ipns = ipns_from_secret(secret)?;
    build_identity(&ipns)
}
