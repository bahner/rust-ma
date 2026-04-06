use crate::{Did, Document, EncryptionKey, Result, SigningKey, VerificationMethod};

#[derive(Debug, Clone)]
pub struct GeneratedIdentity {
    pub root_did: Did,
    pub document: Document,
    pub signing_private_key_hex: String,
    pub encryption_private_key_hex: String,
}

pub fn generate_agent_identity(ipns: &str) -> Result<GeneratedIdentity> {
    let root_did = Did::new_root(ipns)?;
    let sign_did = Did::new(ipns, "sig")?;
    let enc_did = Did::new(ipns, "enc")?;

    let signing_key = SigningKey::generate(sign_did)?;
    let encryption_key = EncryptionKey::generate(enc_did)?;

    let mut document = Document::new(&root_did, &root_did);

    let assertion_vm = VerificationMethod::new(
        root_did.base_id(),
        root_did.base_id(),
        signing_key.key_type.clone(),
        "sig",
        signing_key.public_key_multibase.clone(),
    )?;

    let key_agreement_vm = VerificationMethod::new(
        root_did.base_id(),
        root_did.base_id(),
        encryption_key.key_type.clone(),
        "enc",
        encryption_key.public_key_multibase.clone(),
    )?;

    let assertion_vm_id = assertion_vm.id.clone();
    document.add_verification_method(assertion_vm.clone())?;
    document.add_verification_method(key_agreement_vm.clone())?;
    document.assertion_method = assertion_vm_id;
    document.key_agreement = key_agreement_vm.id.clone();
    document.set_ma_type("agent");
    document.sign(&signing_key, &assertion_vm)?;

    Ok(GeneratedIdentity {
        root_did,
        document,
        signing_private_key_hex: hex::encode(signing_key.private_key_bytes()),
        encryption_private_key_hex: hex::encode(encryption_key.private_key_bytes()),
    })
}
