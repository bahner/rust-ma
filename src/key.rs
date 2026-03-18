use ed25519_dalek::{Signer, SigningKey as Ed25519SigningKey, VerifyingKey};
use rand_core::OsRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::{
    did::Did,
    error::{MaError, Result},
    multiformat::{public_key_multibase_decode, public_key_multibase_encode},
};

pub const ASSERTION_METHOD_KEY_TYPE: &str = "MultiKey";
pub const KEY_AGREEMENT_KEY_TYPE: &str = "MultiKey";

// https://github.com/multiformats/multicodec/blob/master/table.csv
pub const X25519_PUB_CODEC: u64 = 0xec;
pub const ED25519_PUB_CODEC: u64 = 0xed;

#[derive(Clone)]
pub struct SigningKey {
    pub did: Did,
    pub key_type: String,
    signing_key: Ed25519SigningKey,
    pub public_key_multibase: String,
}

impl SigningKey {
    pub fn generate(did: Did) -> Result<Self> {
        let signing_key = Ed25519SigningKey::generate(&mut OsRng);
        let public_key_multibase =
            public_key_multibase_encode(ED25519_PUB_CODEC, signing_key.verifying_key().as_bytes())?;

        Ok(Self {
            did,
            key_type: ASSERTION_METHOD_KEY_TYPE.to_string(),
            signing_key,
            public_key_multibase,
        })
    }

    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.signing_key.sign(data).to_bytes().to_vec()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn private_key_bytes(&self) -> [u8; ed25519_dalek::SECRET_KEY_LENGTH] {
        self.signing_key.to_bytes()
    }

    pub fn from_private_key_bytes(
        did: Did,
        private_key: [u8; ed25519_dalek::SECRET_KEY_LENGTH],
    ) -> Result<Self> {
        let signing_key = Ed25519SigningKey::from_bytes(&private_key);
        let public_key_multibase =
            public_key_multibase_encode(ED25519_PUB_CODEC, signing_key.verifying_key().as_bytes())?;

        Ok(Self {
            did,
            key_type: ASSERTION_METHOD_KEY_TYPE.to_string(),
            signing_key,
            public_key_multibase,
        })
    }

    pub fn validate(&self) -> Result<()> {
        Did::validate(&self.did.id())?;

        if self.key_type != ASSERTION_METHOD_KEY_TYPE {
            return Err(MaError::InvalidKeyType);
        }

        let (codec, key_bytes) = public_key_multibase_decode(&self.public_key_multibase)?;
        if codec != ED25519_PUB_CODEC {
            return Err(MaError::InvalidMulticodec {
                expected: ED25519_PUB_CODEC,
                actual: codec,
            });
        }

        if key_bytes.len() != ed25519_dalek::PUBLIC_KEY_LENGTH {
            return Err(MaError::InvalidKeyLength {
                expected: ed25519_dalek::PUBLIC_KEY_LENGTH,
                actual: key_bytes.len(),
            });
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct EncryptionKey {
    pub did: Did,
    pub key_type: String,
    private_key: StaticSecret,
    pub public_key: X25519PublicKey,
    pub public_key_multibase: String,
}

impl EncryptionKey {
    pub fn generate(did: Did) -> Result<Self> {
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = X25519PublicKey::from(&private_key);
        let public_key_multibase =
            public_key_multibase_encode(X25519_PUB_CODEC, public_key.as_bytes())?;

        Ok(Self {
            did,
            key_type: KEY_AGREEMENT_KEY_TYPE.to_string(),
            private_key,
            public_key,
            public_key_multibase,
        })
    }

    pub fn shared_secret(&self, other: &X25519PublicKey) -> [u8; 32] {
        self.private_key.diffie_hellman(other).to_bytes()
    }

    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.private_key.to_bytes()
    }

    pub fn from_private_key_bytes(did: Did, private_key: [u8; 32]) -> Result<Self> {
        let private_key = StaticSecret::from(private_key);
        let public_key = X25519PublicKey::from(&private_key);
        let public_key_multibase =
            public_key_multibase_encode(X25519_PUB_CODEC, public_key.as_bytes())?;

        Ok(Self {
            did,
            key_type: KEY_AGREEMENT_KEY_TYPE.to_string(),
            private_key,
            public_key,
            public_key_multibase,
        })
    }

    pub fn validate(&self) -> Result<()> {
        Did::validate(&self.did.id())?;

        if self.key_type != KEY_AGREEMENT_KEY_TYPE {
            return Err(MaError::InvalidKeyType);
        }

        let (codec, key_bytes) = public_key_multibase_decode(&self.public_key_multibase)?;
        if codec != X25519_PUB_CODEC {
            return Err(MaError::InvalidMulticodec {
                expected: X25519_PUB_CODEC,
                actual: codec,
            });
        }

        if key_bytes.len() != 32 {
            return Err(MaError::InvalidKeyLength {
                expected: 32,
                actual: key_bytes.len(),
            });
        }

        Ok(())
    }
}