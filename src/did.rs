use std::sync::OnceLock;

use nanoid::nanoid;
use regex::Regex;

use crate::error::{MaError, Result};

pub const DID_PREFIX: &str = "did:ma:";

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Did {
    pub ipns: String,
    /// Local atom/inbox name (for example an avatar inbox in a world).
    /// In practice this often matches a Kubo key name, but this coupling is loose.
    pub fragment: Option<String>,
}

impl Did {
    pub fn new(ipns: impl Into<String>, fragment: impl Into<String>) -> Result<Self> {
        Self::new_fragment(ipns, fragment)
    }

    /// Create a DID with an auto-generated nanoid fragment.
    /// Use `Did::new(ipns, fragment)` when you want a specific fragment.
    pub fn new_root(ipns: impl Into<String>) -> Result<Self> {
        Self::new_fragment(ipns, nanoid!())
    }

    pub fn new_fragment(ipns: impl Into<String>, fragment: impl Into<String>) -> Result<Self> {
        let ipns = ipns.into();
        let fragment = fragment.into();

        validate_identifier(&ipns)?;
        validate_fragment(&fragment)?;

        Ok(Self {
            ipns,
            fragment: Some(fragment),
        })
    }

    pub fn base_id(&self) -> String {
        format!("{DID_PREFIX}{}", self.ipns)
    }

    pub fn with_fragment(&self, fragment: impl Into<String>) -> Result<Self> {
        Self::new_fragment(self.ipns.clone(), fragment)
    }

    pub fn id(&self) -> String {
        match &self.fragment {
            Some(fragment) => format!("{}#{fragment}", self.base_id()),
            None => self.base_id(),
        }
    }

    pub fn parse(input: &str) -> Result<(String, Option<String>)> {
        if input.is_empty() {
            return Err(MaError::EmptyDid);
        }

        let stripped = input
            .strip_prefix(DID_PREFIX)
            .ok_or(MaError::InvalidDidPrefix)?;

        let parts: Vec<_> = stripped.split('#').collect();
        match parts.as_slice() {
            [] => Err(MaError::MissingIdentifier),
            [_, ..] if parts.len() > 2 => Err(MaError::InvalidDidFormat),
            [""] => Err(MaError::MissingIdentifier),
            [identifier] => {
                validate_identifier(identifier)?;
                Ok(((*identifier).to_string(), None))
            }
            [identifier, fragment] => {
                validate_identifier(identifier)?;
                validate_fragment(fragment)?;
                Ok(((*identifier).to_string(), Some((*fragment).to_string())))
            }
            _ => Err(MaError::InvalidDidFormat),
        }
    }

    pub fn validate(input: &str) -> Result<()> {
        Self::parse(input).map(|_| ())
    }

    pub fn validate_has_fragment(input: &str) -> Result<()> {
        match Self::parse(input)? {
            (_, Some(_)) => Ok(()),
            (_, None) => Err(MaError::MissingFragment),
        }
    }
}

impl TryFrom<&str> for Did {
    type Error = MaError;

    fn try_from(value: &str) -> Result<Self> {
        let (ipns, fragment) = Self::parse(value)?;
        match fragment {
            Some(fragment) => Self::new_fragment(ipns, fragment),
            None => Err(MaError::MissingFragment),
        }
    }
}

fn validate_identifier(input: &str) -> Result<()> {
    if input.is_empty() {
        return Err(MaError::MissingIdentifier);
    }
    // IPNS identifiers are CIDv1 encoded in base36lower or base58btc;
    // reject anything containing non-alphanumeric characters.
    if !input.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(MaError::InvalidIdentifier);
    }
    Ok(())
}

static FRAGMENT_RE: OnceLock<Regex> = OnceLock::new();

fn validate_fragment(input: &str) -> Result<()> {
    let re = FRAGMENT_RE
        .get_or_init(|| Regex::new(r"^[a-zA-Z0-9_-]+$").expect("fragment regex must compile"));
    if !re.is_match(input) {
        return Err(MaError::InvalidFragment(input.to_string()));
    }
    Ok(())
}
