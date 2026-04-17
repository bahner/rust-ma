use std::sync::OnceLock;

use nanoid::nanoid;
use regex::Regex;

use crate::error::{MaError, Result};

pub const DID_PREFIX: &str = "did:ma:";

/// A parsed `did:ma:` DID.
///
/// A DID consists of an IPNS identifier and an optional fragment.
/// The base form is `did:ma:<ipns>`, and with a fragment: `did:ma:<ipns>#<fragment>`.
///
/// # Examples
///
/// ```
/// use ma_did::Did;
///
/// // Parse a DID with a fragment
/// let did = Did::try_from("did:ma:k51qzi5uqu5abc#lobby").unwrap();
/// assert_eq!(did.ipns, "k51qzi5uqu5abc");
/// assert_eq!(did.fragment.as_deref(), Some("lobby"));
/// assert_eq!(did.id(), "did:ma:k51qzi5uqu5abc#lobby");
///
/// // Parse a bare DID (no fragment)
/// let bare = Did::try_from("did:ma:k51qzi5uqu5abc").unwrap();
/// assert!(bare.is_bare());
/// assert_eq!(bare.base_id(), "did:ma:k51qzi5uqu5abc");
/// ```
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
        Self::validate_url(input)
    }

    /// Validate that `input` is a DID URL (has a fragment).
    pub fn validate_url(input: &str) -> Result<()> {
        match Self::parse(input)? {
            (_, Some(_)) => Ok(()),
            (_, None) => Err(MaError::MissingFragment),
        }
    }

    /// Validate that `input` is a bare DID (no fragment).
    pub fn validate_bare(input: &str) -> Result<()> {
        match Self::parse(input)? {
            (_, None) => Ok(()),
            (_, Some(_)) => Err(MaError::UnexpectedFragment),
        }
    }

    /// True when this DID has a fragment (is a DID URL).
    pub fn is_url(&self) -> bool {
        self.fragment.is_some()
    }

    /// True when this DID has no fragment (bare DID).
    pub fn is_bare(&self) -> bool {
        self.fragment.is_none()
    }
}

impl TryFrom<&str> for Did {
    type Error = MaError;

    /// Parse any valid DID URL.  A bare DID (no fragment) is a valid DID URL
    /// per W3C DID Core §3.2 — the fragment is optional.
    fn try_from(value: &str) -> Result<Self> {
        let (ipns, fragment) = Self::parse(value)?;
        Ok(Self { ipns, fragment })
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

#[cfg(test)]
mod tests {
    use super::*;

    const BARE: &str = "did:ma:k51qzi5uqu5abc";
    const URL: &str = "did:ma:k51qzi5uqu5abc#lobby";

    #[test]
    fn is_url_with_fragment() {
        let did = Did::try_from(URL).unwrap();
        assert!(did.is_url());
        assert!(!did.is_bare());
    }

    #[test]
    fn is_bare_without_fragment() {
        let did = Did::try_from(BARE).unwrap();
        assert!(did.is_bare());
        assert!(!did.is_url());
    }

    #[test]
    fn validate_url_accepts_fragment() {
        assert!(Did::validate_url(URL).is_ok());
    }

    #[test]
    fn validate_url_rejects_bare() {
        assert!(Did::validate_url(BARE).is_err());
    }

    #[test]
    fn validate_bare_accepts_bare() {
        assert!(Did::validate_bare(BARE).is_ok());
    }

    #[test]
    fn validate_bare_rejects_fragment() {
        assert!(Did::validate_bare(URL).is_err());
    }

    #[test]
    fn validate_has_fragment_delegates_to_validate_url() {
        assert!(Did::validate_has_fragment(URL).is_ok());
        assert!(Did::validate_has_fragment(BARE).is_err());
    }
}
