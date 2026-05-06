//! Shared blocklist normalization, lookup, and artifact metadata.

use std::borrow::Cow;

#[cfg(feature = "lookup")]
pub mod encode;
#[cfg(feature = "build")]
pub mod parser;

const LABEL_SEPARATOR: u8 = 1;

/// Metadata emitted beside blocklist artifacts.
#[derive(Debug, Clone, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Manifest {
    /// Manifest schema version.
    pub schema: u32,
    /// Artifact generation timestamp.
    pub generated_at: String,
    /// Generated list entries.
    pub lists: Vec<ListEntry>,
}

/// Metadata for one generated source list.
#[derive(Debug, Clone, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ListEntry {
    /// Stable list name.
    pub name: String,
    /// Source URL.
    pub source_url: String,
    /// Parser format used for this source.
    pub format: String,
    /// Source license name.
    pub license: String,
    /// Source license URL.
    pub license_url: String,
    /// Artifact filename relative to the assets directory.
    pub artifact_path: String,
    /// SHA-256 of the raw downloaded source.
    pub source_sha256: String,
    /// SHA-256 of the serialized artifact.
    pub artifact_sha256: String,
    /// Number of effective entries after normalization and parent collapse.
    pub entry_count: usize,
    /// Whether stale local artifacts were reused due to a source fetch failure.
    pub stale: bool,
}

/// Policy for deciding whether a DNS query should be blocked.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Blocklist {
    compiled: Vec<CompiledList>,
    overlay: Overlay,
}

impl Blocklist {
    /// Builds a blocklist from compiled lists and an inline overlay.
    #[must_use]
    pub const fn new(compiled: Vec<CompiledList>, overlay: Overlay) -> Self {
        Self { compiled, overlay }
    }

    /// Builds a blocklist with only the inline overlay.
    #[must_use]
    pub fn overlay_only(input: &str) -> Self {
        Self::new(Vec::new(), Overlay::parse(input))
    }

    /// Returns `true` when `domain` is an exact or subdomain match for a rule.
    #[must_use]
    pub fn matches(&self, domain: &str) -> bool {
        let Some(domain) = normalize_domain(domain) else {
            return false;
        };

        self.compiled.iter().any(|list| list.matches(&domain))
            || self.overlay.matches_normalized(&domain)
    }

    /// Returns the compiled lists backing this blocklist.
    #[must_use]
    pub fn compiled_lists(&self) -> &[CompiledList] {
        &self.compiled
    }
}

/// Inline env-var blocklist overlay.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct Overlay {
    domains: Vec<String>,
}

impl Overlay {
    /// Builds an overlay from newline, comma, or whitespace separated domain rules.
    #[must_use]
    pub fn parse(input: &str) -> Self {
        let mut domains: Vec<_> = input
            .split([',', '\n', '\r', '\t', ' '])
            .filter_map(normalize_rule)
            .collect();
        domains.sort_unstable();
        domains.dedup();

        Self { domains }
    }

    /// Returns `true` when `domain` is an exact or subdomain match for a rule.
    #[must_use]
    pub fn matches(&self, domain: &str) -> bool {
        let Some(domain) = normalize_domain(domain) else {
            return false;
        };

        self.matches_normalized(&domain)
    }

    /// Number of overlay rules.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.domains.len()
    }

    /// Returns whether the overlay is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    fn matches_normalized(&self, domain: &str) -> bool {
        self.domains.iter().any(|rule| {
            domain == rule
                || domain
                    .strip_suffix(rule)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        })
    }
}

/// A serialized, zero-copy lookup list.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CompiledList {
    name: String,
    bytes: Vec<u8>,
}

impl CompiledList {
    /// Creates a compiled list from its serialized bytes.
    #[must_use]
    pub fn from_bytes(name: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            bytes,
        }
    }

    /// Stable list name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Serialized trie bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns `true` when `domain` is blocked by this compiled trie.
    #[must_use]
    pub fn matches(&self, domain: &str) -> bool {
        let Some(domain) = normalize_domain(domain) else {
            return false;
        };

        self.matches_normalized(&domain)
    }

    fn matches_normalized(&self, domain: &str) -> bool {
        #[cfg(feature = "lookup")]
        {
            let trie = zerotrie::ZeroTrieSimpleAscii::<[u8]>::from_bytes(self.bytes.as_slice());
            for key in parent_keys(domain) {
                if trie.get(key.as_ref()).is_some() {
                    return true;
                }
            }
        }

        false
    }
}

/// Normalizes a domain into its DNS lookup form.
#[must_use]
pub fn normalize_domain(domain: &str) -> Option<String> {
    let trimmed = domain.trim().trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > 253 {
        return None;
    }

    let ascii = normalize_ascii_or_idna(trimmed)?;
    if ascii.is_empty() || ascii.len() > 253 || ascii.starts_with('.') || ascii.ends_with('.') {
        return None;
    }
    if ascii.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }

    for label in ascii.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        let bytes = label.as_bytes();
        if bytes.first() == Some(&b'-') || bytes.last() == Some(&b'-') {
            return None;
        }
        if !bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        {
            return None;
        }
    }

    Some(ascii)
}

/// Normalizes one inline rule.
#[must_use]
pub fn normalize_rule(rule: &str) -> Option<String> {
    let trimmed = rule.trim().trim_end_matches('.');
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    normalize_domain(trimmed)
}

/// Encodes a normalized domain into reversed-label trie key form.
#[must_use]
pub fn encode_domain_key(domain: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(domain.len() + 1);
    for label in domain.rsplit('.') {
        key.extend_from_slice(label.as_bytes());
        key.push(LABEL_SEPARATOR);
    }

    key
}

fn parent_keys(domain: &str) -> impl Iterator<Item = Cow<'_, [u8]>> {
    let labels: Vec<_> = domain.split('.').collect();
    (0..labels.len()).map(move |start| {
        let mut key = Vec::new();
        for label in labels[start..].iter().rev() {
            key.extend_from_slice(label.as_bytes());
            key.push(LABEL_SEPARATOR);
        }
        Cow::Owned(key)
    })
}

#[cfg(feature = "build")]
fn normalize_ascii_or_idna(domain: &str) -> Option<String> {
    idna::domain_to_ascii(domain)
        .ok()
        .map(|domain| domain.to_ascii_lowercase())
}

#[cfg(not(feature = "build"))]
fn normalize_ascii_or_idna(domain: &str) -> Option<String> {
    if domain.is_ascii() {
        Some(domain.to_ascii_lowercase())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{Blocklist, CompiledList, Overlay, encode_domain_key, normalize_domain};

    #[test]
    fn overlay_matches_exact_and_subdomains() {
        let blocklist = Blocklist::overlay_only("example.com, ads.test");

        assert!(blocklist.matches("example.com"));
        assert!(blocklist.matches("www.example.com."));
        assert!(blocklist.matches("x.ads.test"));
        assert!(!blocklist.matches("notexample.com"));
    }

    #[test]
    fn overlay_ignores_comments_and_invalid_domains() {
        let overlay = Overlay::parse("#comment\nexample.com\n127.0.0.1\nbad_domain");

        assert_eq!(overlay.len(), 1);
        assert!(overlay.matches("example.com"));
    }

    #[test]
    fn normalization_rejects_invalid_hosts() {
        assert_eq!(
            normalize_domain("Example.COM."),
            Some(String::from("example.com"))
        );
        assert_eq!(normalize_domain(""), None);
        assert_eq!(normalize_domain("-bad.example"), None);
        assert_eq!(normalize_domain("bad-.example"), None);
        assert_eq!(normalize_domain("127.0.0.1"), None);
    }

    #[test]
    fn compiled_list_matches_parent_rules() {
        let trie = crate::encode::encode_domains(["example.com", "ads.test"]).unwrap();
        let list = CompiledList::from_bytes("test", trie);

        assert!(list.matches("track.example.com"));
        assert!(list.matches("ads.test"));
        assert!(!list.matches("safe.test"));
    }

    #[test]
    fn key_encoding_uses_reversed_labels() {
        assert_eq!(encode_domain_key("example.com"), b"com\x01example\x01");
    }
}
