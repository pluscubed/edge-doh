//! Build-time encoding helpers.

use std::collections::{BTreeMap, BTreeSet};

use zerotrie::ZeroTrieSimpleAscii;

use crate::{encode_domain_key, normalize_domain};

/// Encodes domains into a serialized `ZeroTrieSimpleAscii`.
///
/// # Errors
///
/// Returns a `ZeroTrieBuildError` if the normalized domain keys cannot be encoded into the trie.
pub fn encode_domains<I, S>(domains: I) -> Result<Vec<u8>, zerotrie::ZeroTrieBuildError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let entries: BTreeMap<Vec<u8>, usize> = domains
        .into_iter()
        .filter_map(|domain| normalize_domain(domain.as_ref()))
        .map(|domain| encode_domain_key(domain.as_str()))
        .enumerate()
        .map(|(index, key)| (key, index + 1))
        .collect();

    let trie = ZeroTrieSimpleAscii::<Vec<u8>>::try_from(&entries)?;
    Ok(trie.into_store())
}

/// Removes child entries when a parent domain is already present.
#[must_use]
pub fn collapse_parent_shadowed(domains: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut domains: Vec<_> = domains.into_iter().collect();
    domains.sort_unstable_by(|left, right| {
        left.matches('.')
            .count()
            .cmp(&right.matches('.').count())
            .then_with(|| left.cmp(right))
    });
    domains.dedup();

    let mut kept: Vec<String> = Vec::new();
    let mut kept_set = BTreeSet::new();
    for domain in domains {
        if parent_exists(&kept_set, domain.as_str()) {
            continue;
        }
        kept_set.insert(domain.clone());
        kept.push(domain);
    }

    kept.sort_unstable();
    kept
}

fn parent_exists(parents: &BTreeSet<String>, domain: &str) -> bool {
    domain
        .match_indices('.')
        .any(|(index, _)| parents.contains(&domain[index + 1..]))
}

#[cfg(test)]
mod tests {
    use super::{collapse_parent_shadowed, encode_domains};
    use crate::CompiledList;

    #[test]
    fn collapse_drops_children() {
        let collapsed = collapse_parent_shadowed(vec![
            String::from("ads.example.com"),
            String::from("example.com"),
            String::from("other.test"),
        ]);

        assert_eq!(collapsed, vec!["example.com", "other.test"]);
    }

    #[test]
    fn encode_round_trips_lookup() {
        let bytes = encode_domains(["example.com"]).unwrap();
        let list = CompiledList::from_bytes("test", bytes);

        assert!(list.matches("www.example.com"));
        assert!(!list.matches("example.net"));
    }
}
