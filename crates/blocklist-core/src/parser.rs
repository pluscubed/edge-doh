//! Build-time parsers for source blocklist formats.

use crate::normalize_domain;

/// Supported source list format.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ListFormat {
    /// Lines containing optional `*.` wildcard prefixes and `#`/`!` comments.
    WildcardDomains,
    /// Adblock Plus filters; only pure DNS-blockable `||domain^` rules are accepted.
    AdblockPlus,
}

impl std::str::FromStr for ListFormat {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "wildcard-domains" => Ok(Self::WildcardDomains),
            "adblock-plus" => Ok(Self::AdblockPlus),
            _ => Err(format!("unsupported list format: {value}")),
        }
    }
}

/// Parses source text into normalized domains.
#[must_use]
pub fn parse_domains(input: &str, format: ListFormat) -> Vec<String> {
    match format {
        ListFormat::WildcardDomains => parse_wildcard_domains(input),
        ListFormat::AdblockPlus => parse_adblock_plus(input),
    }
}

/// Parses wildcard-domain source text.
#[must_use]
pub fn parse_wildcard_domains(input: &str) -> Vec<String> {
    input
        .lines()
        .filter_map(|line| {
            let without_hash = line.split_once('#').map_or(line, |(left, _)| left);
            let without_bang = without_hash
                .split_once('!')
                .map_or(without_hash, |(left, _)| left);
            let candidate = without_bang.trim().trim_start_matches("*.");
            normalize_domain(candidate)
        })
        .collect()
}

/// Parses DNS-blockable Adblock Plus rules.
#[must_use]
pub fn parse_adblock_plus(input: &str) -> Vec<String> {
    input.lines().filter_map(parse_adblock_plus_line).collect()
}

fn parse_adblock_plus_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('!')
        || trimmed.starts_with('[')
        || trimmed.starts_with("@@")
        || trimmed.starts_with('/')
        || trimmed.contains("##")
        || trimmed.contains("#@#")
        || trimmed.contains("#?#")
    {
        return None;
    }

    let rest = trimmed.strip_prefix("||")?;
    let domain_end = rest
        .find(['^', '$', '/', ':', '*', '|', '?', '&'])
        .unwrap_or(rest.len());
    let domain = &rest[..domain_end];

    if domain_end < rest.len() && rest.as_bytes()[domain_end] != b'^' {
        return None;
    }
    if domain.is_empty()
        || rest.get(domain_end..domain_end + 1) == Some("/")
        || domain.contains('*')
    {
        return None;
    }

    normalize_domain(domain)
}

#[cfg(test)]
mod tests {
    use super::{ListFormat, parse_adblock_plus, parse_domains, parse_wildcard_domains};

    #[test]
    fn parses_wildcard_domains() {
        let parsed = parse_wildcard_domains(
            r"
            # comment
            *.Example.com
            safe.test # inline comment
            ! comment
            127.0.0.1
            ",
        );

        assert_eq!(parsed, vec!["example.com", "safe.test"]);
    }

    #[test]
    fn parses_dns_blockable_abp_rules() {
        let parsed = parse_adblock_plus(
            r"
            ! comment
            ||example.com^
            ||ads.example.net^$third-party
            @@||allowed.example^
            ||example.org/path
            ||example.test:8080^
            ||*.wild.example^
            example.com
            ##.ad
            ",
        );

        assert_eq!(parsed, vec!["example.com", "ads.example.net"]);
    }

    #[test]
    fn dispatches_by_format() {
        assert_eq!(
            parse_domains("*.example.com", ListFormat::WildcardDomains),
            vec!["example.com"]
        );
    }
}
