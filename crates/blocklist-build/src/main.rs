use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr as _;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use blocklist_core::encode::{collapse_parent_shadowed, encode_domains};
use blocklist_core::parser::{ListFormat, parse_domains};
use blocklist_core::{ListEntry, Manifest};
use clap::Parser;
use reqwest::blocking::Client;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value = "blocklists.toml")]
    config: PathBuf,
    #[arg(long, default_value = "assets")]
    out: PathBuf,
    #[arg(long)]
    allow_stale: bool,
    #[arg(long, default_value_t = 1000)]
    min_entries: usize,
}

#[derive(Debug, Deserialize)]
struct Config {
    schema: u32,
    list: Vec<SourceConfig>,
}

#[derive(Debug, Deserialize)]
struct SourceConfig {
    name: String,
    url: String,
    format: String,
    license: String,
    license_url: String,
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config = read_config(args.config.as_path())?;
    if config.schema != 1 {
        bail!("unsupported blocklists.toml schema: {}", config.schema);
    }

    fs::create_dir_all(args.out.as_path())
        .with_context(|| format!("failed to create {}", args.out.display()))?;
    let existing_entries = read_existing_manifest(args.out.as_path())?;

    let client = Client::builder()
        .user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION")
        ))
        .timeout(Duration::from_secs(60))
        .build()?;

    let mut entries = Vec::with_capacity(config.list.len());
    for source in &config.list {
        entries.push(build_source(
            &client,
            source,
            args.out.as_path(),
            &args,
            &existing_entries,
        )?);
    }

    let manifest = Manifest {
        schema: 1,
        generated_at: generated_at()?,
        lists: entries,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    fs::write(args.out.join("manifest.json"), manifest_bytes)?;

    Ok(())
}

fn read_config(path: &Path) -> Result<Config> {
    let input = fs::read_to_string(path)
        .with_context(|| format!("failed to read config {}", path.display()))?;
    toml::from_str(input.as_str()).with_context(|| format!("failed to parse {}", path.display()))
}

fn read_existing_manifest(out_dir: &Path) -> Result<BTreeMap<String, ListEntry>> {
    let path = out_dir.join("manifest.json");
    if !path.exists() {
        return Ok(BTreeMap::new());
    }

    let input = fs::read(path.as_path())
        .with_context(|| format!("failed to read existing {}", path.display()))?;
    let manifest: Manifest = serde_json::from_slice(input.as_slice())
        .with_context(|| format!("failed to parse existing {}", path.display()))?;

    Ok(manifest
        .lists
        .into_iter()
        .map(|entry| (entry.name.clone(), entry))
        .collect())
}

fn build_source(
    client: &Client,
    source: &SourceConfig,
    out_dir: &Path,
    args: &Args,
    existing_entries: &BTreeMap<String, ListEntry>,
) -> Result<ListEntry> {
    let format = ListFormat::from_str(source.format.as_str()).map_err(anyhow::Error::msg)?;
    let artifact_path = format!("{}.zerotrie", source.name);
    let artifact_file = out_dir.join(artifact_path.as_str());

    let (raw, source_sha256, stale) = match fetch_with_retry(client, source.url.as_str()) {
        Ok(raw) => {
            let source_sha256 = sha256_hex(raw.as_slice());
            (raw, source_sha256, false)
        }
        Err(error) if args.allow_stale && artifact_file.exists() => {
            log::warn!(
                "reusing stale artifact for {} after fetch failure: {error:#}",
                source.name
            );
            let bytes = fs::read(artifact_file.as_path())?;
            if let Some(existing) = existing_entries.get(source.name.as_str()) {
                let mut entry = existing.clone();
                entry.stale = true;
                entry.artifact_sha256 = sha256_hex(bytes.as_slice());
                return Ok(entry);
            }

            bail!(
                "cannot reuse stale artifact for {} without an existing manifest entry",
                source.name
            );
        }
        Err(error) => return Err(error),
    };

    let raw_text = String::from_utf8(raw).context("source is not UTF-8 text")?;
    let parsed = parse_domains(raw_text.as_str(), format);
    let unique: BTreeSet<_> = parsed.into_iter().collect();
    let domains = collapse_parent_shadowed(unique);

    if domains.len() < args.min_entries {
        bail!(
            "{} yielded {} entries, below minimum {}",
            source.name,
            domains.len(),
            args.min_entries
        );
    }

    let artifact = encode_domains(domains.iter().map(String::as_str))?;
    let artifact_sha256 = sha256_hex(artifact.as_slice());
    fs::write(artifact_file.as_path(), artifact.as_slice())
        .with_context(|| format!("failed to write {}", artifact_file.display()))?;

    Ok(ListEntry {
        name: source.name.clone(),
        source_url: source.url.clone(),
        format: source.format.clone(),
        license: source.license.clone(),
        license_url: source.license_url.clone(),
        artifact_path,
        source_sha256,
        artifact_sha256,
        entry_count: domains.len(),
        stale,
    })
}

fn fetch_with_retry(client: &Client, url: &str) -> Result<Vec<u8>> {
    let mut last_error = None;
    for attempt in 0..3 {
        match client
            .get(url)
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
        {
            Ok(response) => {
                return response
                    .bytes()
                    .map(|bytes| bytes.to_vec())
                    .map_err(Into::into);
            }
            Err(error) => {
                last_error = Some(error);
                thread::sleep(Duration::from_secs(2_u64.pow(attempt)));
            }
        }
    }

    Err(anyhow!(
        "failed to fetch {url}: {}",
        last_error.map_or_else(|| String::from("unknown error"), |error| error.to_string())
    ))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn generated_at() -> Result<String> {
    let output = std::process::Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .context("failed to run date")?;
    if !output.status.success() {
        bail!("date failed with status {}", output.status);
    }

    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}
