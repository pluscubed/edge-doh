# Blocklists

`blocklists.toml` declares the source lists built into Workers Assets:

- EasyList China, parsed as DNS-blockable Adblock Plus `||domain^` rules.
- OISD Big, parsed from `domainswild`.
- HaGeZi Multi NORMAL, parsed from `wildcard/multi.txt`.

The build tool downloads each source, normalizes domains through shared core logic, deduplicates,
drops child entries shadowed by parent rules, writes one `.zerotrie` artifact per list, and emits
`assets/manifest.json` with source URL, license, entry count, SHA-256 hashes, and generation time.

## Local Workflow

```sh
cargo run -p blocklist-build -- --config blocklists.toml --out assets/
wrangler dev
curl http://localhost:8787/version
```

Use `--allow-stale` to reuse an existing artifact when a source is temporarily unreachable.
`--min-entries` defaults to `1000` so parser regressions fail hard instead of publishing empty
artifacts.

## Adding A Source

Add a `[[list]]` entry to `blocklists.toml` with a stable `name`, `url`, `format`, `license`, and
`license_url`. Supported formats are:

- `wildcard-domains`: one domain per line, optional `*.` prefix, `#` or `!` comments.
- `adblock-plus`: accepts only pure DNS-blockable `||domain^` style rules and rejects allowlists,
  cosmetic filters, regexes, path rules, wildcard candidates, ports, and IP literals.

## Refresh And Deploy

`.github/workflows/blocklists.yml` refreshes weekly on Sunday at 03:00 UTC and deploys with
Wrangler. Configure the deployment secrets once:

```sh
gh secret set CLOUDFLARE_API_TOKEN
gh secret set CLOUDFLARE_ACCOUNT_ID
```

Manual workflow dispatch has a `strict` input. Strict runs fail on unreachable sources; scheduled
runs reuse stale artifacts when possible.
