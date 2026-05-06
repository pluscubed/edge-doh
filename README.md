# edge-doh

Super performant DoH resolver to be deployed on Cloudflare Workers and similar platforms, with
support for blocklists.

Cloudflare Workers do not expose normal UDP sockets, so the first runtime shape is an RFC 8484 DoH
edge service: accept DNS wire-format requests, apply local blocklist policy, and forward allowed
queries to an upstream DoH endpoint over `fetch`.

## Configuration

- `UPSTREAM_DOH`: upstream DoH endpoint, defaulting to `https://cloudflare-dns.com/dns-query`.
- `BLOCKLIST`: newline, comma, or whitespace separated domain rules. Rules match exact domains and
  subdomains.
- `BLOCKLIST_ASSETS`: Workers Assets binding containing generated `.zerotrie` blocklist artifacts.
  The inline `BLOCKLIST` env var is still applied as a small overlay.

## Blocklist Artifacts

Generate artifacts locally with:

```sh
cargo run -p blocklist-build -- --config blocklists.toml --out assets/
```

Then run `wrangler dev`. The Worker loads `assets/manifest.json` and each listed trie on first
request, caches them for the isolate lifetime, and exposes provenance at `/version`.

See [docs/blocklists.md](docs/blocklists.md) for source formats, refresh workflow, and license
attribution.

## Checks

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo check -p edge-doh --target wasm32-unknown-unknown
cargo bench -p blocklist-core
cd crates/edge-doh && worker-build --release
```

## Reference

Inspired by https://github.com/serverless-dns/serverless-dns
