//! Serverless DNS over HTTPS resolver core and Worker entrypoint.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use blocklist_core::Blocklist;
use hickory_proto::op::{Message, MessageType, ResponseCode};

/// DNS message media type from RFC 8484.
pub const DNS_MESSAGE_CONTENT_TYPE: &str = "application/dns-message";

/// Default upstream used when `UPSTREAM_DOH` is not configured.
pub const DEFAULT_UPSTREAM_DOH: &str = "https://cloudflare-dns.com/dns-query";

/// Result of applying local policy to a `DoH` query.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ResolveDecision {
    /// The query can be forwarded to an upstream resolver.
    Forward {
        /// Original DNS wire-format query.
        query: Vec<u8>,
    },
    /// The query matched a blocklist rule and should be answered locally.
    Block {
        /// DNS wire-format response.
        response: Vec<u8>,
    },
}

/// Applies blocklist policy to a DNS wire-format query.
///
/// Forwarding is intentionally left to the platform entrypoint so the core can stay portable
/// across Cloudflare Workers and future serverless targets.
///
/// # Errors
///
/// Returns `ResolveError` if the DNS message cannot be decoded or an NXDOMAIN response cannot be
/// encoded.
pub fn resolve_query(query: &[u8], blocklist: &Blocklist) -> Result<ResolveDecision, ResolveError> {
    let message = Message::from_vec(query).map_err(|source| ResolveError::Decode {
        source: source.to_string(),
    })?;

    let blocked = message
        .queries
        .iter()
        .map(|query| query.name().to_utf8())
        .any(|name| blocklist.matches(name.as_str()));

    if blocked {
        return Ok(ResolveDecision::Block {
            response: blocked_response(&message)?,
        });
    }

    Ok(ResolveDecision::Forward {
        query: Vec::from(query),
    })
}

/// Decodes an RFC 8484 GET `dns` query parameter.
///
/// # Errors
///
/// Returns `ResolveError::InvalidGetQuery` if the value is not valid unpadded base64url.
pub fn decode_get_query(encoded_query: &str) -> Result<Vec<u8>, ResolveError> {
    URL_SAFE_NO_PAD
        .decode(encoded_query)
        .map_err(|source| ResolveError::InvalidGetQuery {
            source: source.to_string(),
        })
}

/// Error type for DNS parsing and policy handling.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ResolveError {
    /// The DNS message could not be decoded.
    Decode {
        /// Decoder error detail.
        source: String,
    },
    /// The DNS message could not be encoded.
    Encode {
        /// Encoder error detail.
        source: String,
    },
    /// The HTTP GET `dns` parameter is not valid unpadded base64url.
    InvalidGetQuery {
        /// Decoder error detail.
        source: String,
    },
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode { source } => write!(formatter, "failed to decode DNS message: {source}"),
            Self::Encode { source } => write!(formatter, "failed to encode DNS message: {source}"),
            Self::InvalidGetQuery { source } => {
                write!(formatter, "failed to decode DoH GET query: {source}")
            }
        }
    }
}

impl std::error::Error for ResolveError {}

fn blocked_response(query: &Message) -> Result<Vec<u8>, ResolveError> {
    let mut response = Message::new(
        query.metadata.id,
        MessageType::Response,
        query.metadata.op_code,
    );
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.metadata.response_code = ResponseCode::NXDomain;

    for question in &query.queries {
        response.add_query(question.clone());
    }

    response.to_vec().map_err(|source| ResolveError::Encode {
        source: source.to_string(),
    })
}

#[cfg(target_arch = "wasm32")]
mod worker_entrypoint {
    use std::sync::OnceLock;

    use blocklist_core::{CompiledList, ListEntry, Manifest, Overlay};
    use js_sys::Uint8Array;
    use worker::{Env, Fetch, Fetcher, Headers, Method, Request, RequestInit, Response, event};

    use super::{
        DEFAULT_UPSTREAM_DOH, DNS_MESSAGE_CONTENT_TYPE, ResolveDecision, decode_get_query,
        resolve_query,
    };

    static BLOCKLIST: OnceLock<blocklist_core::Blocklist> = OnceLock::new();
    static MANIFEST: OnceLock<Option<Manifest>> = OnceLock::new();

    #[event(fetch)]
    pub async fn fetch(req: Request, env: Env, _ctx: worker::Context) -> worker::Result<Response> {
        match req.path().as_str() {
            "/" | "/dns-query" => handle_dns_query(req, env).await,
            "/health" => Response::ok("ok"),
            "/version" => version_response(&env).await,
            _ => Response::error("not found", 404),
        }
    }

    async fn handle_dns_query(mut req: Request, env: Env) -> worker::Result<Response> {
        let query = match req.method() {
            Method::Get => {
                let url = req.url()?;
                let Some(encoded_query) = url
                    .query_pairs()
                    .find_map(|(key, value)| (key == "dns").then_some(value.into_owned()))
                else {
                    return Response::error("missing dns query parameter", 400);
                };

                match decode_get_query(encoded_query.as_str()) {
                    Ok(query) => query,
                    Err(_) => return Response::error("invalid dns query parameter", 400),
                }
            }
            Method::Post => {
                let content_type = req.headers().get("content-type")?.unwrap_or_default();
                if !content_type.starts_with(DNS_MESSAGE_CONTENT_TYPE) {
                    return Response::error("unsupported content type", 415);
                }

                req.bytes().await?
            }
            _ => return Response::error("method not allowed", 405),
        };

        let blocklist = ensure_blocklist(&env).await?;

        match resolve_query(query.as_slice(), blocklist) {
            Ok(ResolveDecision::Block { response }) => dns_response(response, 200),
            Ok(ResolveDecision::Forward { query }) => forward_query(query, env).await,
            Err(_) => Response::error("invalid dns message", 400),
        }
    }

    async fn ensure_blocklist(env: &Env) -> worker::Result<&'static blocklist_core::Blocklist> {
        if let Some(blocklist) = BLOCKLIST.get() {
            return Ok(blocklist);
        }

        let overlay = env
            .var("BLOCKLIST")
            .map(|value| Overlay::parse(value.to_string().as_str()))
            .unwrap_or_default();

        let (manifest, compiled) = load_compiled_lists(env).await.unwrap_or_default();
        let _ = MANIFEST.set(manifest);
        let blocklist = blocklist_core::Blocklist::new(compiled, overlay);
        let _ = BLOCKLIST.set(blocklist);

        BLOCKLIST.get().ok_or_else(|| {
            worker::Error::RustError(String::from("blocklist cache was not initialized"))
        })
    }

    async fn load_compiled_lists(
        env: &Env,
    ) -> worker::Result<(Option<Manifest>, Vec<CompiledList>)> {
        let assets = env.assets("BLOCKLIST_ASSETS")?;
        let manifest_bytes = fetch_asset(&assets, "manifest.json").await?;
        let manifest: Manifest = serde_json::from_slice(manifest_bytes.as_slice())
            .map_err(|source| worker::Error::RustError(source.to_string()))?;

        let mut compiled = Vec::with_capacity(manifest.lists.len());
        for entry in &manifest.lists {
            let bytes = fetch_asset(&assets, entry.artifact_path.as_str()).await?;
            compiled.push(CompiledList::from_bytes(entry.name.clone(), bytes));
        }

        Ok((Some(manifest), compiled))
    }

    async fn fetch_asset(assets: &Fetcher, path: &str) -> worker::Result<Vec<u8>> {
        let asset_url = format!("https://blocklist-assets/{path}");
        let mut response = assets.fetch(asset_url, None).await?;
        if !(200..300).contains(&response.status_code()) {
            return Err(worker::Error::RustError(format!(
                "asset fetch failed for {path}: {}",
                response.status_code()
            )));
        }

        response.bytes().await
    }

    async fn version_response(env: &Env) -> worker::Result<Response> {
        let _ = ensure_blocklist(env).await?;
        let manifest = MANIFEST.get().and_then(Option::as_ref);
        let body = match manifest {
            Some(manifest) => serde_json::to_string(&VersionSummary::from_manifest(manifest))
                .map_err(|source| worker::Error::RustError(source.to_string()))?,
            None => String::from(r#"{"lists":[]}"#),
        };

        let headers = Headers::new();
        headers.set("content-type", "application/json; charset=utf-8")?;
        Ok(Response::ok(body)?.with_headers(headers))
    }

    #[derive(serde::Serialize)]
    struct VersionSummary<'a> {
        generated_at: &'a str,
        lists: Vec<ListSummary<'a>>,
    }

    #[derive(serde::Serialize)]
    struct ListSummary<'a> {
        name: &'a str,
        source_url: &'a str,
        license: &'a str,
        license_url: &'a str,
        entry_count: usize,
        artifact_sha256: &'a str,
        source_sha256: &'a str,
        stale: bool,
    }

    impl<'a> VersionSummary<'a> {
        fn from_manifest(manifest: &'a Manifest) -> Self {
            Self {
                generated_at: manifest.generated_at.as_str(),
                lists: manifest.lists.iter().map(ListSummary::from_entry).collect(),
            }
        }
    }

    impl<'a> ListSummary<'a> {
        fn from_entry(entry: &'a ListEntry) -> Self {
            Self {
                name: entry.name.as_str(),
                source_url: entry.source_url.as_str(),
                license: entry.license.as_str(),
                license_url: entry.license_url.as_str(),
                entry_count: entry.entry_count,
                artifact_sha256: entry.artifact_sha256.as_str(),
                source_sha256: entry.source_sha256.as_str(),
                stale: entry.stale,
            }
        }
    }

    async fn forward_query(query: Vec<u8>, env: Env) -> worker::Result<Response> {
        let upstream = env
            .var("UPSTREAM_DOH")
            .map(|value| value.to_string())
            .unwrap_or_else(|_| String::from(DEFAULT_UPSTREAM_DOH));

        let headers = Headers::new();
        headers.set("accept", DNS_MESSAGE_CONTENT_TYPE)?;
        headers.set("content-type", DNS_MESSAGE_CONTENT_TYPE)?;

        let body = Uint8Array::from(query.as_slice());
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(body.into()));

        let request = Request::new_with_init(upstream.as_str(), &init)?;
        let mut response = Fetch::Request(request).send().await?;
        let status = response.status_code();
        let bytes = response.bytes().await?;

        dns_response(bytes, status)
    }

    fn dns_response(bytes: Vec<u8>, status: u16) -> worker::Result<Response> {
        let headers = Headers::new();
        headers.set("content-type", DNS_MESSAGE_CONTENT_TYPE)?;
        headers.set("cache-control", "no-store")?;

        Ok(Response::from_bytes(bytes)?
            .with_headers(headers)
            .with_status(status))
    }
}
