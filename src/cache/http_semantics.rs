//! HTTP caching semantics for the readthrough (HTTP) cache API.
//!
//! The functions in this module implement the "suggestions" that the `fastly_http_cache`
//! hostcalls provide to guests: whether a request is cacheable, the default cache key, the
//! suggested cache write options derived from response headers, and the suggested storage action.
//!
//! They follow the behavior documented for Fastly's readthrough cache:
//! <https://www.fastly.com/documentation/guides/concepts/edge-state/cache/cache-freshness/>
//!
//! Where the documentation does not specify the behavior, this module follows RFC 9111. Places
//! where Viceroy's behavior may differ from the Compute platform are marked with `NOTE`.

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime},
};

use http::{
    HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, Version,
    header::{self, AGE, CACHE_CONTROL, CONTENT_LENGTH, EXPIRES, VARY},
};
use sha2::{Digest, Sha256};

use super::{SurrogateKeySet, VaryRule};

/// Length of the cache keys produced by `get_suggested_cache_key`.
///
/// The HTTP cache API requires keys to be exactly this long.
pub const HTTP_CACHE_KEY_LENGTH: usize = 32;

/// TTL used when the response has no freshness information.
///
/// NOTE: The cache freshness documentation says "an HTTP 200 (OK) response with no
/// cache-freshness indicators in the response headers is cacheable and will have a TTL of 2
/// minutes", but the js-compute-runtime integration tests, which run on Compute, expect a TTL of
/// one hour (the default fallback TTL of a Fastly service). We follow the platform.
pub const DEFAULT_TTL: Duration = Duration::from_secs(3600);

const SURROGATE_CONTROL: HeaderName = HeaderName::from_static("surrogate-control");
const SURROGATE_KEY: HeaderName = HeaderName::from_static("surrogate-key");

/// The parts of the looked-up request that the HTTP cache needs to keep around.
#[derive(Debug, Clone)]
pub struct HttpRequestHead {
    pub method: Method,
    pub uri: Uri,
    pub version: Version,
    pub headers: HeaderMap,
}

impl HttpRequestHead {
    pub fn from_parts(parts: &http::request::Parts) -> Self {
        HttpRequestHead {
            method: parts.method.clone(),
            uri: parts.uri.clone(),
            version: parts.version,
            headers: parts.headers.clone(),
        }
    }

    pub fn to_parts(&self) -> http::request::Parts {
        let (mut parts, ()) = http::Request::builder()
            .method(self.method.clone())
            .uri(self.uri.clone())
            .version(self.version)
            .body(())
            .expect("request head was already valid")
            .into_parts();
        parts.headers = self.headers.clone();
        parts
    }
}

/// The HTTP-specific metadata stored alongside a cached object.
#[derive(Debug)]
pub struct HttpResponseMeta {
    pub status: StatusCode,
    pub version: Version,
    pub headers: HeaderMap,
    pub stale_if_error: Duration,
    pub sensitive_data: bool,
    hits: AtomicU64,
}

impl HttpResponseMeta {
    pub fn new(
        status: StatusCode,
        version: Version,
        headers: HeaderMap,
        stale_if_error: Duration,
        sensitive_data: bool,
    ) -> Self {
        HttpResponseMeta {
            status,
            version,
            headers,
            stale_if_error,
            sensitive_data,
            hits: AtomicU64::new(0),
        }
    }

    /// Number of lookups that found this object.
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::SeqCst)
    }

    pub fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::SeqCst);
    }
}

/// Whether a request is cacheable per conservative RFC 9111 semantics: only `GET` and `HEAD`.
pub fn is_request_cacheable(method: &Method) -> bool {
    method == Method::GET || method == Method::HEAD
}

/// The default cache key for a request: a hash of its host and URL.
///
/// NOTE: The Compute platform's exact key derivation is not documented. This mirrors the VCL
/// default (`req.url` and `req.http.host`), which is enough for keys to be stable and distinct
/// within a single Viceroy instance.
pub fn suggested_cache_key(req: &HttpRequestHead) -> [u8; HTTP_CACHE_KEY_LENGTH] {
    let host = req
        .headers
        .get(header::HOST)
        .map(HeaderValue::as_bytes)
        .or_else(|| req.uri.authority().map(|a| a.as_str().as_bytes()))
        .unwrap_or_default();
    let path_and_query = req
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let mut hasher = Sha256::new();
    hasher.update(path_and_query.as_bytes());
    // Separator that cannot appear in a URL path:
    hasher.update(b"\n");
    hasher.update(host);
    hasher.finalize().into()
}

/// Cache write options suggested for a response, before any guest overrides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuggestedWriteOptions {
    pub max_age: Duration,
    pub initial_age: Duration,
    pub stale_while_revalidate: Duration,
    pub stale_if_error: Duration,
    pub vary_rule: String,
    pub surrogate_keys: String,
    pub length: Option<u64>,
    pub sensitive_data: bool,
}

/// The surrogate key that the cache associates with every response to a request, so that it can
/// be purged by URL.
///
/// NOTE: Compute always suggests one such key; its exact format is not documented. Viceroy uses
/// the hex-encoded default cache key.
pub fn url_surrogate_key(req: &HttpRequestHead) -> String {
    suggested_cache_key(req)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect()
}

/// Derive the suggested cache write options from response headers.
///
/// - TTL: `Surrogate-Control: max-age`, `Cache-Control: s-maxage`, `Cache-Control: max-age`,
///   `Expires`, then [`DEFAULT_TTL`], in that order of preference.
/// - `Age` is reported as the initial age, so it reduces the remaining freshness of a TTL taken
///   from `max-age`/`s-maxage`. It does not affect a TTL taken from `Expires`.
/// - `stale-while-revalidate` / `stale-if-error`: `Surrogate-Control`, then `Cache-Control`.
pub fn suggested_write_options(
    request: &HttpRequestHead,
    headers: &HeaderMap,
    now: SystemTime,
) -> SuggestedWriteOptions {
    let surrogate_control = Directives::parse(headers, &SURROGATE_CONTROL);
    let cache_control = Directives::parse(headers, &CACHE_CONTROL);

    let initial_age = headers
        .get(AGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or_default();

    let max_age = if let Some(ttl) = surrogate_control
        .seconds("max-age")
        .or_else(|| cache_control.seconds("s-maxage"))
        .or_else(|| cache_control.seconds("max-age"))
    {
        ttl
    } else if let Some(expires) = headers.get(EXPIRES) {
        // The TTL is relative to the origin's notion of "now", if it provided one.
        let date = headers
            .get(header::DATE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| httpdate::parse_http_date(v).ok())
            .unwrap_or(now);
        // An invalid Expires value means "already expired" (RFC 9111 section 5.3).
        let ttl = expires
            .to_str()
            .ok()
            .and_then(|v| httpdate::parse_http_date(v).ok())
            .and_then(|expires| expires.duration_since(date).ok())
            .unwrap_or_default();
        // Age does not affect an Expires-derived TTL; cancel out the initial age.
        ttl + initial_age
    } else {
        // NOTE: Whether Age reduces the default TTL on Compute is not documented.
        DEFAULT_TTL + initial_age
    };

    let stale_while_revalidate = surrogate_control
        .seconds("stale-while-revalidate")
        .or_else(|| cache_control.seconds("stale-while-revalidate"))
        .unwrap_or_default();
    let stale_if_error = surrogate_control
        .seconds("stale-if-error")
        .or_else(|| cache_control.seconds("stale-if-error"))
        .unwrap_or_default();

    let length = if headers.contains_key(header::TRANSFER_ENCODING) {
        None
    } else {
        headers
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse().ok())
    };

    SuggestedWriteOptions {
        max_age,
        initial_age,
        stale_while_revalidate,
        stale_if_error,
        vary_rule: vary_rule(headers),
        surrogate_keys: surrogate_keys(request, headers),
        length,
        sensitive_data: false,
    }
}

/// The vary rule of a response, as a space-separated list of lowercase header names.
fn vary_rule(headers: &HeaderMap) -> String {
    let names: Vec<HeaderName> = headers
        .get_all(VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|name| !name.is_empty() && *name != "*")
        .filter_map(|name| HeaderName::try_from(name).ok())
        .collect();
    let rule = VaryRule::new(names.iter());
    rule.headers()
        .iter()
        .map(HeaderName::as_str)
        .collect::<Vec<_>>()
        .join(" ")
}

/// The surrogate keys of a response, as a space-separated list.
fn surrogate_keys(request: &HttpRequestHead, headers: &HeaderMap) -> String {
    let url_key = url_surrogate_key(request);
    let keys: Vec<&str> = std::iter::once(url_key.as_str())
        .chain(
            headers
                .get_all(SURROGATE_KEY)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(str::split_ascii_whitespace),
        )
        .collect();
    // Drop keys the cache would reject, rather than failing the whole suggestion.
    match keys.join(" ").parse::<SurrogateKeySet>() {
        Ok(_) => keys.join(" "),
        Err(_) => keys
            .into_iter()
            .filter(|k| k.parse::<SurrogateKeySet>().is_ok())
            .collect::<Vec<_>>()
            .join(" "),
    }
}

/// The storage action suggested by `prepare_response_for_storage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageAction {
    Insert,
    Update,
    DoNotStore,
    RecordUncacheable,
}

/// The response to store, and what to do with it.
#[derive(Debug)]
pub struct PreparedResponse {
    pub action: StorageAction,
    pub status: StatusCode,
    pub version: Version,
    pub headers: HeaderMap,
}

/// Statuses that are cacheable by default.
fn is_status_cacheable(status: StatusCode) -> bool {
    matches!(status.as_u16(), 200 | 203 | 300 | 301 | 302 | 404 | 410)
}

/// Adjust a backend response for storage, and suggest what to do with it.
///
/// `stored` is the response currently in the cache, if the backend request was a revalidation.
pub fn prepare_response_for_storage(
    request: &HttpRequestHead,
    status: StatusCode,
    version: Version,
    headers: &HeaderMap,
    stored: Option<&HttpResponseMeta>,
    now: SystemTime,
) -> PreparedResponse {
    // A 304 to a revalidation request freshens the stored response (RFC 9111 section 4.3.4).
    if status == StatusCode::NOT_MODIFIED
        && let Some(stored) = stored
    {
        let mut merged = stored.headers.clone();
        for name in headers.keys() {
            if name == CONTENT_LENGTH {
                continue;
            }
            merged.remove(name);
            for value in headers.get_all(name) {
                merged.append(name.clone(), value.clone());
            }
        }
        return PreparedResponse {
            action: StorageAction::Update,
            status: stored.status,
            version: stored.version,
            headers: merged,
        };
    }

    let cache_control = Directives::parse(headers, &CACHE_CONTROL);
    let vary_all = headers
        .get_all(VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|name| name.trim() == "*");

    let action = if !is_status_cacheable(status) || vary_all {
        StorageAction::DoNotStore
    } else if cache_control.has("private") || cache_control.has("no-store") {
        // The default VCL boilerplate executes `return(pass)` in `vcl_fetch` for
        // `Cache-Control: private` and `no-store`, which records a hit-for-pass object.
        StorageAction::RecordUncacheable
    } else {
        let options = suggested_write_options(request, headers, now);
        let total = options.max_age + options.stale_while_revalidate + options.stale_if_error;
        if total <= options.initial_age {
            // "The content is deemed uncacheable or has a total TTL of zero."
            StorageAction::DoNotStore
        } else {
            StorageAction::Insert
        }
    };

    PreparedResponse {
        action,
        status,
        version,
        headers: headers.clone(),
    }
}

/// Headers to add to a backend request to revalidate a stored response.
pub fn revalidation_headers(stored: &HttpResponseMeta) -> Vec<(HeaderName, HeaderValue)> {
    let mut out = Vec::new();
    if let Some(etag) = stored.headers.get(header::ETAG) {
        out.push((header::IF_NONE_MATCH, etag.clone()));
    }
    if let Some(last_modified) = stored.headers.get(header::LAST_MODIFIED) {
        out.push((header::IF_MODIFIED_SINCE, last_modified.clone()));
    }
    out
}

/// Whether a client's conditional request is satisfied by the stored response, so that a
/// `304 Not Modified` can be returned instead (RFC 9110 section 13.1).
pub fn is_not_modified(request: &HeaderMap, stored: &HttpResponseMeta) -> bool {
    // If-None-Match takes precedence over If-Modified-Since.
    if let Some(if_none_match) = request.get(header::IF_NONE_MATCH) {
        let Some(etag) = stored
            .headers
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
        else {
            return false;
        };
        let Ok(if_none_match) = if_none_match.to_str() else {
            return false;
        };
        // Weak comparison: ignore the `W/` prefix.
        let normalize = |tag: &str| tag.trim().trim_start_matches("W/").to_owned();
        let etag = normalize(etag);
        return if_none_match
            .split(',')
            .any(|tag| tag.trim() == "*" || normalize(tag) == etag);
    }
    if let Some(if_modified_since) = request
        .get(header::IF_MODIFIED_SINCE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| httpdate::parse_http_date(v).ok())
    {
        return stored
            .headers
            .get(header::LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| httpdate::parse_http_date(v).ok())
            .is_some_and(|last_modified| last_modified <= if_modified_since);
    }
    false
}

/// Parsed directives of a `Cache-Control`-like header.
struct Directives(Vec<(String, Option<String>)>);

impl Directives {
    fn parse(headers: &HeaderMap, name: &HeaderName) -> Self {
        let directives = headers
            .get_all(name)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .filter_map(|directive| {
                let directive = directive.trim();
                if directive.is_empty() {
                    return None;
                }
                let (key, value) = match directive.split_once('=') {
                    Some((key, value)) => (key, Some(value.trim().trim_matches('"').to_owned())),
                    None => (directive, None),
                };
                Some((key.trim().to_ascii_lowercase(), value))
            })
            .collect();
        Directives(directives)
    }

    fn has(&self, key: &str) -> bool {
        self.0.iter().any(|(k, _)| k == key)
    }

    fn seconds(&self, key: &str) -> Option<Duration> {
        self.0
            .iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, v)| v.as_deref())
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (k, v) in pairs {
            map.append(
                HeaderName::try_from(*k).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        map
    }

    fn request() -> HttpRequestHead {
        HttpRequestHead {
            method: Method::GET,
            uri: "http://origin/a".parse().unwrap(),
            version: Version::HTTP_11,
            headers: headers(&[("host", "example.com")]),
        }
    }

    fn suggest(pairs: &[(&str, &str)]) -> SuggestedWriteOptions {
        suggested_write_options(&request(), &headers(pairs), SystemTime::UNIX_EPOCH)
    }

    #[test]
    fn only_get_and_head_are_cacheable() {
        assert!(is_request_cacheable(&Method::GET));
        assert!(is_request_cacheable(&Method::HEAD));
        assert!(!is_request_cacheable(&Method::POST));
    }

    #[test]
    fn cache_key_depends_on_url_and_host() {
        let head = |uri: &str, host: &str| HttpRequestHead {
            method: Method::GET,
            uri: uri.parse().unwrap(),
            version: Version::HTTP_11,
            headers: headers(&[("host", host)]),
        };
        let a = suggested_cache_key(&head("http://origin/a", "example.com"));
        assert_eq!(
            a,
            suggested_cache_key(&head("http://origin/a", "example.com"))
        );
        assert_ne!(
            a,
            suggested_cache_key(&head("http://origin/b", "example.com"))
        );
        assert_ne!(
            a,
            suggested_cache_key(&head("http://origin/a", "example.org"))
        );
    }

    #[test]
    fn ttl_preference_order() {
        let all = [
            ("surrogate-control", "max-age=10"),
            ("cache-control", "s-maxage=20, max-age=30"),
        ];
        assert_eq!(suggest(&all).max_age, Duration::from_secs(10));
        assert_eq!(
            suggest(&[("cache-control", "s-maxage=20, max-age=30")]).max_age,
            Duration::from_secs(20)
        );
        assert_eq!(
            suggest(&[("cache-control", "max-age=30")]).max_age,
            Duration::from_secs(30)
        );
        assert_eq!(suggest(&[]).max_age, DEFAULT_TTL);
    }

    #[test]
    fn age_is_reported_as_initial_age() {
        let options = suggest(&[
            ("cache-control", "max-age=60, stale-while-revalidate=300"),
            ("age", "90"),
        ]);
        assert_eq!(options.max_age, Duration::from_secs(60));
        assert_eq!(options.initial_age, Duration::from_secs(90));
        assert_eq!(options.stale_while_revalidate, Duration::from_secs(300));
    }

    #[test]
    fn expires_ttl_is_not_affected_by_age() {
        let options = suggest(&[
            ("date", "Thu, 01 Jan 1970 00:00:00 GMT"),
            ("expires", "Thu, 01 Jan 1970 00:01:40 GMT"),
            ("age", "30"),
        ]);
        assert_eq!(
            options.max_age - options.initial_age,
            Duration::from_secs(100)
        );
    }

    #[test]
    fn invalid_expires_is_already_expired() {
        let options = suggest(&[("expires", "0")]);
        assert_eq!(options.max_age, Duration::ZERO);
    }

    #[test]
    fn vary_rule_is_normalized() {
        let options = suggest(&[
            ("vary", "Accept-Encoding, X-Test"),
            ("vary", "accept-encoding"),
        ]);
        assert_eq!(options.vary_rule, "accept-encoding x-test");
    }

    #[test]
    fn surrogate_keys_and_length() {
        let url_key = url_surrogate_key(&request());
        assert_eq!(suggest(&[]).surrogate_keys, url_key);
        let options = suggest(&[("surrogate-key", "a b"), ("content-length", "42")]);
        assert_eq!(options.surrogate_keys, format!("{url_key} a b"));
        assert_eq!(options.length, Some(42));
    }

    fn prepare(status: u16, pairs: &[(&str, &str)]) -> StorageAction {
        prepare_response_for_storage(
            &request(),
            StatusCode::from_u16(status).unwrap(),
            Version::HTTP_11,
            &headers(pairs),
            None,
            SystemTime::UNIX_EPOCH,
        )
        .action
    }

    #[test]
    fn storage_action() {
        assert_eq!(prepare(200, &[]), StorageAction::Insert);
        assert_eq!(prepare(404, &[]), StorageAction::Insert);
        assert_eq!(
            prepare(500, &[("cache-control", "max-age=300")]),
            StorageAction::DoNotStore
        );
        assert_eq!(
            prepare(200, &[("cache-control", "no-store")]),
            StorageAction::RecordUncacheable
        );
        assert_eq!(
            prepare(200, &[("cache-control", "private")]),
            StorageAction::RecordUncacheable
        );
        assert_eq!(
            prepare(200, &[("cache-control", "max-age=0")]),
            StorageAction::DoNotStore
        );
        assert_eq!(prepare(200, &[("vary", "*")]), StorageAction::DoNotStore);
    }

    #[test]
    fn not_modified_updates_stored_response() {
        let stored = HttpResponseMeta::new(
            StatusCode::OK,
            Version::HTTP_11,
            headers(&[("etag", "\"v1\""), ("x-old", "1"), ("content-length", "5")]),
            Duration::ZERO,
            false,
        );
        let prepared = prepare_response_for_storage(
            &request(),
            StatusCode::NOT_MODIFIED,
            Version::HTTP_11,
            &headers(&[("cache-control", "max-age=10"), ("content-length", "0")]),
            Some(&stored),
            SystemTime::UNIX_EPOCH,
        );
        assert_eq!(prepared.action, StorageAction::Update);
        assert_eq!(prepared.status, StatusCode::OK);
        assert_eq!(prepared.headers.get("x-old").unwrap(), "1");
        assert_eq!(prepared.headers.get("cache-control").unwrap(), "max-age=10");
        assert_eq!(prepared.headers.get("content-length").unwrap(), "5");
    }
}

#[cfg(test)]
mod revalidation_tests {
    use super::*;

    fn stored(pairs: &[(&'static str, &'static str)]) -> HttpResponseMeta {
        let mut headers = HeaderMap::new();
        for (k, v) in pairs {
            headers.append(*k, HeaderValue::from_static(v));
        }
        HttpResponseMeta::new(
            StatusCode::OK,
            Version::HTTP_11,
            headers,
            Duration::ZERO,
            false,
        )
    }

    fn request(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (k, v) in pairs {
            headers.append(*k, HeaderValue::from_static(v));
        }
        headers
    }

    #[test]
    fn if_none_match() {
        let stored = stored(&[("etag", "\"v1\"")]);
        assert!(is_not_modified(
            &request(&[("if-none-match", "\"v1\"")]),
            &stored
        ));
        assert!(is_not_modified(
            &request(&[("if-none-match", "W/\"v1\", \"v2\"")]),
            &stored
        ));
        assert!(is_not_modified(
            &request(&[("if-none-match", "*")]),
            &stored
        ));
        assert!(!is_not_modified(
            &request(&[("if-none-match", "\"v2\"")]),
            &stored
        ));
        assert!(!is_not_modified(&request(&[]), &stored));
    }

    #[test]
    fn if_modified_since() {
        let stored = stored(&[("last-modified", "Thu, 01 Jan 1970 00:00:10 GMT")]);
        let later = request(&[("if-modified-since", "Thu, 01 Jan 1970 00:00:20 GMT")]);
        let earlier = request(&[("if-modified-since", "Thu, 01 Jan 1970 00:00:05 GMT")]);
        assert!(is_not_modified(&later, &stored));
        assert!(!is_not_modified(&earlier, &stored));
    }
}
