//! A guest program to test the readthrough (HTTP) cache API.
//!
//! The "TheOrigin" backend (see `cli/tests/integration/http_cache.rs`) responds with a body that
//! counts the requests it has received, and with caching headers chosen by the request path.
//! Two responses with the same body therefore mean that the second one was served from cache.

use std::time::Duration;

use fastly::Request;
use fastly::http::HeaderName;

const BACKEND: &str = "TheOrigin";

/// Run a test function with wrapped logging, so it is easy to tell which test failed.
macro_rules! run_test {
    ($name:ident) => {{
        eprintln!("running test: {}", stringify!($name));
        $name();
        eprintln!("completed test: {}", stringify!($name));
    }};
}

/// Send a GET request through the readthrough cache, returning the response body.
fn get(path: &str) -> String {
    get_with(Request::get(format!("http://origin.test{path}")))
}

fn get_with(req: Request) -> String {
    let mut resp = req.send(BACKEND).expect("request succeeds");
    resp.take_body_str()
}

fn get_with_header(path: &str, name: &str, value: &str) -> String {
    get_with(Request::get(format!("http://origin.test{path}")).with_header(name, value))
}

fn main() {
    // When the HTTP cache API is disabled (the default), SDKs fall back to host-side caching,
    // which Viceroy does not implement: every request goes to the backend.
    if Request::from_client().get_path() == "/disabled" {
        run_test!(test_disabled_does_not_cache);
        return;
    }

    run_test!(test_cacheable_response_is_reused);
    run_test!(test_vary_separates_variants);
    run_test!(test_vary_uses_headers_set_by_the_guest);
    run_test!(test_uncacheable_status_is_not_cached);
    run_test!(test_no_store_is_not_cached);
    run_test!(test_private_is_not_cached);
    run_test!(test_expired_response_is_not_reused);
    run_test!(test_pass_bypasses_cache);
    run_test!(test_after_send_can_make_response_cacheable);
    run_test!(test_after_send_can_make_response_uncacheable);
    run_test!(test_after_send_can_set_vary);
    run_test!(test_cache_metadata);
}

fn test_disabled_does_not_cache() {
    let first = get("/cacheable-disabled");
    assert_ne!(get("/cacheable-disabled"), first);
}

fn test_cacheable_response_is_reused() {
    let first = get("/cacheable");
    assert_eq!(get("/cacheable"), first);
}

fn test_vary_separates_variants() {
    let a = get_with_header("/vary", "x-variant", "a");
    let b = get_with_header("/vary", "x-variant", "b");
    assert_ne!(a, b);
    assert_eq!(get_with_header("/vary", "x-variant", "a"), a);
    assert_eq!(get_with_header("/vary", "x-variant", "b"), b);
}

/// The vary rule must be evaluated against the request as modified by the guest, not the request
/// as originally constructed (see fastly/js-compute-runtime#1178).
fn test_vary_uses_headers_set_by_the_guest() {
    let mut a = Request::get("http://origin.test/vary-guest");
    a.set_header("x-variant", "a");
    let a = get_with(a);

    let mut b = Request::get("http://origin.test/vary-guest");
    b.set_header("x-variant", "a");
    b.set_header("x-variant", "b");
    assert_ne!(get_with(b), a);
}

fn test_uncacheable_status_is_not_cached() {
    let first = get("/status-500");
    assert_ne!(get("/status-500"), first);
}

fn test_no_store_is_not_cached() {
    let first = get("/no-store");
    assert_ne!(get("/no-store"), first);
}

fn test_private_is_not_cached() {
    let first = get("/private");
    assert_ne!(get("/private"), first);
}

fn test_expired_response_is_not_reused() {
    let first = get("/max-age-0");
    assert_ne!(get("/max-age-0"), first);
}

fn test_pass_bypasses_cache() {
    let first = get("/cacheable-pass");
    let mut req = Request::get("http://origin.test/cacheable-pass");
    req.set_pass(true);
    assert_ne!(get_with(req), first);
}

fn test_after_send_can_make_response_cacheable() {
    let send = || {
        let mut req = Request::get("http://origin.test/no-store-override");
        req.set_after_send(|resp| {
            resp.set_cacheable();
            resp.set_ttl(Duration::from_secs(60));
            Ok(())
        });
        get_with(req)
    };
    let first = send();
    assert_eq!(send(), first);
}

fn test_after_send_can_make_response_uncacheable() {
    let send = || {
        let mut req = Request::get("http://origin.test/cacheable-override");
        req.set_after_send(|resp| {
            resp.set_uncacheable(false);
            Ok(())
        });
        get_with(req)
    };
    let first = send();
    assert_ne!(send(), first);
}

fn test_after_send_can_set_vary() {
    let send = |variant: &str| {
        let mut req = Request::get("http://origin.test/vary-override");
        req.set_header("x-variant", variant);
        req.set_after_send(|resp| {
            resp.set_vary([&HeaderName::from_static("x-variant")]);
            Ok(())
        });
        get_with(req)
    };
    let a = send("a");
    let b = send("b");
    assert_ne!(a, b);
    assert_eq!(send("a"), a);
}

fn test_cache_metadata() {
    let req = || Request::get("http://origin.test/metadata");

    let miss = req().send(BACKEND).expect("request succeeds");
    assert_eq!(miss.get_header_str("x-cache"), Some("MISS"));

    let hit = req().send(BACKEND).expect("request succeeds");
    assert_eq!(hit.get_header_str("x-cache"), Some("HIT"));
    assert_eq!(hit.get_header_str("x-cache-hits"), Some("1"));
    let vary: Vec<&str> = hit.get_header_all_str("vary");
    assert_eq!(vary, ["x-variant"]);
}
