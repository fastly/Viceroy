//! A guest program to test that Simple Cache get_or_set_with works properly.

use fastly::cache::simple::{self, CacheEntry};
use std::time::Duration;

fn main() {
    // A static key is fine here because each integration test runs with a fresh in-memory cache.
    let key = "simple-cache-get-or-set-with";

    let body = simple::get_or_set_with(key, || {
        Ok(CacheEntry {
            value: "hello".into(),
            ttl: Duration::from_secs(10),
        })
    })
    .expect("first get_or_set_with succeeds")
    .expect("first get_or_set_with returns body");

    assert_eq!(body.into_string(), "hello");

    let body = simple::get_or_set_with(key, || {
        panic!("loader closure should not run on cache hit")
    })
    .expect("second get_or_set_with succeeds")
    .expect("second get_or_set_with returns body");

    assert_eq!(body.into_string(), "hello");
}
