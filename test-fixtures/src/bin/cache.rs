//! A guest program to test the core cache API works properly.

use bytes::Bytes;
use fastly::cache::core::*;
use fastly::http::{HeaderName, HeaderValue};
use std::io::{Read, Write};
use std::time::Duration;
use uuid::Uuid;

/// Run a test function with wrapped logging.
/// This makes it easy to tell what test failed when run on Compute Platform.
macro_rules! run_test {
    ($name:ident) => {{
        eprintln!("running test: {}", stringify!($name));
        $name();
        eprintln!("completed test: {}", stringify!($name));
    }};
}

fn main() {
    let service = std::env::var("FASTLY_SERVICE_VERSION").unwrap();
    eprintln!("Running tests; version {service}");

    run_test!(test_non_concurrent);
    run_test!(test_concurrent);

    run_test!(test_single_body);
    run_test!(test_insert_stale);
    run_test!(test_edge_expired);
    run_test!(test_edge_expires_after_ttl);

    run_test!(test_vary);
    run_test!(test_vary_multiple);
    run_test!(test_novary_ignore_headers);
    run_test!(test_vary_subtle);
    run_test!(test_vary_combine);

    run_test!(test_length_from_body);
    run_test!(test_inconsistent_body_length);

    run_test!(test_user_metadata);
    run_test!(test_service_id);

    run_test!(test_stale_while_revalidate);
    run_test!(test_keyed_purge);
    run_test!(test_soft_purge);
    run_test!(test_purge_variant);

    run_test!(test_racing_transactions);
    run_test!(test_implicit_cancel_of_fetch);
    run_test!(test_implicit_cancel_of_pending);
    run_test!(test_explicit_cancel);
    run_test!(test_collapse_across_vary);

    run_test!(test_stream_back);

    run_test!(test_range_request_unsupported);

    eprintln!("Completed all tests for version {service}")
}

fn new_key() -> CacheKey {
    Uuid::new_v4().into_bytes().to_vec().into()
}

/// Among two transactions started in order,
/// assert that the first is ready and the second is pending,
/// and convert the former to a Transaction.
fn ready_and_pending(
    busy1: PendingTransaction,
    busy2: PendingTransaction,
) -> (Transaction, PendingTransaction) {
    let b1 = busy1.pending().expect("error checking status");
    let b2 = busy2.pending().expect("error checking status");
    assert!(!b1);
    assert!(b2);
    (busy1.wait().unwrap(), busy2)
}

/// Wait for the length of a cached object to be known.
///
/// Internally in Viceroy, all writes to cached bodies are streaming writes, and are processed
/// concurrently. That means an `insert..finish()` sequence, followed by a `lookup..to_stream()`,
/// may still observe the body as "streaming" for a period of time.
///
/// If we didn't provide a known .length() along with the insert data, we can sleep+poll until the
/// length is known, implying that the whole body is available.
///
/// Note that we have to do the whole lookup in order to get the result; the metadata can't change
/// from under a Found.
///
/// This is an ugly hack. Sorry.
fn poll_known_length(key: &CacheKey) -> Found {
    loop {
        if let Some(v) = lookup(key.clone())
            .execute()
            .expect("lookup should not generate error")
        {
            if v.known_length().is_some() {
                return v;
            }
        }
        std::thread::sleep(Duration::from_millis(101));
    }
}

fn test_non_concurrent() {
    let key = new_key();

    {
        let fetch = lookup(key.clone())
            .execute()
            .expect("failed initial lookup");
        assert!(fetch.is_none());
    }

    let body = "hello world".as_bytes();
    {
        let mut writer = insert(key.clone(), Duration::from_secs(101))
            .known_length(body.len() as u64)
            .execute()
            .unwrap();
        writer.write_all(body).unwrap();
        writer.finish().unwrap();
    }

    {
        let fetch = lookup(key.clone()).execute().unwrap();
        let Some(got) = fetch else {
            panic!("did not fetch from cache")
        };
        let got = got.to_stream().unwrap().into_bytes();
        assert_eq!(&got, &body);
    }
}

fn test_concurrent() {
    let key = new_key();

    {
        let fetch = lookup(key.clone())
            .execute()
            .expect("failed initial lookup");
        assert!(fetch.is_none());
    }

    let mut writer = insert(key.clone(), Duration::from_secs(525600 * 60))
        .execute()
        .unwrap();

    let fetch: Found = lookup(key.clone()).execute().unwrap().unwrap();
    assert!(fetch.is_usable());
    assert!(!fetch.is_stale());
    let mut body = fetch.to_stream().unwrap();
    let mut body = body.read_chunks(6);

    write!(writer, "hello ").unwrap();
    writer.flush().unwrap();

    // This appears to be the only read mechanism that won't block for more.
    let hello = body.next().unwrap().unwrap();
    assert_eq!(hello, b"hello ");

    write!(writer, "world").unwrap();
    writer.finish().unwrap();

    let cached = body.next().unwrap().unwrap();
    assert_eq!(cached, b"world");

    assert!(body.next().is_none());
}

fn test_single_body() {
    let key = new_key();

    let body = "hello world".as_bytes();
    {
        let mut writer = insert(key.clone(), Duration::from_secs(102))
            .known_length(body.len() as u64)
            .execute()
            .unwrap();
        writer.write_all(body).unwrap();
        writer.finish().unwrap();
    }

    let f1 = lookup(key.clone())
        .execute()
        .unwrap()
        .expect("could not perform first fetch");

    let b1 = f1.to_stream().unwrap();

    // Reading a second body from the same Found results in an error, as documented:
    assert!(matches!(f1.to_stream(), Err(CacheError::InvalidOperation)));

    // If the existing body is read out and closed...
    let v1 = b1.into_bytes();
    // A new body can be read:
    let b2 = f1.to_stream().unwrap();

    // TODO: This is a difference between compute platform and Viceroy.
    // In Viceroy, it's sufficient to close the body, then the read can proceed:
    if std::env::var("FASTLY_HOSTNAME").unwrap() == "localhost" {
        b2.into_handle().close().unwrap();
        let b3 = f1
            .to_stream()
            .expect("should be able to re-read body after close of existing body");
        let v3 = b3.into_bytes();
        assert_eq!(&v1, &v3);
    } else {
        b2.into_handle().close().unwrap();
        // In Compute Platform, the body must complete:
        f1.to_stream()
            .expect_err("should be able to re-read body after close of existing body");
    }
}

fn test_insert_stale() {
    let key = new_key();

    {
        let mut writer = insert(key.clone(), Duration::from_secs(1))
            .initial_age(Duration::from_secs(2))
            .execute()
            .unwrap();
        write!(writer, "hello").unwrap();
        writer.finish().unwrap();
    }

    let Some(found) = lookup(key.clone()).execute().unwrap() else {
        // Compute platform only returns stale results if the object is in the stale-while-revalidate period;
        // it would return here.
        return;
    };
    // In Viceroy, you may get a stale result- but will still tell you it's stale.
    assert!(!found.is_usable());
    assert!(found.is_stale());
    assert!(found.age() >= Duration::from_secs(2));
}

fn test_edge_expired() {
    let key = new_key();

    // Expired on the edge, but not for users.
    {
        let mut writer = insert(key.clone(), Duration::from_secs(103))
            .initial_age(Duration::from_secs(2))
            .deliver_node_max_age(Duration::from_secs(1))
            .execute()
            .unwrap();
        write!(writer, "hello").unwrap();
        writer.finish().unwrap();
    }

    // According to current Compute Platform behavior... still fresh!
    let found = lookup(key.clone())
        .execute()
        .unwrap()
        .expect("still considered fresh");
    assert!(found.is_usable());
    assert!(!found.is_stale());
    assert!(found.age() >= Duration::from_secs(2));
    assert!(
        found.ttl() > Duration::from_secs(1),
        "got ttl: {}",
        found.ttl().as_secs_f32()
    );
}

fn test_edge_expires_after_ttl() {
    let key = new_key();

    // Error for the delivery max age to be greater than the TTL.
    let result = insert(key.clone(), Duration::from_secs(1))
        .deliver_node_max_age(Duration::from_secs(104))
        .execute();
    if !result.is_err() {
        panic!("error to provide deliver_node_max_age > ttl");
    }
}

fn test_vary() {
    let key = new_key();

    let header_name = HeaderName::from_static("x-viceroy-test");

    {
        let mut writer = insert(key.clone(), Duration::from_secs(105))
            .header(&header_name, "foo")
            .vary_by([&header_name])
            .execute()
            .unwrap();
        write!(writer, "hello").unwrap();
        writer.finish().unwrap();
    }

    // Lookup with just the key should return "not found";
    // the request's headers don't match the rule.
    let r1 = lookup(key.clone()).execute().unwrap();
    assert!(r1.is_none());

    // Lookup with the key & matching header value should work:
    let r2 = lookup(key.clone())
        .header(&header_name, "foo")
        .execute()
        .unwrap();
    assert!(r2.is_some());

    // Lookup with the key & non-matching header value should be "not found":
    let r3 = lookup(key.clone())
        .header(&header_name, "bar")
        .execute()
        .unwrap();
    assert!(r3.is_none());
}

fn test_vary_multiple() {
    let key = new_key();

    // Set up three objects with different vary_by headers:
    // The first varies by h1 and expects "test", with body "hello"
    // The second varies by h2 and expects "assert", with body "world"
    // The third varies by h3 and expects nothing, with body "goodbye"
    let h1 = HeaderName::from_static("x-viceroy-test");
    let h2 = HeaderName::from_static("x-viceroy-assert");
    let h3 = HeaderName::from_static("x-viceroy-verify");

    {
        let mut writer = insert(key.clone(), Duration::from_secs(106))
            .header(&h1, "test")
            .vary_by([&h1])
            .execute()
            .unwrap();
        write!(writer, "hello").unwrap();
        writer.finish().unwrap();
    }

    {
        let mut writer = insert(key.clone(), Duration::from_secs(107))
            .header(&h2, "assert")
            .vary_by([&h2])
            .execute()
            .unwrap();
        write!(writer, "world").unwrap();
        writer.finish().unwrap();
    }

    {
        let mut writer = insert(key.clone(), Duration::from_secs(108))
            .vary_by([&h3])
            .execute()
            .unwrap();
        write!(writer, "goodbye").unwrap();
        writer.finish().unwrap();
    }

    {
        // Match values for all three.
        // Should return the most-recently-inserted, i.e. "goodbye".
        // Note: reversed order of headers in the request.
        let r = lookup(key.clone())
            .header(&h2, "assert")
            .header(&h1, "test")
            // No h3; note that H3 doesn't have a value when inserted
            .execute()
            .unwrap();
        let body = r.unwrap().to_stream().unwrap().into_string();
        assert_eq!(&body, "goodbye");
    }

    {
        // Match values for just the first.
        let r = lookup(key.clone())
            .header(&h1, "test")
            .header(&h3, "verify")
            .execute()
            .unwrap();
        let body = r.unwrap().to_stream().unwrap().into_string();
        assert_eq!(&body, "hello");
    }

    {
        // Match values for the last, by providing no headers.
        let r = lookup(key.clone()).execute().unwrap();
        let body = r.unwrap().to_stream().unwrap().into_string();
        assert_eq!(&body, "goodbye");
    }
}

fn test_novary_ignore_headers() {
    let key = new_key();

    // The response and request have headers included, but don't have vary_by.
    // That means the headers shouldn't matter.
    let h1 = HeaderName::from_static("x-viceroy-test");
    {
        let mut writer = insert(key.clone(), Duration::from_secs(109))
            .header(&h1, "test")
            .execute()
            .unwrap();
        write!(writer, "hello").unwrap();
        writer.finish().unwrap();
    }

    {
        // Header present: should retrieve the result.
        let r = lookup(key.clone()).header(&h1, "test").execute().unwrap();
        let body = r.unwrap().to_stream().unwrap().into_string();
        assert_eq!(&body, "hello");
    }

    {
        // Header missing: no vary_by, so shouldn't matter.
        let r = lookup(key.clone()).execute().unwrap();
        let body = r.unwrap().to_stream().unwrap().into_string();
        assert_eq!(&body, "hello");
    }
}

fn test_vary_subtle() {
    let key = new_key();

    // A very subtle (hah!) case: can one header run in to another?

    let h1 = HeaderName::from_static("x-viceroy-test");
    let h2 = HeaderName::from_static("x-viceroy-assert");
    {
        let mut writer = insert(key.clone(), Duration::from_secs(110))
            .vary_by([&h1, &h2])
            .header(&h1, "test")
            .header(&h2, "assert")
            .execute()
            .unwrap();
        write!(writer, "hello").unwrap();
        writer.finish().unwrap();
    }

    // We want to try to insert a tricky header *value*...
    let v: Result<HeaderValue, _> = "test\r\nx-viceroy-assert: assert".try_into();
    // ...but that won't work:
    v.unwrap_err();
    // If it did, we would do this:
    //let request = lookup(key.clone()).header(&h1, v);
    //let result = request.execute().unwrap();
    //assert!(result.is_none())
}

fn test_vary_combine() {
    let key = new_key();

    let trust = HeaderValue::from_static("trust");
    let verify = HeaderValue::from_static("verify");

    let h1 = HeaderName::from_static("x-viceroy-test");
    {
        let mut writer = insert(key.clone(), Duration::from_secs(111))
            .vary_by([&h1])
            .header_values(&h1, [&trust, &verify])
            .execute()
            .unwrap();
        write!(writer, "hello").unwrap();
        writer.finish().unwrap();
    }

    let r = lookup(key.clone())
        .header_values(&h1, [&trust, &verify])
        .execute()
        .unwrap();
    assert!(r.is_some());

    // A comma-delimited value is considered distinct from multiple values.
    // This may lead to suboptimal caching in some cases, but is safe from information leakage.
    let r = lookup(key.clone())
        .header(&h1, "trust, verify")
        .execute()
        .unwrap();
    assert!(r.is_none());

    // Order matters for HTTP header values:
    let r = lookup(key.clone())
        .header_values(&h1, [&verify, &trust])
        .execute()
        .unwrap();
    assert!(r.is_none());
}

fn test_user_metadata() {
    let key = new_key();

    let writer = insert(key.clone(), Duration::from_secs(112))
        .user_metadata(Bytes::copy_from_slice(b"hi there"))
        .execute()
        .unwrap();

    // Body not yet written, but we should be able to read the metadata right away.
    {
        let got = lookup(key.clone())
            .execute()
            .unwrap()
            .expect("did not fetch streaming");
        let md = got.user_metadata();
        assert_eq!(&md, b"hi there".as_slice());
    }

    writer.finish().unwrap();

    {
        let got = lookup(key.clone())
            .execute()
            .unwrap()
            .expect("did not fetch streaming");
        let md = got.user_metadata();
        assert_eq!(&md, b"hi there".as_slice());
    }
}

fn test_service_id() {
    let key = new_key();

    let Err(e) = insert(key.clone(), Duration::from_secs(10))
        .on_behalf_of("NRF5TZWykaNWzn1WCb7hj2")
        .execute()
    else {
        panic!("unexpected success at using on_behalf_of");
    };

    assert!(matches!(e, CacheError::Unsupported), "{}", e);
}

fn test_length_from_body() {
    // We can get a known length from "just" streaming the body.
    let key = new_key();

    let body = "hello beautiful world".as_bytes();
    let mut writer = insert(key.clone(), Duration::from_secs(115))
        .execute()
        .unwrap();
    {
        let fetch = lookup(key.clone()).execute().unwrap();
        // We haven't streamed the body, so the length is unknown.
        let got = fetch.unwrap();
        assert!(got.known_length().is_none());
    }
    writer.write_all(body).unwrap();
    writer.finish().unwrap();

    let got = poll_known_length(&key);
    assert_eq!(got.known_length().unwrap(), body.len() as u64);
}

fn test_inconsistent_body_length() {
    // If a body length is provided, writing an inconsistent length should generate an error.
    let key = new_key();

    {
        let fetch = lookup(key.clone())
            .execute()
            .expect("failed initial lookup");
        assert!(fetch.is_none());
    }

    // Short write:
    {
        let body = "hello beautiful world".as_bytes();
        let extra_len = body.len() + 10;
        let mut writer = insert(key.clone(), Duration::from_secs(116))
            .known_length(extra_len as u64)
            .execute()
            .unwrap();

        let found = lookup(key.clone()).execute().unwrap().unwrap();
        // In metadata, so should be immediately available:
        assert_eq!(found.known_length().unwrap(), extra_len as u64);

        // Finish writing, but it's a short write:
        writer.write_all(body).unwrap();
        writer.finish().unwrap();

        let mut got = found.to_stream().unwrap();
        let mut data = Vec::new();
        got.read_to_end(&mut data).unwrap_err();
    }

    // Long write:
    {
        let body = "hello beautiful world".as_bytes();
        let extra_len = body.len() - 3;
        let mut writer = insert(key.clone(), Duration::from_secs(10))
            .known_length(extra_len as u64)
            .execute()
            .unwrap();

        let found = lookup(key.clone()).execute().unwrap().unwrap();
        assert_eq!(found.known_length().unwrap(), extra_len as u64);
        writer.write_all(body).unwrap();
        writer.finish().unwrap();

        let mut got = found.to_stream().unwrap();
        let mut data = Vec::new();
        got.read_to_end(&mut data).unwrap_err();
    }
}

fn test_stale_while_revalidate() {
    let key = new_key();
    {
        let mut writer = insert(key.clone(), Duration::from_secs(1))
            .initial_age(Duration::from_secs(2))
            .user_metadata(Bytes::from_static(b"version 1"))
            .stale_while_revalidate(Duration::from_secs(100))
            .execute()
            .unwrap();
        write!(writer, "hello").unwrap();
        writer.finish().unwrap();
    }

    // A normal lookup will get the stale result, but can't pick up an obligation.
    {
        let found = lookup(key.clone()).execute().unwrap().unwrap();
        assert!(found.is_stale());
        assert!(found.is_usable());
    }

    // Transactional lookups will all complete, with the stale result.
    let txn1 = Transaction::lookup(key.clone()).execute().unwrap();
    let txn2 = Transaction::lookup(key.clone()).execute().unwrap();
    for txn in [&txn1, &txn2] {
        assert!(txn.found().unwrap().is_stale());
        assert!(txn.found().unwrap().is_usable());
        assert_eq!(
            txn.found().unwrap().user_metadata().iter().as_slice(),
            b"version 1"
        );
    }

    // One of these should get the obligation:
    eprintln!("1 must_insert_or_update: {}", txn1.must_insert_or_update());
    eprintln!("2 must_insert_or_update: {}", txn2.must_insert_or_update());
    eprintln!("1 must_insert: {}", txn1.must_insert());
    eprintln!("2 must_insert: {}", txn2.must_insert());

    // Update without modifying the body:
    txn1.update(Duration::from_secs(100))
        .user_metadata(Bytes::from_static(b"version 2"))
        .execute()
        .unwrap();

    // A new request should read the new metadata:
    let found = lookup(key.clone()).execute().unwrap().unwrap();
    assert_eq!(found.user_metadata().iter().as_slice(), b"version 2");
    // And the original body:
    let body = found.to_stream().unwrap().into_string();
    assert_eq!(&body, "hello");
}

fn test_keyed_purge() {
    fn write_key(surrogate_keys: impl IntoIterator<Item = &'static str>, value: &str) -> Bytes {
        let key = new_key();
        let mut writer = insert(key.clone(), Duration::from_secs(100))
            .surrogate_keys(surrogate_keys)
            .execute()
            .unwrap();
        writer.write_all(value.as_bytes()).unwrap();
        writer.finish().unwrap();
        key
    }

    let key1 = write_key(["keyA", "keyB"], "value1");
    let key2 = write_key(["keyA"], "value2");
    let key3 = write_key(["keyB"], "value3");
    assert!(lookup(key1.clone()).execute().unwrap().is_some());
    assert!(lookup(key2.clone()).execute().unwrap().is_some());
    assert!(lookup(key3.clone()).execute().unwrap().is_some());

    fastly::http::purge::purge_surrogate_key("keyB").unwrap();
    assert!(lookup(key1).execute().unwrap().is_none());
    assert!(lookup(key2).execute().unwrap().is_some());
    assert!(lookup(key3).execute().unwrap().is_none());
}

fn test_soft_purge() {
    fn write_key(surrogate_keys: impl IntoIterator<Item = &'static str>, value: &str) -> Bytes {
        let key = new_key();
        let mut writer = insert(key.clone(), Duration::from_secs(100))
            .surrogate_keys(surrogate_keys)
            .execute()
            .unwrap();
        writer.write_all(value.as_bytes()).unwrap();
        writer.finish().unwrap();
        key
    }

    let key1 = write_key(["keyA", "keyB"], "value1");
    let key2 = write_key(["keyA"], "value2");
    let key3 = write_key(["keyB"], "value3");

    fastly::http::purge::soft_purge_surrogate_key("keyB").unwrap();
    // Compute Platform will return stale data that has been soft-purged, if it's still within the
    // TTL.
    assert!(lookup(key1)
        .execute()
        .unwrap()
        .expect("is found")
        .is_stale());
    assert!(lookup(key3)
        .execute()
        .unwrap()
        .expect("is found")
        .is_stale());
    // key2 is untouched:
    assert!(!lookup(key2)
        .execute()
        .unwrap()
        .expect("is found")
        .is_stale());
}

fn test_purge_variant() {
    let header = HeaderName::from_static("test");
    let key = new_key();
    {
        let mut writer = insert(key.clone(), Duration::from_secs(100))
            .surrogate_keys(["keyA"])
            .header(header.clone(), "value1")
            .vary_by([&header])
            .execute()
            .unwrap();
        writer.write_all(b"value1").unwrap();
        writer.finish().unwrap();
    }
    {
        let mut writer = insert(key.clone(), Duration::from_secs(100))
            .surrogate_keys(["keyB"])
            .header(header.clone(), "value2")
            .vary_by([&header])
            .execute()
            .unwrap();
        writer.write_all(b"value2").unwrap();
        writer.finish().unwrap();
    }

    // Self-test: we can read these back before we purge...
    for variant in ["value1", "value2"] {
        assert_eq!(
            lookup(key.clone())
                .header(header.clone(), variant)
                .execute()
                .unwrap()
                .unwrap()
                .to_stream()
                .unwrap()
                .into_string(),
            variant
        );
    }

    fastly::http::purge::purge_surrogate_key("keyA").unwrap();

    // keyA was purged:
    assert!(lookup(key.clone())
        .header(header.clone(), "value1")
        .execute()
        .unwrap()
        .is_none());

    // keyB is fine:
    assert_eq!(
        lookup(key.clone())
            .header(header.clone(), "value2")
            .execute()
            .unwrap()
            .unwrap()
            .to_stream()
            .unwrap()
            .into_string(),
        "value2"
    );
}

fn test_racing_transactions() {
    let key = new_key();

    let busy1 = Transaction::lookup(key.clone()).execute_async().unwrap();
    let busy2 = Transaction::lookup(key.clone()).execute_async().unwrap();
    let (tx, pending) = ready_and_pending(busy1, busy2);
    assert!(tx.found().is_none());
    // The first to resolve should have the obligation to insert:
    assert!(tx.must_insert());
    let mut body = tx.insert(Duration::from_secs(125)).execute().unwrap();

    // Once we've started streaming, the other transaction should complete:
    let tx = pending.wait().unwrap();
    assert!(!tx.must_insert());
    let found = tx.found().unwrap();
    assert_eq!(found.ttl(), Duration::from_secs(125));
    let mut rd_body = found.to_stream().unwrap();

    // Write the body and read it back:
    body.write(b"hello").unwrap();
    body.finish().unwrap();

    let mut read = String::new();
    rd_body.read_to_string(&mut read).unwrap();
    assert_eq!(&read, "hello");
}

fn test_implicit_cancel_of_fetch() {
    let key = new_key();

    let busy1 = Transaction::lookup(key.clone()).execute_async().unwrap();
    let busy2 = Transaction::lookup(key.clone()).execute_async().unwrap();
    let (t1, pending) = ready_and_pending(busy1, busy2);

    // Cancel via dropping:
    assert!(t1.must_insert_or_update());
    std::mem::drop(t1);
    let t2 = pending.wait().unwrap();
    assert!(t2.found().is_none());
    assert!(t2.must_insert_or_update());
}

fn test_implicit_cancel_of_pending() {
    let key = new_key();

    let busy1 = Transaction::lookup(key.clone()).execute_async().unwrap();
    let busy2 = Transaction::lookup(key.clone()).execute_async().unwrap();
    let (t1, pending) = ready_and_pending(busy1, busy2);

    // Should be safe to drop `pending` while t1 is outstanding.
    // Note: Compute Platform previously required
    //  std::mem::drop(t1);
    // before drop(pending), so this is a regression test for Compute.
    std::mem::drop(pending);
    assert!(t1.must_insert_or_update());
}

fn test_explicit_cancel() {
    let key = new_key();

    let busy1 = Transaction::lookup(key.clone()).execute_async().unwrap();
    let busy2 = Transaction::lookup(key.clone()).execute_async().unwrap();
    let (tx, pending) = ready_and_pending(busy1, busy2);

    // Cancel explicitly:
    assert!(tx.must_insert_or_update());
    tx.cancel_insert_or_update().unwrap();

    let t2 = pending.wait().unwrap();
    assert!(!t2.found().is_some());
    assert!(t2.must_insert_or_update());
}

fn test_collapse_across_vary() {
    let key = new_key();

    let header1 = HeaderName::from_static("header1");
    let header2 = HeaderName::from_static("header2");

    // Prefill with distinct vary rules, with stale responses:
    let b = insert(key.clone(), Duration::ZERO)
        .header(&header1, "value1")
        .vary_by([&header1].into_iter())
        .execute()
        .unwrap();
    b.finish().unwrap();

    let b = insert(key.clone(), Duration::ZERO)
        .header(&header2, "value2")
        .vary_by([&header2].into_iter())
        .execute()
        .unwrap();
    b.finish().unwrap();

    // vary: header2 is the most recent value.
    // If we start a transaction that matches both rules:
    let txn2 = Transaction::lookup(key.clone())
        .header(&header2, "value2")
        .header(&header1, "value1")
        .execute_async()
        .unwrap();
    // And a transaction that matches only the header1 rule:
    let txn1 = Transaction::lookup(key.clone())
        .header(&header1, "value1")
        .execute_async()
        .unwrap();

    // Are these requests collapsed?
    //
    // If we are using the most-recent-received Vary rule as a heuristic for "what do we expect the
    // next Vary rule to be", then we should *not* collapse them: the most recent vary rule is
    // `header2`, and these have distinct `header2` values.
    //
    // However, if we're saying "collapse based on any vary rule received in the past", they would
    // not be collapsed.
    //
    // We err on the side of "less latency, more requests": both of these should be outstanding,
    // because according to the most recent vary rule they are distinct.
    assert!(!txn2.pending().unwrap());
    assert!(!txn1.pending().unwrap());
}

fn test_stream_back() {
    let key = new_key();

    let body = "hello beautiful world";

    let tx = Transaction::lookup(key.clone()).execute().unwrap();
    assert!(tx.found().is_none());
    assert!(tx.must_insert_or_update());

    let (mut writer, found) = tx
        .insert(Duration::from_secs(126))
        .execute_and_stream_back()
        .unwrap();

    writer.write_all(body.as_bytes()).unwrap();
    writer.finish().unwrap();

    let got = found.to_stream().unwrap().into_string();
    assert_eq!(&got, &body);
}

fn test_range_request_unsupported() {
    let key = new_key();

    let body = "abc123def".as_bytes();
    {
        let mut writer = insert(key.clone(), Duration::from_secs(10))
            .known_length(body.len() as u64)
            .execute()
            .unwrap();
        writer.write_all(body).unwrap();
        writer.finish().unwrap();
    }

    let fetch = lookup(key.clone()).execute().unwrap();
    let Some(got) = fetch else {
        panic!("did not fetch from cache")
    };
    let got = got.to_stream_from_range(Some(3), Some(5));
    if !got.is_err() {
        panic!("range requests are not yet supported in Viceroy");
    }
}
