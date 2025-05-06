//! A guest program to test the core cache API works properly.

use bytes::Bytes;
use fastly::cache::core::*;
use fastly::http::{HeaderName, HeaderValue};
use std::io::Write;
use std::time::Duration;
use uuid::Uuid;

fn main() {
    test_non_concurrent();
    test_concurrent();

    test_single_body();
    test_insert_stale();

    test_vary();
    test_vary_multiple();
    test_novary_ignore_headers();
    test_vary_combine();
    test_vary_subtle();

    test_user_metadata();

    test_length_from_body();
    test_inconsistent_body_length();

    // We don't have a way of testing "incomplete streaming results in an error"
    // in a single instance. If we fail to close the (write) body handle, the underlying host object
    // is still hanging around, ready for more writes, until the instance is done.
    // Oh well -- that's what we have collecting_body::tests::unfinished_stream for.
}

/// Wait for the length of a cached object to be known.
///
/// Internally in Viceroy, all writes to cached bodies are streaming writes, and are processed
/// concurrently. That means an `insert..finish()` sequence, followed by a `lookup..to_stream()`,
/// may still observe the body as "streaming" for a period of time.
///
/// If we didn't provide a known .length() along with the insert data, we can sleep+poll until the
/// length is known, implying that the whole bosy is available.
///
/// This is an ugly hack. Sorry.
fn poll_known_length(found: &Found) {
    while let None = found.known_length() {
        std::thread::sleep(Duration::from_millis(100));
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
        let mut writer = insert(key.clone(), Duration::from_secs(10))
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
        let mut writer = insert(key.clone(), Duration::from_secs(10))
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
    let f2 = lookup(key.clone())
        .execute()
        .unwrap()
        .expect("could not perform second fetch");

    // We should be able to get two bodies from two different lookups:
    let b1 = f1.to_stream().unwrap();
    let _b2 = f2.to_stream().unwrap();
    // But a second body from the same lookup should cause an error-
    // specifically an InvalidOperation error, per the API docs-
    // while the first is outstanding:
    eprintln!("{}", f1.to_stream().unwrap_err());
    assert!(matches!(f1.to_stream(), Err(CacheError::InvalidOperation)));
    std::mem::drop(b1);
    // Now the prior read from that lookup can proceed:
    let _ = f1.to_stream().unwrap();
}

fn test_insert_stale() {
    let key = new_key();

    {
        let mut writer = insert(key.clone(), Duration::from_secs(1))
            .initial_age(Duration::from_secs(2))
            .execute()
            .unwrap();
        write!(writer, "hello").unwrap();
        writer.flush().unwrap();
    }

    let found = lookup(key.clone()).execute().unwrap().unwrap();

    // NOTE: from cceckman-at-fastly:
    // The compute platform currently does not return stale objects unless
    // they have stale_while_revalidate semantics. This may change in the future.
    // Viceroy _may_ return stale objects, i.e. it presents a superset of the compute platform's
    // behavior.
    assert!(!found.is_usable());
    assert!(found.is_stale());
    assert!(found.age() >= Duration::from_secs(2));
    assert!(found.ttl() == Duration::from_secs(1));
}

fn test_vary() {
    let key = new_key();

    let header_name = HeaderName::from_static("x-viceroy-test");

    {
        let mut writer = insert(key.clone(), Duration::from_secs(1000))
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
        let mut writer = insert(key.clone(), Duration::from_secs(1000))
            .header(&h1, "test")
            .vary_by([&h1])
            .execute()
            .unwrap();
        write!(writer, "hello").unwrap();
        writer.finish().unwrap();
    }

    {
        let mut writer = insert(key.clone(), Duration::from_secs(1000))
            .header(&h2, "assert")
            .vary_by([&h2])
            .execute()
            .unwrap();
        write!(writer, "world").unwrap();
        writer.finish().unwrap();
    }

    {
        let mut writer = insert(key.clone(), Duration::from_secs(1000))
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
            // no h3
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
        let mut writer = insert(key.clone(), Duration::from_secs(1000))
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
        let mut writer = insert(key.clone(), Duration::from_secs(1000))
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
        let mut writer = insert(key.clone(), Duration::from_secs(1000))
            .vary_by([&h1])
            .header_values(&h1, [&trust, &verify])
            .execute()
            .unwrap();
        write!(writer, "hello").unwrap();
        writer.finish().unwrap();
    }

    let r = lookup(key.clone())
        .header(&h1, "trust, verify")
        .execute()
        .unwrap();
    assert!(r.is_some());

    let r = lookup(key.clone())
        .header_values(&h1, [&trust, &verify])
        .execute()
        .unwrap();
    assert!(r.is_some());

    // Order matters for HTTP header values:
    let r = lookup(key.clone())
        .header_values(&h1, [&verify, &trust])
        .execute()
        .unwrap();
    assert!(r.is_none());
}

fn test_user_metadata() {
    let key = new_key();

    let writer = insert(key.clone(), Duration::from_secs(10))
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

fn test_length_from_body() {
    let key = new_key();

    let body = "hello beautiful world".as_bytes();
    let mut writer = insert(key.clone(), Duration::from_secs(10))
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

    let fetch = lookup(key.clone()).execute().unwrap();
    let got = fetch.unwrap();
    poll_known_length(&got);
    assert_eq!(got.known_length().unwrap(), body.len() as u64);
}

fn test_inconsistent_body_length() {
    // Body length can change when streaming completes.
    let key = new_key();

    {
        let fetch = lookup(key.clone())
            .execute()
            .expect("failed initial lookup");
        assert!(fetch.is_none());
    }

    let body = "hello beautiful world".as_bytes();
    let extra_len = body.len() + 10;
    let mut writer = insert(key.clone(), Duration::from_secs(10))
        .known_length(extra_len as u64)
        .execute()
        .unwrap();

    let found = lookup(key.clone()).execute().unwrap().unwrap();
    // In metadata, so should be immediately available:
    assert_eq!(found.known_length().unwrap(), extra_len as u64);

    // Finish writing:
    writer.write_all(body).unwrap();
    writer.finish().unwrap();

    // Doesn't immediately update the length, but it will be up to date by the time we've read all
    // the bytes.
    let got = found.to_stream().unwrap().into_bytes();
    assert_eq!(got.len(), body.len());
    assert_eq!(found.known_length().unwrap(), body.len() as u64);
}

fn new_key() -> CacheKey {
    Uuid::new_v4().into_bytes().to_vec().into()
}
