//! A guest program to test the core cache API works properly.

use fastly::cache::core::*;
use fastly::http::HeaderName;
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
    // We don't have a way of testing "incomplete streaming results in an error"
    // in a single instance. If we fail to close the (write) body handle, the underlying host object
    // is still hanging around, ready for more writes, until the instance is done.
    // Oh well -- that's what we have collecting_body::tests::unfinished_stream for.
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
    // But a second body from the same lookup should cause an error, while the first is
    // outstanding:
    // TODO: cceckman-at-fastly: Tidy up error types. This should return InvalidOperation per the
    // API.
    // assert!(matches!(f1.to_stream(), Err(CacheError::InvalidOperation)));
    assert!(f1.to_stream().is_err());
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
        // Should return the most-recently-inserted, i.e. "goodbye"
        let r = lookup(key.clone())
            .header(&h1, "test")
            .header(&h2, "assert")
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

fn new_key() -> CacheKey {
    Uuid::new_v4().into_bytes().to_vec().into()
}
