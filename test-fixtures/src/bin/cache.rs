//! A guest program to test the core cache API works properly.

use fastly::cache::core::*;
use std::io::Write;
use std::time::Duration;
use uuid::Uuid;

fn main() {
    test_non_concurrent();
    test_concurrent();

    test_single_body();
    test_insert_stale();
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
    // The compute platform currently does not return stale objects
    // they have stale_while_revalidate semantics. This may change in the future.
    // Viceroy _may_ return stale objects, i.e. it presents a superset of the compute platform's
    // behavior.
    assert!(!found.is_usable());
    assert!(found.is_stale());
    assert!(found.age() >= Duration::from_secs(2));
    assert!(found.ttl() == Duration::from_secs(1));
}

fn new_key() -> CacheKey {
    Uuid::new_v4().into_bytes().to_vec().into()
}
