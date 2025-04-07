//! A guest program to test the core cache API works properly.

use fastly::cache::core::*;
use std::io::Write;
use std::time::Duration;
use uuid::Uuid;

fn main() {
    test_non_concurrent();
    test_concurrent();
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

    let mut writer = insert(key.clone(), Duration::from_secs(10))
        .execute()
        .unwrap();

    let fetch: Found = lookup(key.clone()).execute().unwrap().unwrap();
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

fn new_key() -> CacheKey {
    Uuid::new_v4().into_bytes().to_vec().into()
}
