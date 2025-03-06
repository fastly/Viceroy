//! A guest program to test the core cache API works properly.

use fastly::cache::core::*;
use std::io::Write;
use std::time::Duration;

fn test_non_concurrent() {
    let key = CacheKey::from_static("hello".as_bytes());

    {
        let fetch = lookup(key.clone())
            .execute()
            .expect("failed initial lookup");
        assert!(fetch.is_none());
    }

    let body = "world".as_bytes();
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

fn main() {
    test_non_concurrent();
}
