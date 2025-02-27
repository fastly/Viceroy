//! A guest program to test the core cache API works properly.

use fastly::cache::core::*;
use std::io::Write;
use std::time::Duration;

fn main() {
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

    // TODO: cceckman -- Without the sleep (or more precisely a Tokio yield), this doesn't succeed
    // deterministically.
    // Completing streaming of the Body doesn't mean it's synchronously committed into the cache;
    // this task can `finish` the write and then immediately resume.
    //
    // But! This is something that *implementing* the transactional API will solve, even if it
    // doesn't *use* the transactional API. The `insert` will immediately -- synchronously --
    // make the body available for streaming; so while the lookup call might get a partly-streaming
    // body, it'll still *get* the body.
    //
    std::thread::sleep(Duration::from_millis(5));
    {
        let fetch = lookup(key.clone()).execute().unwrap();
        let Some(got) = fetch else {
            panic!("did not fetch from cache")
        };
        let got = got.to_stream().unwrap().into_bytes();
        assert_eq!(&got, &body);
    }
}
