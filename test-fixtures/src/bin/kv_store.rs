//! A guest program to test that KV store works properly.

use fastly::kv_store::{
    KVStore,
    KVStoreError::{ItemNotFound, StoreNotFound},
};

fn main() {
    // Check we can't get a store that does not exist
    match KVStore::open("non_existant") {
        Err(StoreNotFound(_)) => {}
        _ => panic!(),
    }

    let store_one = KVStore::open("store_one").unwrap().unwrap();
    // Test that we can get data using the `data` config key
    assert_eq!(
        store_one.lookup("first").unwrap().take_body().into_string(),
        "This is some data"
    );
    // Test that we can get data from a file using the `path` config key
    assert_eq!(
        store_one
            .lookup("second")
            .unwrap()
            .take_body()
            .into_string(),
        "More data"
    );
    // Test that we can get metadata using the `metadata` config key
    assert_eq!(
        store_one.lookup("third").unwrap().metadata().unwrap(),
        "some metadata"
    );
    // Test that we cannot get metadata if it's not set
    assert_eq!(
        store_one.lookup("first").unwrap().metadata(),
        None
    );

    let empty_store = KVStore::open("empty_store").unwrap().unwrap();
    // Check that the value "bar" is not in the store
    match empty_store.lookup("bar") {
        Err(ItemNotFound) => {}
        _ => panic!(),
    }
    empty_store.insert("bar", "foo").unwrap();
    // Check that the value "bar" is now in the store
    assert_eq!(
        empty_store.lookup("bar").unwrap().take_body().into_string(),
        "foo"
    );
}
