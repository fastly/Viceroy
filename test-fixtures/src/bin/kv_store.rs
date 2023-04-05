//! A guest program to test that object store works properly.

use fastly::ObjectStore;
use fastly::object_store::ObjectStoreError::ObjectStoreNotFound;

fn main() {
    // Check we can't get a store that does not exist
    match ObjectStore::open("non_existant") {
        Err(ObjectStoreNotFound(_)) => {},
        _ => panic!(),
    }

    let store_one = ObjectStore::open("store_one").unwrap().unwrap();
    // Test that we can get data using the `data` config key
    assert_eq!(
        store_one.lookup_str("first").unwrap().unwrap(),
        "This is some data"
    );
    // Test that we can get data from a file using the `path` config key
    assert_eq!(
        store_one.lookup_str("second").unwrap().unwrap(),
        "More data"
    );

    let mut empty_store = ObjectStore::open("empty_store").unwrap().unwrap();
    // Check that the value "bar" is not in the store
    assert_eq!(empty_store.lookup_str("bar"), Ok(None));
    empty_store.insert("bar", "foo").unwrap();
    // Check that the value "bar" is now in the store
    assert_eq!(empty_store.lookup_str("bar").unwrap().unwrap(), "foo");
}
