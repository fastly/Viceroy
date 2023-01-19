//! A guest program to test that secret store works properly.

use fastly::SecretStore;

fn main() {
    // Check we can't get a store that does not exist
    match SecretStore::open("nonexistent") {
        Err(_) => {}
        _ => panic!(),
    }

    let store_one = SecretStore::open("store_one").unwrap();
    assert_eq!(
        store_one.get("first").unwrap().plaintext(),
        "This is some data"
    );
    assert_eq!(store_one.get("second").unwrap().plaintext(), "More data");

    match store_one.try_get("third").unwrap() {
        None => {}
        _ => panic!(),
    }
}
