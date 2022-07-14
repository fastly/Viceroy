//! A guest program to test that dictionary lookups work properly.

use fastly::ConfigStore;

fn main() {
    let animals = ConfigStore::open("animals");
    assert_eq!(animals.get("dog").unwrap(), "woof");
    assert_eq!(animals.get("cat").unwrap(), "meow");
    assert_eq!(animals.get("lamp"), None);
}
