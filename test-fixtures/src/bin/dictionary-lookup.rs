//! A guest program to test that dictionary lookups work properly.

use fastly::Dictionary;

fn main() {
    let animals = Dictionary::open("animals");
    assert_eq!(animals.get("dog").unwrap(), "woof");
    assert_eq!(animals.get("cat").unwrap(), "meow");
    assert_eq!(animals.get("lamp"), None);
}
