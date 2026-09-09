//! Regression fixture for https://github.com/fastly/Viceroy/issues/698:
//!
//! "A `transaction_lookup` on a cache entry against a key for which there is
//! an open handle hangs. This is counter to XQD, which returns immediately
//! with an error."
//!
//! The first `Transaction::lookup` on a fresh key comes back obligated to
//! insert/update, and that handle is deliberately left open (never inserted,
//! updated, or canceled). A second, blocking `Transaction::lookup` against
//! the same key then has nothing to wait for except that same never-to-be-
//! resolved obligation, so it should fail fast rather than block forever.

use fastly::cache::core::*;
use uuid::Uuid;

fn new_key() -> CacheKey {
    Uuid::new_v4().into_bytes().to_vec().into()
}

fn main() {
    let key = new_key();

    let tx1 = Transaction::lookup(key.clone())
        .execute()
        .expect("first transaction_lookup should succeed");
    assert!(tx1.must_insert_or_update());
    // `tx1` is intentionally left open here.

    // Bug: XQD returns with an error, Viceroy hangs
    // expect_err might be more idomatic but that requires Transaction: Debug
    assert!(
        Transaction::lookup(key).execute().is_err(),
        "second transaction_lookup should return an error, not hang"
    );
}
