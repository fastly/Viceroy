use bytes::Bytes;
use fastly::cache::core::*;
use http::HeaderName;
use std::io::{Read, Write};
use std::time::Duration;
use uuid::Uuid;

fn main() {
    test_racing_transactions();
    test_implicit_cancel_of_fetch();
    test_implicit_cancel_of_pending();
    test_explicit_cancel();
    test_collapse_across_vary();
    test_user_metadata();
}

fn new_key() -> CacheKey {
    Uuid::new_v4().into_bytes().to_vec().into()
}

/// Among two transactions started in order,
/// assert that the first is ready and the second is pending,
/// and convert the former to a Transaction.
fn ready_and_pending(
    busy1: PendingTransaction,
    busy2: PendingTransaction,
) -> (Transaction, PendingTransaction) {
    let b1 = busy1.pending().expect("error checking status");
    let b2 = busy2.pending().expect("error checking status");
    assert!(!b1);
    assert!(b2);
    (busy1.wait().unwrap(), busy2)
}

fn test_racing_transactions() {
    let key = new_key();

    let busy1 = Transaction::lookup(key.clone()).execute_async().unwrap();
    let busy2 = Transaction::lookup(key.clone()).execute_async().unwrap();
    let (tx, pending) = ready_and_pending(busy1, busy2);
    assert!(tx.found().is_none());
    // The first to resolve should have the obligation to insert:
    assert!(tx.must_insert());
    let mut body = tx.insert(Duration::from_secs(100)).execute().unwrap();

    // Once we've started streaming, the other transaction should complete:
    let tx = pending.wait().unwrap();
    assert!(!tx.must_insert());
    let found = tx.found().unwrap();
    assert_eq!(found.ttl(), Duration::from_secs(100));
    let mut rd_body = found.to_stream().unwrap();

    // Write the body and read it back:
    body.write(b"hello").unwrap();
    body.finish().unwrap();

    let mut read = String::new();
    rd_body.read_to_string(&mut read).unwrap();
    assert_eq!(&read, "hello");
}

fn test_implicit_cancel_of_fetch() {
    let key = new_key();

    let busy1 = Transaction::lookup(key.clone()).execute_async().unwrap();
    let busy2 = Transaction::lookup(key.clone()).execute_async().unwrap();
    let (t1, pending) = ready_and_pending(busy1, busy2);

    // Cancel via dropping:
    assert!(t1.must_insert_or_update());
    std::mem::drop(t1);
    let t2 = pending.wait().unwrap();
    assert!(t2.found().is_none());
    assert!(t2.must_insert_or_update());
}

fn test_implicit_cancel_of_pending() {
    let key = new_key();

    let busy1 = Transaction::lookup(key.clone()).execute_async().unwrap();
    let busy2 = Transaction::lookup(key.clone()).execute_async().unwrap();
    let (t1, pending) = ready_and_pending(busy1, busy2);

    // Cancel the blocked request via dropping.
    // Fun fact, this was a bug in compute platform that we fixed when writing the Viceroy
    // implementation!
    std::mem::drop(pending);
    assert!(t1.must_insert_or_update());
}

fn test_explicit_cancel() {
    let key = new_key();

    let busy1 = Transaction::lookup(key.clone()).execute_async().unwrap();
    let busy2 = Transaction::lookup(key.clone()).execute_async().unwrap();
    let (tx, pending) = ready_and_pending(busy1, busy2);

    // Cancel explicitly:
    assert!(tx.must_insert_or_update());
    tx.cancel_insert_or_update().unwrap();

    let t2 = pending.wait().unwrap();
    assert!(!t2.found().is_some());
    assert!(t2.must_insert_or_update());
}

fn test_collapse_across_vary() {
    let key = new_key();

    let header1 = HeaderName::from_static("header1");
    let header2 = HeaderName::from_static("header2");

    // Prefill with distinct vary rules, with stale responses:
    let b = insert(key.clone(), Duration::ZERO)
        .header(&header1, "value1")
        .vary_by([&header1].into_iter())
        .execute()
        .unwrap();
    b.finish().unwrap();

    let b = insert(key.clone(), Duration::ZERO)
        .header(&header2, "value2")
        .vary_by([&header2].into_iter())
        .execute()
        .unwrap();
    b.finish().unwrap();

    // vary: header2 is the most recent value.
    // If we start a transaction that matches both rules:
    let txn2 = Transaction::lookup(key.clone())
        .header(&header2, "value2")
        .header(&header1, "value1")
        .execute_async()
        .unwrap();
    // And a transaction that matches only the header1 rule:
    let txn1 = Transaction::lookup(key.clone())
        .header(&header1, "value1")
        .execute_async()
        .unwrap();

    // Are these requests collapsed?
    //
    // If we are using the most-recent-received Vary rule as a heuristic for "what do we expect the
    // next Vary rule to be", then we should *not* collapse them: the most recent vary rule is
    // `header2`, and these have distinct `header2` values.
    //
    // However, if we're saying "collapse based on any vary rule received in the past", they would
    // not be collapsed.
    //
    // We err on the side of "less latency, more requests": both of these should be outstanding,
    // because according to the most recent vary rule they are distinct.
    assert!(!txn2.pending().unwrap());
    assert!(!txn1.pending().unwrap());
}

fn test_user_metadata() {
    let key = new_key();

    let l1 = Transaction::lookup(key.clone()).execute().unwrap();

    let body = l1
        .insert(Duration::from_secs(10))
        .user_metadata(Bytes::copy_from_slice(b"hi there"))
        .execute()
        .unwrap();

    // Body not yet written, but we should be able to read the metadata right away.
    {
        let l2 = Transaction::lookup(key.clone()).execute().unwrap();
        let got = l2.found().unwrap();
        let md = got.user_metadata();
        assert_eq!(&md, b"hi there".as_slice());
    }

    body.finish().unwrap();

    {
        let l2 = Transaction::lookup(key.clone()).execute().unwrap();
        let got = l2.found().unwrap();
        let md = got.user_metadata();
        assert_eq!(&md, b"hi there".as_slice());
    }
}
