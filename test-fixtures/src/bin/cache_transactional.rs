use fastly::cache::core::*;
use std::io::{Read, Write};
use std::time::Duration;
use uuid::Uuid;

fn main() {
    test_racing_transactions();
    test_implicit_cancel();
    test_explicit_cancel();
}

fn new_key() -> CacheKey {
    Uuid::new_v4().into_bytes().to_vec().into()
}

/// Among two transactions, pick the one "ready" and the one "pending", in that order.
fn ready_and_pending(
    busy1: PendingTransaction,
    busy2: PendingTransaction,
) -> (Transaction, PendingTransaction) {
    // Exactly one should become pending:
    let (ready, pending) = loop {
        let p1 = busy1.pending().unwrap();
        let p2 = busy2.pending().unwrap();
        if !p1 {
            assert!(p2);
            break (busy1, busy2);
        }
        if !p2 {
            assert!(p1);
            break (busy2, busy1);
        }
        std::thread::sleep(Duration::from_millis(4));
    };
    (ready.wait().unwrap(), pending)
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

fn test_implicit_cancel() {
    let key = new_key();

    let busy1 = Transaction::lookup(key.clone()).execute_async().unwrap();
    let busy2 = Transaction::lookup(key.clone()).execute_async().unwrap();
    let (tx, pending) = ready_and_pending(busy1, busy2);

    // Cancel via dropping:
    assert!(tx.must_insert_or_update());
    std::mem::drop(tx);
    //let t2 = pending.wait().unwrap();
    //assert!(!t2.found().is_some());
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
