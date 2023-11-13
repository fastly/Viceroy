//! A guest program to test that edge-rate-limiting API is implemented.

//use std::time::Duration;

//use fastly::erl::{CounterDuration, Penaltybox, RateCounter, RateWindow, ERL};

fn main() {
//    let entry = "entry";

//    let rc = RateCounter::open("rc");
//    let pb = Penaltybox::open("pb");
//    let erl = ERL::open(rc, pb);

//    let not_blocked = erl
//        .check_rate(entry, 1, RateWindow::TenSecs, 100, Duration::from_secs(300))
//        .unwrap();
//    assert_eq!(not_blocked, false);

//    let rc2 = RateCounter::open("rc");
//    let rate_1 = rc2.lookup_rate(entry, RateWindow::OneSec).unwrap();
//    assert_eq!(rate_1, 0);

//    let count10 = rc2.lookup_count(entry, CounterDuration::TenSec).unwrap();
//    assert_eq!(count10, 0);

//    assert!(rc2.increment(entry, 600).is_ok());

//    let pb2 = Penaltybox::open("pb");
//    let not_in_pb = pb2.has(entry).unwrap();
//    assert_eq!(not_in_pb, false);

//    assert!(pb2.add(entry, Duration::from_secs(300)).is_ok());
}
