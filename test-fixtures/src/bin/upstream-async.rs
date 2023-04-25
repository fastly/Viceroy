//! This test fixture runs essentially the same test three different ways: using `wait`, `poll`, and `select`
//! on `PendingRequest`s.
//!
//! The test makes async requests to two different backends, each of which returns an identifying header,
//! and then checks that both responses are eventually returned and processed.

use fastly::{
    http::request::{select, PendingRequest, PollResult},
    Request, Response,
};

/// Set up async requests to two distinct backends.
fn send_async_reqs() -> (PendingRequest, PendingRequest) {
    let req1 = Request::get("http://www.example1.com/")
        .send_async("backend1")
        .unwrap();
    let req2 = Request::get("http://www.example2.com/")
        .send_async("backend2")
        .unwrap();
    (req1, req2)
}

/// A structure to process responses as they come in, and ensure that they are as expected.
struct ResponseTracker {
    /// Have we processed the response from `backend1` yet?
    response1: bool,
    /// Have we processed the response from `backend2` yet?
    response2: bool,
}

impl ResponseTracker {
    fn new() -> Self {
        Self {
            response1: false,
            response2: false,
        }
    }

    /// Digest a response, updating tracker state accordingly.
    ///
    /// Panics if a response from the given backend has already been seen, or if the response doesn't
    /// contain the expected identifying header.
    fn process(&mut self, resp: Response) {
        if resp.get_header("Backend-1-Response").is_some() {
            assert!(!self.response1);
            self.response1 = true;
        } else if resp.get_header("Backend-2-Response").is_some() {
            assert!(!self.response2);
            self.response2 = true;
        } else {
            panic!("Response did not include backend header");
        }
    }

    /// After both responses have been processed, assert that they have updated the tracker state as expected.
    fn assert_complete(self) {
        assert!(self.response1);
        assert!(self.response2);
    }
}

/// Run the test using the `wait` API, just waiting on and processing each response in sequence
fn test_wait() {
    let mut tracker = ResponseTracker::new();
    let (req1, req2) = send_async_reqs();
    tracker.process(req1.wait().unwrap());
    tracker.process(req2.wait().unwrap());
    tracker.assert_complete();
}

fn test_poll() {
    let req1 = Request::get("http://www.example1.com/")
        .send_async("backend1")
        .unwrap();

    // req1 should not be ready until a request is sent to backend2
    let PollResult::Pending(req1) = req1.poll() else {
        panic!("req1 finished too soon")
    };

    // sending req2 should unblock req1, and req2 itself should return immediately.
    let req2 = Request::get("http://www.example2.com/")
        .send_async("backend2")
        .unwrap();

    // avoid races by resolving the responses to both requests in a loop
    let mut tracker = ResponseTracker::new();
    let mut reqs = vec![req1, req2];

    while !reqs.is_empty() {
        for req in std::mem::replace(&mut reqs, Vec::new()) {
            match req.poll() {
                PollResult::Pending(req) => reqs.push(req),
                PollResult::Done(resp_result) => tracker.process(resp_result.unwrap()),
            }
        }
    }

    tracker.assert_complete();
}

/// Run the test using the `select` API, processing each response as it is returned.
fn test_select() {
    let mut tracker = ResponseTracker::new();
    let (req1, req2) = send_async_reqs();
    let mut reqs = vec![req1, req2];

    while !reqs.is_empty() {
        let (resp_result, rest) = select(reqs);
        tracker.process(resp_result.unwrap());
        reqs = rest;
    }

    tracker.assert_complete();
}

fn main() {
    test_wait();
    test_poll();
    test_select();

    // If we made it through the gauntlet above without panicking, we're good: return 200 OK
    Response::from_status(200).send_to_client();
}
