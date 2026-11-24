//! Exercise reason phrases through the Rust SDK.
use fastly::{Error, Request, Response};

/// Verify the response's reason phrase using the SDK API methods:
fn check_reason_phrase(resp: &Response, expected: &[u8]) {
    assert_eq!(resp.get_reason_phrase(expected.len()).unwrap(), expected);
    assert_eq!(
        resp.get_reason_phrase_lossy(expected.len()).unwrap(),
        String::from_utf8_lossy(expected)
    );

    if expected.is_empty() {
        return;
    }

    for max_len in [0, expected.len() - 1] {
        let err = resp.get_reason_phrase(max_len).unwrap_err();
        assert_eq!(err.needed_buf_size, expected.len());
    }
}

#[fastly::main]
fn main(req: Request) -> Result<Response, Error> {
    let mut resp = req.with_pass(true).send("TheOrigin")?;
    let expected = resp.take_body_bytes();

    // Response has expected phrase:
    check_reason_phrase(&resp, expected.as_slice());

    // And a synthetic response has no reason phrase:
    let synthetic = fastly::handle::ResponseHandle::new();
    assert!(synthetic.get_reason_phrase(0).unwrap().is_empty());

    Ok(Response::from_status(200))
}
