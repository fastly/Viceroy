use fastly::http::{self, HeaderValue};
use fastly::{Error, Request};

fn main() -> Result<(), Error> {
    let mut req = Request::from_client();

    // Send a backend request with a synthetic body and some bad headers
    Request::post("http://example.org/TheURL")
        // Even though we set a chunked transfer encoding, the backend should see a
        // content-length. This is hardcoded XQD behavior to strip this header.
        .with_header(
            http::header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        )
        .with_body("synthetic")
        .with_pass(true)
        .send("TheOrigin")?
        .into_body_bytes();

    // Now test forwarding the non-synthetic request from the client.

    // Set a bogus content-length and forward to the backend.
    req.set_header(
        http::header::CONTENT_LENGTH,
        HeaderValue::from_static("99999"),
    );
    let mut resp = req.with_pass(true).send("TheOrigin")?;

    // Now set a bogus transfer encoding even though this should not be a chunked response
    resp.set_header(
        http::header::TRANSFER_ENCODING,
        HeaderValue::from_static("chunked"),
    );
    resp.send_to_client();
    Ok(())
}
