//! Test that ManuallyFromHeaders mode preserves Transfer-Encoding header.
//!
//! With manual framing mode, the guest explicitly sets framing headers (Content-Length
//! or Transfer-Encoding) and they should be preserved rather than stripped.
//!
//! We use a streaming body so hyper doesn't know the length upfront.

use fastly::http::{header, FramingHeadersMode, HeaderValue};
use fastly::{Error, Request, Response};
use std::io::Write;

fn main() -> Result<(), Error> {
    let (mut stream, pending) = Request::post("http://example.org/")
        .with_header(header::TRANSFER_ENCODING, HeaderValue::from_static("chunked"))
        .with_framing_headers_mode(FramingHeadersMode::ManuallyFromHeaders)
        .send_async_streaming("TheOrigin")?;

    write!(stream, "test")?;
    stream.finish()?;
    pending.wait()?;

    Response::new().send_to_client();
    Ok(())
}
