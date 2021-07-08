//! Exercise calculation of Content-Length.
use fastly::handle::{BodyHandle, RequestHandle, ResponseHandle};
use fastly::http::{header, Url};
use fastly::log::set_panic_endpoint;
use fastly::Error;
use std::io::{Read, Write};

fn main() -> Result<(), Error> {
    set_panic_endpoint("PANIC!")?;
    let mut r = RequestHandle::new();
    r.set_url(&Url::parse("http://origin.org/")?);
    let b = BodyHandle::new();
    let (resp, mut body) = r.send(b, "TheOrigin")?;

    assert_eq!(resp.get_status(), 200);

    assert_eq!(
        resp.get_header_value(&header::CONTENT_LENGTH, 10)?
            .expect("response should have Content-Length"),
        "20"
    );

    let mut buf = [0; 4];

    body.read_exact(&mut buf).expect("read should have succeed");

    // Copy some bytes from the upstream response
    let mut newb = BodyHandle::from(&buf[..]); // 4

    // Add some synthetic bytes
    newb.write_all(b"12345")?; // ; 4 + 5

    // Append a synthetic body
    newb.append(BodyHandle::from("xyz")); // 4 + 5 + 3

    // Append the rest of the upstream body
    newb.append(body); // 4 + 5 + 3 + (20-4) = 28

    ResponseHandle::new().send_to_client(newb);

    Ok(())
}
