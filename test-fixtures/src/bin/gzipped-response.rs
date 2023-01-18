use fastly::http::request::SendError;
use fastly::http::StatusCode;
use fastly::{Backend, Request};
use std::io::Read;

static HELLO_WORLD: &'static str = "hello, world!\n";
static HELLO_WORLD_GZ: &'static [u8] = include_bytes!("../../data/hello_world.gz");

fn main() -> Result<(), SendError> {
    let echo_server = Backend::from_name("echo").expect("Could not find echo backend?");

    // Test framework sanity check: a request without the auto_decompress flag
    // should bounce back to us unchanged.
    let standard_echo = Request::put("http://127.0.0.1:9000")
        .with_header("Content-Encoding", "gzip")
        .with_body_octet_stream(HELLO_WORLD_GZ)
        .send(echo_server.clone())?;

    assert_eq!(
        standard_echo.get_header_str("Content-Encoding"),
        Some("gzip")
    );
    assert_eq!(
        standard_echo.get_content_length(),
        Some(HELLO_WORLD_GZ.len())
    );

    // Similarly, if we set the auto_decompress flag to false, it should also
    // bounce back to us unchanged.
    let explicit_no = Request::put("http://127.0.0.1:9000")
        .with_header("Content-Encoding", "gzip")
        .with_body_octet_stream(HELLO_WORLD_GZ)
        .with_auto_decompress_gzip(false)
        .send(echo_server.clone())?;

    assert_eq!(explicit_no.get_header_str("Content-Encoding"), Some("gzip"));
    assert_eq!(explicit_no.get_content_length(), Some(HELLO_WORLD_GZ.len()));

    // But if we set the auto_decompress flag to true, and send a compressed
    // file, we should get the uncompressed version back
    let mut unpacked_echo = Request::put("http://127.0.0.1:9000")
        .with_header("Content-Encoding", "gzip")
        .with_body_octet_stream(HELLO_WORLD_GZ)
        .with_auto_decompress_gzip(true)
        .send(echo_server.clone())?;

    assert!(unpacked_echo.get_header("Content-Encoding").is_none());
    assert!(unpacked_echo.get_content_length().is_none());
    let hopefully_unpacked = unpacked_echo.take_body_str();
    assert_eq!(HELLO_WORLD, &hopefully_unpacked);

    // This should work when the header is "x-gzip", as well; see
    // https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#gzip.coding
    let mut xunpacked_echo = Request::put("http://127.0.0.1:9000")
        .with_header("Content-Encoding", "x-gzip")
        .with_body_octet_stream(HELLO_WORLD_GZ)
        .with_auto_decompress_gzip(true)
        .send(echo_server.clone())?;

    assert!(xunpacked_echo.get_header("Content-Encoding").is_none());
    assert!(xunpacked_echo.get_content_length().is_none());
    let xhopefully_unpacked = xunpacked_echo.take_body_str();
    assert_eq!(HELLO_WORLD, &xhopefully_unpacked);

    // The same, but now we're going to use await.
    let unpacked_echo_pending = Request::put("http://127.0.0.1:9000")
        .with_header("Content-Encoding", "gzip")
        .with_body_octet_stream(HELLO_WORLD_GZ)
        .with_auto_decompress_gzip(true)
        .send_async(echo_server.clone())?;

    let mut unpacked_echo_async = unpacked_echo_pending.wait()?;
    assert!(unpacked_echo_async.get_header("Content-Encoding").is_none());
    assert!(unpacked_echo_async.get_content_length().is_none());
    let hopefully_unpacked = unpacked_echo_async.take_body_str();
    assert_eq!(HELLO_WORLD, &hopefully_unpacked);

    // The same, but now we're going to stream the data over.
    let unpacked_stream_pending = {
        // braces to force the drop on the body
        let (mut streaming_body, pending_req) = Request::put("http://127.0.0.1:9000")
            .with_header("Content-Encoding", "gzip")
            .with_auto_decompress_gzip(true)
            .send_async_streaming(echo_server.clone())?;

        for tiny_bit in HELLO_WORLD_GZ.chunks(8) {
            streaming_body.write_bytes(tiny_bit);
        }

        streaming_body.finish().unwrap();

        pending_req
    };
    let mut unpacked_stream_async = unpacked_stream_pending.wait()?;
    assert!(unpacked_stream_async
        .get_header("Content-Encoding")
        .is_none());
    assert!(unpacked_stream_async.get_content_length().is_none());
    let hopefully_unpacked = unpacked_stream_async.take_body_str();
    assert_eq!(HELLO_WORLD, &hopefully_unpacked);

    // That being said, if we set the flag to true and send it a text file,
    // we should just get it back unchanged.
    let mut yes_but_uncompressed = Request::put("http://127.0.0.1:9000")
        .with_body_octet_stream(HELLO_WORLD.as_bytes())
        .with_auto_decompress_gzip(true)
        .send(echo_server.clone())?;

    let still_unpacked = yes_but_uncompressed.take_body_str();
    assert_eq!(HELLO_WORLD, &still_unpacked);

    // A slightly odder case: We set everything up for unpacking, but we
    // don't actually send a gzip'd file. We should get a response, and
    // it should technically be OK, but we should get an error when we
    // try to do anything with the body.
    let mut bad_gzip = Request::put("http://127.0.0.1:9000")
        .with_header("Content-Encoding", "gzip")
        .with_body_octet_stream(HELLO_WORLD.as_bytes())
        .with_auto_decompress_gzip(true)
        .send(echo_server.clone())?;

    assert!(bad_gzip.get_header("Content-Encoding").is_none());
    assert!(bad_gzip.get_content_length().is_none());
    assert_eq!(bad_gzip.get_status(), StatusCode::OK);
    let mut body = vec![];
    assert!(bad_gzip.get_body_mut().read_to_end(&mut body).is_err());

    // Just for fun, let's return the response to the caller, and make
    // sure things come out there, as well.
    Request::put("http://127.0.0.1:9000")
        .with_header("Content-Encoding", "gzip")
        .with_body_octet_stream(HELLO_WORLD_GZ)
        .with_auto_decompress_gzip(true)
        .send(echo_server.clone())?
        .send_to_client();

    Ok(())
}
