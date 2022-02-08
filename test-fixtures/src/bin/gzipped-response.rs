use fastly::{Backend, Request};
use fastly::http::request::SendError;

static HELLO_WORLD: &'static str = include_str!("../../data/hello_world");
static HELLO_WORLD_GZ: &'static [u8] = include_bytes!("../../data/hello_world.gz");

fn main() -> Result<(), SendError> {
    let echo_server = Backend::from_name("echo").expect("Could not find echo backend?");

    // Test framework sanity check: a request without the auto_decompress flag
    // should bounce back to us unchanged.
    let standard_echo = Request::put("http://127.0.0.1:9000")
        .with_header("Content-Encoding", "gzip")
        .with_body_octet_stream(HELLO_WORLD_GZ)
        .send(echo_server.clone())?;

    assert_eq!(standard_echo.get_header_str("Content-Encoding"), Some("gzip"));
    assert_eq!(standard_echo.get_content_length(), Some(HELLO_WORLD_GZ.len()));

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

    // That being said, if we set the flag to true and send it a text file,
    // we should just get it back unchanged.
    let mut yes_but_uncompressed = Request::put("http://127.0.0.1:9000")
        .with_body_octet_stream(HELLO_WORLD.as_bytes())
        .with_auto_decompress_gzip(true)
        .send(echo_server.clone())?;

    let still_unpacked = yes_but_uncompressed.take_body_str();
    assert_eq!(HELLO_WORLD, &still_unpacked);

    // A slightly odder case: We set everything up for unpacking, but we
    // don't actually send a gzip'd file. In this case, we're going to say
    // that we should get back exactly the input, even with the bogus
    // content encoding.
    let bad_gzip = Request::put("http://127.0.0.1:9000")
        .with_header("Content-Encoding", "gzip")
        .with_body_octet_stream(HELLO_WORLD.as_bytes())
        .with_auto_decompress_gzip(true)
        .send(echo_server.clone())?;

    assert_eq!(bad_gzip.get_header_str("Content-Encoding"), Some("gzip"));
    assert_eq!(bad_gzip.get_content_length(), Some(HELLO_WORLD.len()));

    Ok(())
}
