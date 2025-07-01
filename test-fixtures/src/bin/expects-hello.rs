use fastly::Request;
use http::{HeaderName, StatusCode};

fn main() {
    let mut resp = Request::get("https://fastly.com/")
        // .with_version(Version::HTTP_2)
        .with_header(HeaderName::from_static("accept-encoding"), "gzip")
        .with_auto_decompress_gzip(true)
        .send("ReturnsHello")
        .expect("can send request");
    assert_eq!(resp.get_status(), StatusCode::OK);
    let got = resp.take_body_str();
    eprintln!("got: {}", got);

    assert_eq!(&got, "hello world", "got: {}", got);
}
