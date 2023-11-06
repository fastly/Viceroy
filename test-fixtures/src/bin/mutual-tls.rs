use base64::engine::{general_purpose, Engine};
use fastly::http::StatusCode;
use fastly::secret_store::Secret;
use fastly::{Backend, Error, Request, Response};
use std::str::FromStr;

/// Pass everything from the downstream request through to the backend, then pass everything back
/// from the upstream request to the downstream response.
fn main() -> Result<(), Error> {
    let client_req = Request::from_client();
    let certificate = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/data/client.crt"));
    let key_bytes = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/data/client.key"));
    let key_secret = Secret::from_bytes(key_bytes.to_vec()).expect("can inject key");

    let Some(port_str) = client_req.get_header_str("Port") else {
        panic!("Couldn't find out what port to use!");
    };
    let port = u16::from_str(port_str).unwrap();

    let backend = Backend::builder("mtls-backend", format!("localhost:{}", port))
        .enable_ssl()
        .provide_client_certificate(certificate, key_secret)
        .finish()
        .expect("can build backend");

    let resp = Request::get("http://localhost/")
        .with_header("header", "is-a-thing")
        .with_body("hello")
        .send(backend)
        .unwrap();

    assert_eq!(resp.get_status(), StatusCode::OK);
    let body = resp.into_body().into_string();
    let mut cert_cursor = std::io::Cursor::new(certificate);
    let mut info = rustls_pemfile::certs(&mut cert_cursor).expect("got certs");
    assert_eq!(info.len(), 1);
    let reflected_cert = info.remove(0);
    let base64_cert = general_purpose::STANDARD.encode(reflected_cert);
    assert_eq!(body, base64_cert);

    Response::from_status(200)
        .with_body("Hello, Viceroy!")
        .send_to_client();

    Ok(())
}
