use fastly::{Backend, Error, Request};
//use fastly::experimental::GrpcBackend;
use std::str::FromStr;

/// Pass everything from the downstream request through to the backend, then pass everything back
/// from the upstream request to the downstream response.
fn main() -> Result<(), Error> {
    let client_req = Request::from_client();
    let Some(port_str) = client_req.get_header_str("Port") else {
            panic!("Couldn't find out what port to use!");
    };
    let port = u16::from_str(port_str).unwrap();

    let backend = Backend::builder("grpc-backend", format!("localhost:{}", port))
//        .for_grpc(true)
        .finish()
        .expect("can build backend");

    Request::get("http://localhost/")
        .with_header("header", "is-a-thing")
        .with_body("hello")
        .send(backend)
        .unwrap()
        .send_to_client();

    Ok(())
}
