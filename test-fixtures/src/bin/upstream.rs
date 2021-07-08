use fastly::{Backend, Request, Response};

/// This test fixture simply forwards the client request to a desired backend, specified by
/// a special `Viceroy-Backend` header.
fn main() {
    let client_req = Request::from_client();

    // Extract the desired backend from a the `Viceroy-Backend` header
    let backend_name = client_req
        .get_header_str("Viceroy-Backend")
        .expect("No backend header");
    let backend = Backend::from_name(backend_name).expect("Could not parse backend name");

    // Forward the request to the given backend
    client_req
        .send(backend)
        .unwrap_or_else(|_| Response::from_status(500))
        .send_to_client();
}
