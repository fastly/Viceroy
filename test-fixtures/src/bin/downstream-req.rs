use fastly::Request;
use std::net::IpAddr;

fn main() {
    let mut client_req = Request::from_client();

    // Check that the actual request headers came through
    assert_eq!(client_req.get_header_str("Accept"), Some("text/html"));
    assert_eq!(client_req.get_header_str("X-Custom-Test"), Some("abcdef"));

    // Mutate the client request
    client_req.set_header("X-Custom-2", "added");

    // Ensure that the methods for getting the original header info do _not_
    // include the mutation
    let names: Vec<String> = client_req.get_original_header_names().unwrap().collect();
    assert_eq!(
        names,
        vec![String::from("accept"), String::from("x-custom-test")]
    );
    assert_eq!(client_req.get_original_header_count().unwrap(), 2);

    assert_eq!(client_req.take_body_str(), "Hello, world!");

    let localhost: IpAddr = "127.0.0.1".parse().unwrap();
    assert_eq!(client_req.get_client_ip_addr().unwrap(), localhost);

    let localhost: IpAddr = "127.0.0.1".parse().unwrap();
    assert_eq!(client_req.get_server_ip_addr().unwrap(), localhost);

    assert_eq!(client_req.get_tls_cipher_openssl_name(), None);
    assert_eq!(client_req.get_tls_cipher_openssl_name_bytes(), None);
    assert_eq!(client_req.get_tls_client_hello(), None);
    assert_eq!(client_req.get_tls_protocol(), None);
    assert_eq!(client_req.get_tls_protocol_bytes(), None);
    // NOTE: This currently fails, waiting on a patch to land in the fastly crate
    // assert_eq!(client_req.get_tls_raw_client_certificate(), None);
    assert_eq!(client_req.get_tls_raw_client_certificate_bytes(), None);
}
