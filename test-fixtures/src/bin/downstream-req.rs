use fastly::Request;
use fastly_shared::FastlyStatus;
use std::net::IpAddr;

#[link(wasm_import_module = "fastly_http_downstream")]
extern "C" {
    #[link_name = "downstream_compliance_region"]
    pub fn downstream_compliance_region(
        req_handle: fastly_sys::RequestHandle,
        region_out: *mut u8,
        region_max_len: usize,
        nwritten: *mut usize,
    ) -> FastlyStatus;
}

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

    // Request ID matches session ID for first request:
    let req_id = client_req.get_client_request_id().unwrap().to_string();
    let session_id = std::env::var("FASTLY_TRACE_ID").unwrap();
    assert_eq!(req_id, session_id);

    // Check that we can get addresses used in downstream connection:
    let localhost: IpAddr = "127.0.0.1".parse().unwrap();
    assert_eq!(client_req.get_client_ip_addr().unwrap(), localhost);

    let localhost: IpAddr = "127.0.0.1".parse().unwrap();
    assert_eq!(client_req.get_server_ip_addr().unwrap(), localhost);

    // Viceroy doesn't consider its requests DDOS attacks:
    assert_eq!(client_req.get_client_ddos_detected(), Some(false));

    // Viceroy returns false for `fastly_key_is_valid`:
    assert_eq!(client_req.fastly_key_is_valid(), false);

    // TLS is currently unsupported, so these should work but return `None`:
    assert_eq!(client_req.get_tls_cipher_openssl_name(), None);
    assert_eq!(client_req.get_tls_cipher_openssl_name_bytes(), None);
    assert_eq!(client_req.get_tls_client_hello(), None);
    assert_eq!(client_req.get_tls_protocol(), None);
    assert_eq!(client_req.get_tls_protocol_bytes(), None);
    assert_eq!(client_req.get_tls_client_hello(), None);
    assert_eq!(client_req.get_tls_ja3_md5(), None);
    assert_eq!(client_req.get_tls_ja4(), None);
    assert_eq!(client_req.get_tls_raw_client_certificate(), None);
    assert_eq!(client_req.get_tls_raw_client_certificate_bytes(), None);
    assert!(client_req.get_tls_client_cert_verify_result().is_none());
    // NOTE: This currently fails, waiting on a patch to land in the fastly crate
    // assert_eq!(client_req.get_tls_raw_client_certificate(), None);
    assert_eq!(client_req.get_tls_raw_client_certificate_bytes(), None);

    // Other downstream metadata that Viceroy doesn't currently support:
    assert_eq!(client_req.get_client_h2_fingerprint(), None);
    assert_eq!(client_req.get_client_oh_fingerprint(), None);

    // Get the actual handle:
    let (rh, _) = client_req.into_handles();

    // Check that we get a "none" region:
    let mut region = Vec::with_capacity(10);
    let mut nwritten = 0;
    let status = unsafe {
        downstream_compliance_region(rh.as_u32(), region.as_mut_ptr(), region.capacity(), &mut nwritten)
    };
    unsafe {
        region.set_len(nwritten);
    }
    assert_eq!(status, FastlyStatus::OK);
    assert_eq!(nwritten, 4);
    assert_eq!(region.as_slice(), b"none");

}
