//! Reports the downstream TLS metadata Viceroy exposes for the client request.
use fastly::{Request, Response};

fn main() {
    let req = Request::from_client();
    let hello = req.get_tls_client_hello();
    let body = format!(
        "url={}\nprotocol={}\ncipher={}\nsni={}\nhello_len={}\nhello_version={}\n",
        req.get_url_str(),
        req.get_tls_protocol().unwrap().unwrap_or("-"),
        req.get_tls_cipher_openssl_name().unwrap().unwrap_or("-"),
        req.get_tls_client_servername().unwrap_or("-"),
        hello.map_or_else(|| "-".to_owned(), |h| h.len().to_string()),
        // The ClientHello body starts with the two-byte `legacy_version`.
        hello.map_or_else(|| "-".to_owned(), |h| format!("{:02x}{:02x}", h[0], h[1])),
    );
    Response::from_body(body).send_to_client();
}
