//! Send a [`418 I'm a teapot`][tea] response downstream.
//!
//! `teapot-status.wasm` will create a [`418 I'm a teapot`][tea] response, per [RFC2324][rfc]. This
//! status code is used to clearly indicate that a response came from the guest program.
//!
//! [rfc]: https://tools.ietf.org/html/rfc2324
//! [tea]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/418

use fastly_sys::{
    fastly_http_body as http_body, fastly_http_resp as http_resp, BodyHandle, ResponseHandle,
};

fn main() {
    let mut body: BodyHandle = 0;
    let mut resp: ResponseHandle = 0;
    unsafe {
        // Create a new response, set its status code, and send it downstream.
        http_resp::new(&mut resp)
            .result()
            .expect("can create a new response");
        http_resp::status_set(resp, 418)
            .result()
            .expect("can set the status code");
        http_body::new(&mut body)
            .result()
            .expect("can create a new body");
        http_resp::send_downstream(resp, body, 0)
            .result()
            .expect("can send the response downstream");
    }
}
