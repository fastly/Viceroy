//! A guest program that exercises the Fanout and WebSocket passthrough handoff hostcalls.
//!
//! Both hostcalls report `unsupported` when the corresponding feature is not enabled for the
//! service, so this fixture reports the raw `FastlyStatus` it observed back to the test.

use std::io::Write;

use fastly::{Request, Response};
use fastly_shared::FastlyStatus;
use fastly_sys::fastly_http_req;

fn main() {
    let client_req = Request::from_client();
    let path = client_req.get_path().to_owned();
    let backend = client_req
        .get_header_str("handoff-backend")
        .unwrap_or("origin")
        .to_owned();

    // Optionally send a response before attempting the handoff, so that a test can check that
    // the "a response was already sent" error takes precedence over the feature check. The
    // response is streamed, so that the status can still be reported through its body once the
    // handoff has been attempted.
    let already_sent = client_req
        .get_header_str("send-response-first")
        .is_some()
        .then(|| Response::from_status(200).stream_to_client());

    let (req_handle, _body_handle) = client_req.into_handles();
    let req = req_handle.as_u32();

    let status = unsafe {
        match path.as_str() {
            "/fanout" => {
                fastly_http_req::redirect_to_grip_proxy_v2(req, backend.as_ptr(), backend.len())
            }
            "/websocket" => fastly_http_req::redirect_to_websocket_proxy_v2(
                req,
                backend.as_ptr(),
                backend.len(),
            ),
            other => panic!("unexpected path: {other}"),
        }
    };

    if let Some(mut body) = already_sent {
        write!(body, "status={}", status.code).unwrap();
        body.finish().unwrap();
        return;
    }

    // On success the handoff target owns the response; otherwise report what we saw.
    if status == FastlyStatus::OK {
        return;
    }

    Response::from_body(format!("status={}", status.code)).send_to_client();
}
