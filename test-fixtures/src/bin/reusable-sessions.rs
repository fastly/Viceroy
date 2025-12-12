//! A guest program that tests the hostcalls for fetching multiple requests per session.

use fastly::{Request, Response};
use fastly::handle::{BodyHandle, RequestHandle};
use fastly_shared::{FastlyStatus, INVALID_REQUEST_HANDLE};
use fastly_sys::fastly_http_downstream::*;

fn is_ready(handle: u32) -> bool {
    let mut ready_out: u32 = 0;
    unsafe {
        let status = fastly_sys::fastly_async_io::is_ready(handle, &mut ready_out);
        assert_eq!(status, FastlyStatus::OK);
    }
    ready_out == 1
}

fn main() {
    let mut counter = 0;
    let mut req = Request::from_client();

    'outer: loop {
        assert_eq!(req.take_body().into_string(), counter.to_string());

        // Make sure we're registered to receive the next request before
        // responding to avoid flakes.
        let mask = NextRequestOptionsMask::empty();
        let opts = NextRequestOptions::default();

        let mut pending = INVALID_REQUEST_HANDLE;
        let status = unsafe {
            next_request(mask, &opts, &mut pending)
        };

        if status != FastlyStatus::OK {
            return;
        }

        // Respond to downstream.
        counter += 1;
        let resp = Response::from_body(format!("Response #{counter}"));
        resp.send_to_client_impl(false, false);

        // And fetch our next incoming request.
        let mut rh = INVALID_REQUEST_HANDLE;
        let mut bh = INVALID_REQUEST_HANDLE;

        while !is_ready(pending) {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        let status = unsafe { next_request_wait(pending, &mut rh, &mut bh) };

        match status {
            FastlyStatus::OK => {},
            FastlyStatus::NONE => break 'outer,
            _ => panic!("unexpected result: {status:?}"),
        }

        let bh = unsafe { BodyHandle::from_u32(bh) };
        let rh = {
            let mut new = RequestHandle::new();
            *new.as_u32_mut() = rh;
            new
        };

        req = Request::from_handles(rh, Some(bh));
    }
}
