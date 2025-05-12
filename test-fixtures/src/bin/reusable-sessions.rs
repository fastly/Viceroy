//! A guest program that tests the hostcalls for fetching multiple requests per session.

use fastly::{Request, Response};
use fastly::handle::{BodyHandle, RequestHandle};
use fastly_shared::{FastlyStatus, INVALID_REQUEST_HANDLE};

pub type RequestPromiseHandle = u32;

#[derive(Default)]
#[repr(C)]
pub struct NextRequestOptions {
    pub reserved: u64,
}

bitflags::bitflags! {
    /// Request options.
    #[derive(Default)]
    #[repr(transparent)]
    pub struct NextRequestOptionsMask: u32 {
        const RESERVED = 1 << 0;
    }
}

#[link(wasm_import_module = "fastly_http_downstream")]
extern "C" {
    #[link_name = "next_req"]
    pub fn next_req(
        options_mask: NextRequestOptionsMask,
        options: *const NextRequestOptions,
        handle_out: *mut RequestPromiseHandle,
    ) -> FastlyStatus;

    #[link_name = "next_req_wait"]
    pub fn next_req_wait(
        handle: RequestPromiseHandle,
        req_handle_out: *mut fastly_sys::RequestHandle,
        body_handle_out: *mut fastly_sys::BodyHandle,
    ) -> FastlyStatus;

    #[link_name = "next_req_abandon"]
    pub fn next_req_abandon(
        handle: RequestPromiseHandle,
    ) -> FastlyStatus;
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
            next_req(mask, &opts, &mut pending)
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

        'inner: loop {
            let status = unsafe { next_req_wait(pending, &mut rh, &mut bh) };

            match status {
                FastlyStatus::OK => break 'inner,
                FastlyStatus::AGAIN => continue 'inner,
                FastlyStatus::NONE => break 'outer,
                _ => panic!("unexpected result: {status:?}"),
            }
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
