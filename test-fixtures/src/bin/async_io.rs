//! Tests the `async_io` hostcalls by setting up one of each kind of async item, each against
//! a distinct backend. Checks each for readiness, and then does a select with timeout against
//! all of them.

use std::str::FromStr;

use fastly::handle::{BodyHandle, RequestHandle, ResponseHandle};
use fastly::http::{HeaderName, HeaderValue, Method, StatusCode, Url};
use fastly::Error;
use fastly_shared::{CacheOverride, FastlyStatus};

fn is_ready(handle: u32) -> bool {
    let mut ready_out: u32 = 0;
    unsafe {
        let status = fastly_sys::fastly_async_io::is_ready(handle, &mut ready_out);
        assert_eq!(status, FastlyStatus::OK);
    }
    ready_out == 1
}

fn append_header(resp: &mut ResponseHandle, header: impl ToString, value: impl ToString) {
    resp.append_header(
        &HeaderName::from_str(&header.to_string()).unwrap(),
        &HeaderValue::from_str(&value.to_string()).unwrap(),
    )
}

fn test_select() -> Result<(), Error> {
    let mut ds_resp = ResponseHandle::new();
    let pass = CacheOverride::pass();

    // The "simple" case is a pending request, where the async item is awaiting the response headers
    let mut simple_req = RequestHandle::new();
    simple_req.set_url(&Url::parse("http://simple.org/")?);
    simple_req.set_cache_override(&pass);
    let simple_pending_req = simple_req.send_async(BodyHandle::new(), "Simple")?;
    let simple_pending_req_handle = simple_pending_req.as_u32();

    // The "read body" case involves a sync `send`, followed by treating the response body as an async item
    // to read from
    let mut read_body_req = RequestHandle::new();
    read_body_req.set_url(&Url::parse("http://readbody.org/")?);
    read_body_req.set_cache_override(&pass);
    let (_read_body_resp, read_body) = read_body_req.send(BodyHandle::new(), "ReadBody")?;
    let read_body_handle = unsafe { read_body.as_u32() };

    // The "write body" case involves a `send_async_streaming` call, where the streaming body is the
    // async item of interest. To test readiness, we need to ensure the body is large enough that Hyper
    // won't try to buffer it, and hence we can see backpressure on streaming. We do this by including
    // a large (4MB) prefix of the body _prior to_ streaming.
    const INITIAL_BYTE_COUNT: usize = 4 * 1024 * 1024;
    let mut write_body_req = RequestHandle::new();
    write_body_req.set_url(&Url::parse("http://writebody.org/")?);
    write_body_req.set_cache_override(&pass);
    write_body_req.set_method(&Method::POST);
    let mut write_body_initial = BodyHandle::new();
    let initial_bytes = write_body_initial.write_bytes(&vec![0; INITIAL_BYTE_COUNT]);
    assert_eq!(initial_bytes, INITIAL_BYTE_COUNT);
    let (mut write_body, _write_body_pending_req) =
        write_body_req.send_async_streaming(write_body_initial, "WriteBody")?;
    let write_body_handle = unsafe { write_body.as_u32() };

    // Now we attempt to stream 8 chunks of 8KB each, which is the maximum non-Hyper buffering allowed.
    // That limit is set in xqd itself, via a combination of (1) channel size of 8 and (2) the `write`
    // implementation for streaming bodies only taking up to an 8KB chunk at a time.
    let one_chunk = vec![0; 8 * 1024];
    let mut nwritten = 0;
    for _ in 0..8 {
        nwritten += write_body.write_bytes(&one_chunk);
    }
    assert_eq!(nwritten, 8 * 1024 * 8);

    // Give the servers a chance to do their thing. This is needed to resolve a race between the servers
    // initiating responses / reading buffers and the guest snapshotting readiness or performing `select`
    //
    // If this ever becomes flaky, an alternative would be to introduce an additional backend that
    // responds only when the other backends have reached their steady state, via a VTC semaphore, and
    // block on THAT backend here.
    std::thread::sleep(std::time::Duration::from_millis(100));

    append_header(
        &mut ds_resp,
        "Simple-Ready",
        is_ready(simple_pending_req_handle),
    );
    append_header(&mut ds_resp, "Read-Ready", is_ready(read_body_handle));
    append_header(&mut ds_resp, "Write-Ready", is_ready(write_body_handle));

    let handles = vec![
        simple_pending_req_handle,
        read_body_handle,
        write_body_handle,
    ];
    let mut ready_idx = 0;
    unsafe {
        fastly_sys::fastly_async_io::select(handles.as_ptr(), handles.len(), 20, &mut ready_idx);
    };
    if ready_idx == u32::MAX {
        append_header(&mut ds_resp, "Ready-Index", "timeout");
    } else {
        append_header(&mut ds_resp, "Ready-Index", ready_idx);
    }

    let close_status = unsafe { fastly_sys::fastly_http_body::close(write_body_handle) };
    assert!(close_status.is_ok());

    ds_resp.send_to_client(BodyHandle::new());
    Ok(())
}

fn test_empty_select(timeout: u32) {
    let mut ds_resp = ResponseHandle::new();

    let empty_handles = Vec::new();
    let mut ready_idx = 0;

    let res = unsafe {
        fastly_sys::fastly_async_io::select(empty_handles.as_ptr(), 0, timeout, &mut ready_idx)
    };

    if res == FastlyStatus::OK {
        if ready_idx == u32::MAX {
            append_header(&mut ds_resp, "Ready-Index", "timeout");
        } else {
            append_header(&mut ds_resp, "Ready-Index", ready_idx);
        }
    } else {
        ds_resp.set_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    ds_resp.send_to_client(BodyHandle::new());
}

fn main() -> Result<(), Error> {
    let client_req = RequestHandle::from_client();
    if let Ok(Some(val)) =
        client_req.get_header_value(&HeaderName::from_str("Empty-Select-Timeout").unwrap(), 1024)
    {
        test_empty_select(val.to_str().unwrap().parse().unwrap());
        Ok(())
    } else {
        test_select()
    }
}
