//! A guest program that tests the hostcalls in the response module.

use {
    crate::limits::MAX_HEADER_NAME_LEN,
    bytes::BytesMut,
    fastly::{error::BufferSizeError, handle::ResponseHandle as FastlyResponseHandle},
    fastly_shared::{FastlyStatus, HttpVersion},
    fastly_sys::{
        fastly_http_resp::{
            header_append, header_insert, header_remove, header_value_get, new, status_get,
            status_set, version_get, version_set,
        },
        ResponseHandle,
    },
    http::header::{HeaderName, HeaderValue},
};

#[path = "../limits.rs"]
pub(crate) mod limits;

const HEADER_LEN_TOO_LONG: usize = MAX_HEADER_NAME_LEN + 1;

fn test_status_set_and_get() {
    let mut resp1: ResponseHandle = 0;
    let mut resp2: ResponseHandle = 0;
    let mut resp3: ResponseHandle = 0;
    let mut resp4: ResponseHandle = 0;

    unsafe {
        new(&mut resp1);
        new(&mut resp2);
        new(&mut resp3);
        new(&mut resp4);

        status_set(resp1, 200);
        status_set(resp2, 300);
        status_set(resp3, 500);

        // Test that an invalid status code will result in an error code.
        assert_eq!(status_set(resp4, 1), FastlyStatus::INVAL);
    }

    let mut status1: u16 = 0;
    let mut status2: u16 = 0;
    let mut status3: u16 = 0;

    unsafe {
        status_get(resp1, &mut status1);
        status_get(resp2, &mut status2);
        status_get(resp3, &mut status3);
    }

    assert_eq!(status1, 200);
    assert_eq!(status2, 300);
    assert_eq!(status3, 500);
}

fn test_version_set_and_get() {
    let mut resp1: ResponseHandle = 0;
    let mut resp2: ResponseHandle = 0;

    let mut version1 = 0;
    let mut version2 = 0;

    unsafe {
        // Test that one successfully gets the default version.
        new(&mut resp1);
        version_get(resp1, &mut version1);

        // Test that one successfully gets the previously-set version.
        new(&mut resp2);
        version_set(resp2, HttpVersion::Http09 as u32);
        version_get(resp2, &mut version2);
    }

    assert_eq!(version1, HttpVersion::Http11 as u32);
    assert_eq!(version2, HttpVersion::Http09 as u32);
}

fn test_header_value_get_and_insert() {
    let mut resp: ResponseHandle = 0;

    let hdr_name: &[u8] = b"header-name";
    let hdr_val: &[u8] = b"foo";

    let good_max = 255;
    let mut good_buffer = BytesMut::with_capacity(good_max);

    let bad_max = 1;
    let mut bad_buffer = BytesMut::with_capacity(bad_max);

    let mut nwritten = 0;

    unsafe {
        // Test that one successfully gets a header that is not set.
        new(&mut resp);
        header_value_get(
            resp,
            hdr_name.as_ptr(),
            hdr_name.len(),
            good_buffer.as_mut_ptr(),
            good_max,
            &mut nwritten,
        );
        good_buffer.set_len(nwritten);
        assert_eq!(nwritten, 0);
        assert_eq!(
            "",
            HeaderValue::from_bytes(&good_buffer).expect("bytes from host are valid")
        );

        // Test that one successfully gets a header that has been inserted.
        header_insert(
            resp,
            hdr_name.as_ptr(),
            hdr_name.len(),
            hdr_val.as_ptr(),
            hdr_val.len(),
        );
        header_value_get(
            resp,
            hdr_name.as_ptr(),
            hdr_name.len(),
            good_buffer.as_mut_ptr(),
            good_max,
            &mut nwritten,
        );
        good_buffer.set_len(nwritten);
        assert_eq!(nwritten, 3);
        assert_eq!(
            "foo",
            HeaderValue::from_bytes(&good_buffer).expect("bytes from host are valid")
        );

        // Test that an attempt to place a header value in a too-short buffer fails.
        nwritten = 0;
        assert_eq!(
            header_value_get(
                resp,
                hdr_name.as_ptr(),
                hdr_name.len(),
                bad_buffer.as_mut_ptr(),
                bad_max,
                &mut nwritten
            ),
            FastlyStatus::BUFLEN
        );
        // Affirm that nwritten indicates the amount of space needed for this call
        // to have been successful.
        assert_eq!(nwritten, 3);

        // Test that an attempt to get a too-long header name fails.
        nwritten = 0;
        let long_header =
            Vec::from_iter(hdr_name.iter().cycle().take(HEADER_LEN_TOO_LONG).copied());
        assert_eq!(
            header_value_get(
                resp,
                long_header.as_ptr(),
                long_header.len(),
                good_buffer.as_mut_ptr(),
                good_max,
                &mut nwritten
            ),
            FastlyStatus::INVAL
        );
        assert_eq!(nwritten, 0);

        // Test that an attempt to insert a too-long header name fails.
        assert_eq!(
            header_insert(
                resp,
                long_header.as_ptr(),
                long_header.len(),
                hdr_val.as_ptr(),
                hdr_val.len(),
            ),
            FastlyStatus::INVAL
        );
    }
}

fn test_header_append_and_remove() {
    let mut resp: ResponseHandle = 0;

    let hdr_name: &[u8] = b"header-name";
    let hdr_val: &[u8] = b"foo";

    let good_max = 255;
    let mut good_buffer = BytesMut::with_capacity(good_max);

    let mut nwritten = 0;

    unsafe {
        // Test that one can append a header that is not already set.
        new(&mut resp);
        header_append(
            resp,
            hdr_name.as_ptr(),
            hdr_name.len(),
            hdr_val.as_ptr(),
            hdr_val.len(),
        );
        header_value_get(
            resp,
            hdr_name.as_ptr(),
            hdr_name.len(),
            good_buffer.as_mut_ptr(),
            good_max,
            &mut nwritten,
        );
        good_buffer.set_len(nwritten);
        assert_eq!(nwritten, 3);
        assert_eq!(
            "foo",
            HeaderValue::from_bytes(&good_buffer).expect("bytes from host are valid")
        );

        // Test that an attempt to append a too-long header name fails.
        let long_header =
            Vec::from_iter(hdr_name.iter().cycle().take(HEADER_LEN_TOO_LONG).copied());
        assert_eq!(
            header_append(
                resp,
                long_header.as_ptr(),
                long_header.len(),
                hdr_val.as_ptr(),
                hdr_val.len(),
            ),
            FastlyStatus::INVAL
        );

        // Test that an attempt to remove a too-long header name fails.
        assert_eq!(
            header_remove(resp, long_header.as_ptr(), long_header.len()),
            FastlyStatus::INVAL
        );

        // Test that removing a previously-appended header succeeds.
        nwritten = 0;
        assert_eq!(
            header_remove(resp, hdr_name.as_ptr(), hdr_name.len()),
            FastlyStatus::OK
        );
        header_value_get(
            resp,
            hdr_name.as_ptr(),
            hdr_name.len(),
            good_buffer.as_mut_ptr(),
            good_max,
            &mut nwritten,
        );
        good_buffer.set_len(nwritten);
        assert_eq!(nwritten, 0);
        assert_eq!(
            "",
            HeaderValue::from_bytes(&good_buffer).expect("bytes from host are valid")
        );

        // Test that attempting to remove a header that isn't there fails.
        assert_eq!(
            header_remove(resp, hdr_name.as_ptr(), hdr_name.len()),
            FastlyStatus::INVAL
        );
    }
}

fn test_header_multi_value_set_and_get() {
    let mut response = FastlyResponseHandle::new();
    let hdr_name = HeaderName::from_static("header-name");
    let hdr_values = vec![
        HeaderValue::from_static("foo"),
        HeaderValue::from_static("bar"),
    ];

    let othr_hdr_name = HeaderName::from_static("other-header-name");
    let othr_hdr_values = vec![
        HeaderValue::from_static("zip"),
        HeaderValue::from_static("zap"),
    ];

    let good_max = 255;
    let bad_max = 1;

    // Test that one can set a header to multiple values and get those same values back.
    response.set_header_values(&hdr_name, &hdr_values);
    let header_values: Vec<HeaderValue> = response
        .get_header_values(&hdr_name, good_max)
        .collect::<Result<Vec<HeaderValue>, _>>()
        .unwrap();

    assert!(header_values.iter().any(|i| i == "foo"));
    assert!(header_values.iter().any(|i| i == "bar"));
    assert_eq!(hdr_values.len(), header_values.len());

    // Test that one gets the expected error when the buffer size is too small.
    match response
        .get_header_values(&hdr_name, bad_max)
        .collect::<Result<Vec<HeaderValue>, _>>()
    {
        Err(BufferSizeError { .. }) => (),
        _ => panic!("Expected BufferSizeError"),
    }

    // Test that an attempt to get values for a not-there header results in a 0-length vector.
    let not_there_hdr_name = HeaderName::from_static("not-there-header");
    let result = response
        .get_header_values(&not_there_hdr_name, good_max)
        .collect::<Result<Vec<HeaderValue>, _>>()
        .unwrap();
    assert_eq!(result.len(), 0);

    // Test that one can set multiple header names on a response and get all those names back
    response.set_header_values(&othr_hdr_name, &othr_hdr_values);
    let header_names: Vec<HeaderName> = response
        .get_header_names(good_max)
        .collect::<Result<Vec<HeaderName>, _>>()
        .unwrap();

    assert!(header_names.iter().any(|i| i == "header-name"));
    assert!(header_names.iter().any(|i| i == "other-header-name"));
    assert_eq!(header_names.len(), 2);

    // Test that one gets the expected error when the buffer size is too small.
    match response
        .get_header_names(bad_max)
        .collect::<Result<Vec<HeaderName>, _>>()
    {
        Err(BufferSizeError { .. }) => (),
        _ => panic!("Expected BufferSizeError"),
    }

    // Test that an attempt to get names for a headerless response results in a 0-length vector.
    let headerless_response = FastlyResponseHandle::new();
    let no_header_names: Vec<HeaderName> = headerless_response
        .get_header_names(good_max)
        .collect::<Result<Vec<HeaderName>, _>>()
        .unwrap();

    assert_eq!(0, no_header_names.len());
}

fn main() {
    test_status_set_and_get();
    test_version_set_and_get();
    test_header_value_get_and_insert();
    test_header_append_and_remove();
    test_header_multi_value_set_and_get();
}
