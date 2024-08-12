//! A guest program that tests the hostcalls in the request module.

use {
    crate::limits::MAX_HEADER_NAME_LEN,
    bytes::BytesMut,
    fastly::{error::BufferSizeError, handle::RequestHandle as FastlyRequestHandle},
    fastly_shared::{FastlyStatus, HttpVersion},
    fastly_sys::fastly_http_req::{
        header_append, header_insert, header_remove, header_value_get, method_get, method_set, new,
        uri_get, uri_set, version_get, version_set,
    },
    fastly_sys::{ContentEncodings, RequestHandle},
    http::header::{HeaderName, HeaderValue},
    http::{Method, Uri},
};

#[path = "../limits.rs"]
pub(crate) mod limits;

const HEADER_LEN_TOO_LONG: usize = MAX_HEADER_NAME_LEN + 1;

fn test_version_set_and_get() {
    let mut req1: RequestHandle = 0;
    let mut req2: RequestHandle = 0;

    let mut version1 = 0;
    let mut version2 = 0;

    unsafe {
        // Test that one successfully gets the default version.
        new(&mut req1);
        let stat = version_get(req1, &mut version1);
        assert_eq!(stat, FastlyStatus::OK);

        // Test that one successfully gets the previously-set version.
        new(&mut req2);
        let stat = version_set(req2, HttpVersion::Http09 as u32);
        assert_eq!(stat, FastlyStatus::OK);
        let stat = version_get(req2, &mut version2);
        assert_eq!(stat, FastlyStatus::OK);
    }

    assert_eq!(version1, HttpVersion::Http11 as u32);
    assert_eq!(version2, HttpVersion::Http09 as u32);
}

fn test_uri_set_and_get() {
    let mut req: RequestHandle = 0;

    let uri: &[u8] = b"https://zip.com/foo/bar";

    let tiny_max = 2;
    let mut tiny_buffer = BytesMut::with_capacity(tiny_max);

    let good_max = 255;
    let mut good_buffer = BytesMut::with_capacity(good_max);

    let bad_max = 1;
    let mut bad_buffer = BytesMut::with_capacity(bad_max);

    let mut nwritten = 0;

    unsafe {
        // Test that one successfully gets the default uri.
        new(&mut req);
        assert_eq!(
            uri_get(req, tiny_buffer.as_mut_ptr(), tiny_max, &mut nwritten),
            FastlyStatus::OK
        );
        tiny_buffer.set_len(nwritten);
        assert_eq!(nwritten, 1);
        assert_eq!(
            "/",
            Uri::from_maybe_shared(tiny_buffer.freeze()).expect("Request uri is valid"),
        );

        // Test that one can set and get a uri.
        nwritten = 0;
        assert_eq!(uri_set(req, uri.as_ptr(), uri.len()), FastlyStatus::OK);

        uri_get(req, good_buffer.as_mut_ptr(), good_max, &mut nwritten);
        good_buffer.set_len(nwritten);
        assert_eq!(nwritten, uri.len());
        assert_eq!(
            "https://zip.com/foo/bar",
            Uri::from_maybe_shared(good_buffer.freeze()).expect("Request uri is valid"),
        );

        // Test that one cannot get a uri when a too-small buffer is supplied
        assert_eq!(
            uri_get(req, bad_buffer.as_mut_ptr(), bad_max, &mut nwritten),
            FastlyStatus::BUFLEN
        );
        // Affirm that nwritten indicates the amount of space needed for this call
        // to have been successful.
        assert_eq!(nwritten, uri.len());

        // Test that one cannot exaggerate the size of one's uri.
        assert_eq!(
            uri_set(req, uri.as_ptr(), uri.len() + 1),
            FastlyStatus::ERROR
        );
    }
}

fn test_method_set_and_get() {
    let mut req: RequestHandle = 0;

    let method: &[u8] = b"POST";

    let tiny_max = 5;
    let mut tiny_buffer = BytesMut::with_capacity(tiny_max);

    let good_max = 255;
    let mut good_buffer = BytesMut::with_capacity(good_max);

    let bad_max = 1;
    let mut bad_buffer = BytesMut::with_capacity(bad_max);

    let mut nwritten = 0;

    unsafe {
        // Test that one successfully gets the default method.
        new(&mut req);
        assert_eq!(
            method_get(req, tiny_buffer.as_mut_ptr(), tiny_max, &mut nwritten),
            FastlyStatus::OK
        );
        tiny_buffer.set_len(nwritten);
        assert_eq!(nwritten, 3);
        assert_eq!(
            Method::GET,
            Method::from_bytes(&tiny_buffer).expect("Request method is valid"),
        );

        // Test that one can set and get a method.
        nwritten = 0;
        assert_eq!(
            method_set(req, method.as_ptr(), method.len()),
            FastlyStatus::OK
        );
        assert_eq!(
            method_get(req, good_buffer.as_mut_ptr(), good_max, &mut nwritten),
            FastlyStatus::OK
        );
        good_buffer.set_len(nwritten);
        assert_eq!(nwritten, 4);
        assert_eq!(
            Method::POST,
            Method::from_bytes(&good_buffer).expect("Request method is valid"),
        );

        // Test that one cannot get a method when a too-small buffer is supplied
        assert_eq!(
            method_get(req, bad_buffer.as_mut_ptr(), bad_max, &mut nwritten),
            FastlyStatus::BUFLEN
        );
        // Affirm that nwritten indicates the amount of space needed for this call
        // to have been successful.
        assert_eq!(nwritten, method.len());
    }
}

fn test_header_value_get_and_insert() {
    let mut req: RequestHandle = 0;

    let hdr_name: &[u8] = b"header-name";
    let hdr_val: &[u8] = b"foo";

    let good_max = 255;
    let mut good_buffer = BytesMut::with_capacity(good_max);

    let bad_max = 1;
    let mut bad_buffer = BytesMut::with_capacity(bad_max);

    let mut nwritten = 0;

    unsafe {
        // Test that one successfully gets a header that is not set.
        new(&mut req);
        header_value_get(
            req,
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
            req,
            hdr_name.as_ptr(),
            hdr_name.len(),
            hdr_val.as_ptr(),
            hdr_val.len(),
        );
        header_value_get(
            req,
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
                req,
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
                req,
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
                req,
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
    let mut req: RequestHandle = 0;

    let hdr_name: &[u8] = b"header-name";
    let hdr_val: &[u8] = b"foo";

    let good_max = 255;
    let mut good_buffer = BytesMut::with_capacity(good_max);

    let mut nwritten = 0;

    unsafe {
        // Test that one can append a header that is not already set.
        new(&mut req);
        header_append(
            req,
            hdr_name.as_ptr(),
            hdr_name.len(),
            hdr_val.as_ptr(),
            hdr_val.len(),
        );
        header_value_get(
            req,
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
                req,
                long_header.as_ptr(),
                long_header.len(),
                hdr_val.as_ptr(),
                hdr_val.len(),
            ),
            FastlyStatus::INVAL
        );

        // Test that an attempt to remove a too-long header name fails.
        assert_eq!(
            header_remove(req, long_header.as_ptr(), long_header.len()),
            FastlyStatus::INVAL
        );

        // Test that removing a previously-appended header succeeds.
        nwritten = 0;
        assert_eq!(
            header_remove(req, hdr_name.as_ptr(), hdr_name.len()),
            FastlyStatus::OK
        );
        header_value_get(
            req,
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
            header_remove(req, hdr_name.as_ptr(), hdr_name.len()),
            FastlyStatus::INVAL
        );
    }
}

fn test_header_multi_value_set_and_get() {
    let mut request = FastlyRequestHandle::new();
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
    request.set_header_values(&hdr_name, &hdr_values);
    let header_values: Vec<HeaderValue> = request
        .get_header_values(&hdr_name, good_max)
        .collect::<Result<Vec<HeaderValue>, _>>()
        .unwrap();

    assert!(header_values.iter().any(|i| i == "foo"));
    assert!(header_values.iter().any(|i| i == "bar"));
    assert_eq!(hdr_values.len(), header_values.len());

    // Test that one gets the expected error when the buffer size is too small.
    match request
        .get_header_values(&hdr_name, bad_max)
        .collect::<Result<Vec<HeaderValue>, _>>()
    {
        Err(BufferSizeError { .. }) => (),
        _ => panic!("Expected BufferSizeError"),
    }

    // Test that an attempt to get values for a not-there header results in a 0-length vector.
    let not_there_hdr_name = HeaderName::from_static("not-there-header");
    let result = request
        .get_header_values(&not_there_hdr_name, good_max)
        .collect::<Result<Vec<HeaderValue>, _>>()
        .unwrap();
    assert_eq!(result.len(), 0);

    // Test that one can set multiple header names on a response and get all those names back
    request.set_header_values(&othr_hdr_name, &othr_hdr_values);
    let header_names: Vec<HeaderName> = request
        .get_header_names(good_max)
        .collect::<Result<Vec<HeaderName>, _>>()
        .unwrap();

    assert!(header_names.iter().any(|i| i == "header-name"));
    assert!(header_names.iter().any(|i| i == "other-header-name"));
    assert_eq!(header_names.len(), 2);

    // Test that one gets the expected error when the buffer size is too small.
    match request
        .get_header_names(bad_max)
        .collect::<Result<Vec<HeaderName>, _>>()
    {
        Err(BufferSizeError { .. }) => (),
        _ => panic!("Expected BufferSizeError"),
    }

    // Test that an attempt to get names for a headerless request results in a 0-length vector.
    let headerless_request = FastlyRequestHandle::new();
    let no_header_names: Vec<HeaderName> = headerless_request
        .get_header_names(good_max)
        .collect::<Result<Vec<HeaderName>, _>>()
        .unwrap();

    assert_eq!(0, no_header_names.len());
}

fn test_default_decompress_response() {
    let mut request = FastlyRequestHandle::new();

    request.set_auto_decompress_response(ContentEncodings::default());
}

fn main() {
    test_version_set_and_get();
    test_uri_set_and_get();
    test_method_set_and_get();
    test_header_value_get_and_insert();
    test_header_append_and_remove();
    test_header_multi_value_set_and_get();
    test_default_decompress_response()
}
