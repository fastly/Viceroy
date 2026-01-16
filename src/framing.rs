//! Utilities for validating "framing headers" (Content-Length and Transfer-Encoding) for HTTP messages.

use http::{header, HeaderMap};

pub fn content_length_is_valid(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::CONTENT_LENGTH).iter();

    match values.next() {
        None => true,
        Some(val) => val.as_bytes().iter().all(|b| b.is_ascii_digit()) && values.next().is_none(),
    }
}

pub fn transfer_encoding_is_supported(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::TRANSFER_ENCODING).iter();

    match values.next() {
        None => true,
        Some(val) => {
            val.to_str()
                .map(|s| s.eq_ignore_ascii_case("chunked"))
                .unwrap_or(false)
                && values.next().is_none()
        }
    }
}
