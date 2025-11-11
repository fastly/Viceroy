//! Utilities for validating "framing headers" (Content-Length and Transfer-Encoding) for HTTP messages.

use http::{header, HeaderMap};

pub fn content_length_is_valid(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::CONTENT_LENGTH).iter();

    if let Some(val) = values.next() {
        if val.as_bytes().iter().all(|b| b.is_ascii_digit()) && values.next().is_none() {
            return true;
        }
    }
    false
}

pub fn transfer_encoding_is_supported(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::TRANSFER_ENCODING).iter();

    if let Some(val) = values.next() {
        if val
            .to_str()
            .map(|s| s.eq_ignore_ascii_case("chunked"))
            .unwrap_or(false)
            && values.next().is_none()
        {
            return true;
        }
    }
    false
}
