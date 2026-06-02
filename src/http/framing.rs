//! Utilities for validating "framing headers" (Content-Length and Transfer-Encoding) for HTTP messages.

use crate::body::Body;
use crate::http::filtering::filter_outgoing_headers;
use crate::sandbox::{ViceroyRequestMetadata, ViceroyResponseMetadata};
use crate::wiggle_abi::types::FramingHeadersMode;

use http::{HeaderMap, Request, Response, header};

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

pub fn apply_response_framing(response: &mut Response<Body>) {
    let mut framing_headers_mode = response
        .extensions()
        .get::<ViceroyResponseMetadata>()
        .map(|metadata: &ViceroyResponseMetadata| metadata.framing_headers_mode)
        .unwrap_or(FramingHeadersMode::Automatic);

    if framing_headers_mode == FramingHeadersMode::ManuallyFromHeaders {
        if !content_length_is_valid(response.headers()) {
            tracing::warn!(
                "Downstream response has malformed Content-Length header, falling back to automatic framing."
            );
            framing_headers_mode = FramingHeadersMode::Automatic;
        } else if !transfer_encoding_is_supported(response.headers()) {
            tracing::warn!(
                "Downstream response has unsupported Transfer-Encoding header, falling back to automatic framing."
            );
            framing_headers_mode = FramingHeadersMode::Automatic;
        } else if !response
            .headers()
            .contains_key(hyper::header::CONTENT_LENGTH)
            && !response
                .headers()
                .contains_key(hyper::header::TRANSFER_ENCODING)
        {
            tracing::warn!(
                "Downstream response has neither Content-Length nor Transfer-Encoding header, falling back to automatic framing."
            );
            framing_headers_mode = FramingHeadersMode::Automatic;
        }
    }

    if framing_headers_mode != FramingHeadersMode::ManuallyFromHeaders {
        filter_outgoing_headers(response.headers_mut());
    }
}

pub fn apply_request_framing(req: &mut Request<Body>) {
    let mut framing_headers_mode = req
        .extensions()
        .get::<ViceroyRequestMetadata>()
        .map(|vrm| vrm.framing_headers_mode)
        .unwrap_or(FramingHeadersMode::Automatic);

    if framing_headers_mode == FramingHeadersMode::ManuallyFromHeaders {
        if !content_length_is_valid(req.headers()) {
            tracing::warn!(
                "Backend request has malformed Content-Length header, falling back to automatic framing."
            );
            framing_headers_mode = FramingHeadersMode::Automatic;
        } else if !transfer_encoding_is_supported(req.headers()) {
            tracing::warn!(
                "Backend request has unsupported Transfer-Encoding header, falling back to automatic framing."
            );
            framing_headers_mode = FramingHeadersMode::Automatic;
        } else if !req.headers().contains_key(header::CONTENT_LENGTH)
            && !req.headers().contains_key(header::TRANSFER_ENCODING)
        {
            tracing::warn!(
                "Backend request has neither Content-Length nor Transfer-Encoding header, falling back to automatic framing."
            );
            framing_headers_mode = FramingHeadersMode::Automatic;
        }
    }
    if framing_headers_mode != FramingHeadersMode::ManuallyFromHeaders {
        filter_outgoing_headers(req.headers_mut());
    }
}
