use hyper::{header, HeaderMap};

pub fn filter_outgoing_headers(headers: &mut HeaderMap) {
    // Remove framing-related headers; we rely on Hyper to insert the appropriate
    // framing headers automatically, and do not allow guests to include them.
    headers.remove(header::CONTENT_LENGTH);
    headers.remove(header::TRANSFER_ENCODING);
}
