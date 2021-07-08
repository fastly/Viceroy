//! Operations related to handling the "downstream" (end-client) request

use crate::{body::Body, error::DownstreamRequestError};
use http::Request;
use hyper::Uri;

/// Canonicalize the incoming request into the form expected by host calls.
///
/// The primary canonicalization is to provide an absolute URL (with authority), using the HOST
/// header of the request.
pub fn prepare_request(req: Request<hyper::Body>) -> Result<Request<Body>, DownstreamRequestError> {
    let (mut metadata, body) = req.into_parts();
    let uri_parts = metadata.uri.into_parts();

    // Prefer to find the host from the HOST header, rather than the URL.
    let http_host = if let Some(host_header) = metadata.headers.get(http::header::HOST) {
        std::str::from_utf8(host_header.as_bytes())
            .map_err(|_| DownstreamRequestError::InvalidHost)?
    } else {
        uri_parts
            .authority
            .as_ref()
            .ok_or(DownstreamRequestError::InvalidHost)?
            .host()
    };

    // rebuild the request URI, replacing the authority with only the host and ensuring there is
    // a path and scheme
    let path_and_query = uri_parts
        .path_and_query
        .ok_or(DownstreamRequestError::InvalidUrl)?;
    let scheme = uri_parts.scheme.unwrap_or(http::uri::Scheme::HTTP);
    metadata.uri = Uri::builder()
        .scheme(scheme)
        .authority(http_host)
        .path_and_query(path_and_query)
        .build()
        .map_err(|_| DownstreamRequestError::InvalidUrl)?;

    Ok(Request::from_parts(metadata, Body::from(body)))
}
