//! Operations related to handling the "downstream" (end-client) request
use std::net::SocketAddr;

use crate::body::Body;
use crate::error::DownstreamRequestError;
use http::Request;
use hyper::Uri;
use tokio::sync::oneshot::Sender;

#[derive(Debug)]
pub struct DownstreamMetadata {
    // A unique request ID.
    pub req_id: u64,
    /// The IP address and port that received this request.
    pub server_addr: SocketAddr,
    /// The downstream IP address and port for this request.
    pub client_addr: SocketAddr,
    /// The compliance region that this request was received in.
    ///
    /// For now this is just always `"none"`, but we place the field in the session
    /// to make it easier to implement custom configuration values later on.
    pub compliance_region: Vec<u8>,
}

#[derive(Debug)]
pub struct DownstreamRequest {
    pub req: hyper::Request<Body>,
    pub metadata: DownstreamMetadata,
    pub sender: Sender<hyper::Response<Body>>,
}

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
