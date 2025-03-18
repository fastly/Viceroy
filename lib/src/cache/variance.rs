//! Support for request- and response-keyed variance, per HTTP's vary rules
//!
//! HTTP caching as described in RFC 9111 has two components to a key. The first is the "request
//! key", defined by the caching entity -- typically consisting of the URL and often the method.
//! The response from the server may include a Vary header, which lists request field names
//! (i.e. header names) that affect the cacheability of the response. A subsequent request must
//! match all the Vary values in order to use the cached result.
//!
//! The core cache API provides the bones of this.
//!

use std::{fmt::Write, str::FromStr};

use bytes::{Bytes, BytesMut};
pub use http::HeaderName;
use http::{header::InvalidHeaderName, HeaderMap};

use crate::Error;

/// A rule for variance of a request.
///
/// This rule describes what fields (headers) are used to determine whether a new request "matches"
/// a previous response.
///
/// VaryRule is canonicalized, with lowercase-named header names in sorted order.
#[derive(Debug)]
pub struct VaryRule {
    headers: Vec<HeaderName>,
}

impl FromStr for VaryRule {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let headers: Result<Vec<HeaderName>, InvalidHeaderName> =
            s.split(" ").map(HeaderName::try_from).collect();
        let mut headers = headers?;
        headers.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        Ok(VaryRule { headers })
    }
}

impl VaryRule {
    /// Construct the Variant for the given headers: the (header, value) pairs that must be present
    /// to match.
    pub fn variant(&self, headers: &HeaderMap) -> Variant {
        let mut buf = BytesMut::new();
        for header in self.headers.iter() {
            write!(&mut buf, "{}: ", header.as_str()).unwrap();
            for (i, value) in headers.get_all(header).iter().enumerate() {
                if i != 0 {
                    write!(&mut buf, ", ").unwrap();
                }
                buf.extend(value.as_bytes());
            }
            write!(&mut buf, "\r\n").unwrap();
        }
        Variant {
            signature: buf.into(),
        }
    }
}

/// The portion of a cache key that is defined by request and response.
///
/// A `vary_by` directive indicates that a cached object should only be matched if the headers
/// listed in `vary_by` match that of the request that generated the cached object.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Variant {
    /// The internal representation is an HTTP header block: headers and values separated by a CRLF
    /// sequence. However, since header values may contain arbitrary bytes, this is a Bytes rather
    /// than a String.
    signature: Bytes,
}
