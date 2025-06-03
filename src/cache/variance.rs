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

use std::{collections::HashSet, str::FromStr};

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
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VaryRule {
    headers: Vec<HeaderName>,
}

impl FromStr for VaryRule {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let headers: Result<Vec<HeaderName>, InvalidHeaderName> =
            s.split(" ").map(HeaderName::try_from).collect();
        Ok(VaryRule::new(headers?.iter()))
    }
}

impl VaryRule {
    pub fn new<'a>(headers: impl Iterator<Item = &'a HeaderName>) -> VaryRule {
        // Deduplicate:
        let headers: HashSet<HeaderName> = headers.cloned().collect();
        let mut headers: Vec<HeaderName> = headers.into_iter().collect();
        headers.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        VaryRule { headers }
    }

    /// Construct the Variant for the given headers: the (header, value) pairs that must be present
    /// for a request to match a response.
    pub fn variant(&self, headers: &HeaderMap) -> Variant {
        let mut buf = BytesMut::new();
        // Include the count, to avoid confusion from values that might contain our marker phrases.
        buf.extend_from_slice(format!("[headers: {}]", self.headers.len()).as_bytes());

        for header in self.headers.iter() {
            buf.extend_from_slice(format!("[header: {}]", header.as_str().len()).as_bytes());
            buf.extend_from_slice(header.as_str().as_bytes());

            let values = headers.get_all(header);
            buf.extend_from_slice(format!("[values: {}]", values.iter().count()).as_bytes());

            for value in values.iter() {
                buf.extend_from_slice(format!("[value: {}]", value.as_bytes().len()).as_bytes());
                buf.extend_from_slice(value.as_bytes());
            }
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
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default, Clone)]
pub struct Variant {
    /// The internal representation is an HTTP header block: headers and values separated by a CRLF
    /// sequence. However, since header values may contain arbitrary bytes, this is a Bytes rather
    /// than a String.
    signature: Bytes,
}

#[cfg(test)]
mod tests {
    use super::VaryRule;

    #[test]
    fn vary_rule_uniqe_sorted() {
        let vary1: VaryRule = "unknown-header Accept content-type".parse().unwrap();
        let vary2: VaryRule = "content-type unknown-header unknown-header Accept"
            .parse()
            .unwrap();
        assert_eq!(vary1, vary2);
    }
}
