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

use std::str::FromStr;

use http::header::InvalidHeaderName;
pub use http::HeaderName;

use crate::Error;

/// A rule for variance of a request.
///
/// This rule describes what fields (headers) are used to determine whether a new request "matches"
/// a previous response.
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
