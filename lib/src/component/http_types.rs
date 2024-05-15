use {
    super::fastly::api::{http_types, types},
    crate::session::Session,
};

impl http_types::Host for Session {}

// The http crate's `Version` is a struct that has a bunch of
// associated constants, not an enum; this is only a partial conversion.
impl TryFrom<http::version::Version> for http_types::HttpVersion {
    type Error = types::Error;
    fn try_from(v: http::version::Version) -> Result<Self, Self::Error> {
        match v {
            http::version::Version::HTTP_09 => Ok(http_types::HttpVersion::Http09),
            http::version::Version::HTTP_10 => Ok(http_types::HttpVersion::Http10),
            http::version::Version::HTTP_11 => Ok(http_types::HttpVersion::Http11),
            http::version::Version::HTTP_2 => Ok(http_types::HttpVersion::H2),
            http::version::Version::HTTP_3 => Ok(http_types::HttpVersion::H3),
            _ => Err(types::Error::Unsupported),
        }
    }
}

impl From<http_types::HttpVersion> for http::version::Version {
    fn from(v: http_types::HttpVersion) -> http::version::Version {
        match v {
            http_types::HttpVersion::Http09 => http::version::Version::HTTP_09,
            http_types::HttpVersion::Http10 => http::version::Version::HTTP_10,
            http_types::HttpVersion::Http11 => http::version::Version::HTTP_11,
            http_types::HttpVersion::H2 => http::version::Version::HTTP_2,
            http_types::HttpVersion::H3 => http::version::Version::HTTP_3,
        }
    }
}
