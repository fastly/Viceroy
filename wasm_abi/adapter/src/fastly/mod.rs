mod adapter;
mod cache;
mod config_store;
mod core;
mod error;
mod http_cache;
mod macros;

pub(crate) use error::*;

pub use cache::*;
pub use config_store::*;
pub use core::*;
pub use http_cache::*;

/// Decode an IP address from `ip_len` bytes pointed to by `ip_octets` into a Wit `IpAddress`.
pub(crate) unsafe fn decode_ip_address(
    ip_octets: *const u8,
    ip_len: usize,
) -> Option<crate::bindings::fastly::compute::types::IpAddress> {
    let ip = std::slice::from_raw_parts(ip_octets, ip_len);
    if let Ok(bytes) = <[u8; 4]>::try_from(ip) {
        Some(crate::bindings::fastly::compute::types::IpAddress::Ipv4(
            bytes.into(),
        ))
    } else if let Ok(bytes) = <[u8; 16]>::try_from(ip) {
        Some(crate::bindings::fastly::compute::types::IpAddress::Ipv6(
            std::net::Ipv6Addr::from(bytes).segments().into(),
        ))
    } else {
        None
    }
}

/// Encode a Wit `IpAddress` into the `ip_octets` buffer, and return the number of bytes written.
pub(crate) unsafe fn encode_ip_address(
    ip_addr: crate::bindings::fastly::compute::types::IpAddress,
    ip_octets: *mut u8,
) -> usize {
    let bytes = match ip_addr {
        crate::bindings::fastly::compute::types::IpAddress::Ipv4(bytes) => {
            &<[u8; 4]>::from(bytes)[..]
        }
        crate::bindings::fastly::compute::types::IpAddress::Ipv6(segments) => {
            &std::net::Ipv6Addr::from(<[u16; 8]>::from(segments)).octets()[..]
        }
    };
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), ip_octets, bytes.len());
    bytes.len()
}
