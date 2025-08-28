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

use crate::bindings::fastly::api::types;

/// Encode a Wit `IpAddress` into the `ip_octets` buffer, and return the number of bytes written.
pub(crate) unsafe fn encode_ip_address(ip_addr: types::IpAddress, ip_octets: *mut u8) -> usize {
    let bytes = match ip_addr {
        types::IpAddress::Ipv4(bytes) => &<[u8; 4]>::from(bytes)[..],
        types::IpAddress::Ipv6(segments) => {
            &std::net::Ipv6Addr::from(<[u16; 8]>::from(segments)).octets()[..]
        }
    };
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), ip_octets, bytes.len());
    bytes.len()
}
