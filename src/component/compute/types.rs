use {crate::component::bindings::fastly::compute::types, crate::linking::ComponentCtx};

impl types::Host for ComponentCtx {}

impl From<std::net::IpAddr> for types::IpAddress {
    fn from(addr: std::net::IpAddr) -> Self {
        match addr {
            std::net::IpAddr::V4(addr) => types::IpAddress::Ipv4(addr.octets().into()),
            std::net::IpAddr::V6(addr) => types::IpAddress::Ipv6(addr.segments().into()),
        }
    }
}

impl From<types::IpAddress> for std::net::IpAddr {
    fn from(addr: types::IpAddress) -> Self {
        match addr {
            types::IpAddress::Ipv4(tuple) => <[u8; 4]>::from(tuple).into(),
            types::IpAddress::Ipv6(tuple) => <[u16; 8]>::from(tuple).into(),
        }
    }
}
