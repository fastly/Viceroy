use {
    super::fastly::compute_at_edge::{geo, types},
    crate::{error, session::Session},
    std::net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

#[async_trait::async_trait]
impl geo::Host for Session {
    async fn lookup(&mut self, octets: Vec<u8>) -> Result<String, types::FastlyError> {
        let ip_addr: IpAddr = match octets.len() {
            4 => IpAddr::V4(Ipv4Addr::from(
                TryInto::<[u8; 4]>::try_into(octets).unwrap(),
            )),
            16 => IpAddr::V6(Ipv6Addr::from(
                TryInto::<[u8; 16]>::try_into(octets).unwrap(),
            )),
            _ => return Err(error::Error::InvalidArgument.into()),
        };

        Ok(self.geolocation_lookup(&ip_addr).ok_or(geo::Error::UnknownError)?)
    }
}
