use {
    super::fastly::api::{geo, types},
    crate::{
        error,
        linking::{ComponentCtx, SessionView},
    },
    std::net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

impl geo::Host for ComponentCtx {
    async fn lookup(&mut self, octets: Vec<u8>, max_len: u64) -> Result<Vec<u8>, types::Error> {
        let ip_addr: IpAddr = match octets.len() {
            4 => IpAddr::V4(Ipv4Addr::from(
                TryInto::<[u8; 4]>::try_into(octets).unwrap(),
            )),
            16 => IpAddr::V6(Ipv6Addr::from(
                TryInto::<[u8; 16]>::try_into(octets).unwrap(),
            )),
            _ => return Err(error::Error::InvalidArgument.into()),
        };

        let json = self
            .session()
            .geolocation_lookup(&ip_addr)
            .ok_or(geo::Error::UnknownError)?;

        if json.len() > usize::try_from(max_len).unwrap() {
            return Err(error::Error::BufferLengthError {
                buf: "geo_out",
                len: "geo_max_len",
            }
            .into());
        }

        Ok(json.into_bytes())
    }
}
