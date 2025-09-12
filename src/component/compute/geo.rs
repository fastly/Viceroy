use {
    crate::component::bindings::fastly::compute::{geo, types},
    crate::{error, linking::ComponentCtx},
    std::net::IpAddr,
};

impl geo::Host for ComponentCtx {
    fn lookup(&mut self, addr: types::IpAddress, max_len: u64) -> Result<String, types::Error> {
        let ip_addr: IpAddr = addr.into();

        let json = self
            .session()
            .geolocation_lookup(&ip_addr)
            .ok_or(geo::Error::GenericError)?;

        if json.len() > usize::try_from(max_len).unwrap() {
            return Err(error::Error::BufferLengthError {
                buf: "geo_out",
                len: "geo_max_len",
            }
            .into());
        }

        Ok(json)
    }
}
