//! fastly_geo` hostcall implementations.

use std::net::{IpAddr, Ipv4Addr};

use {
    crate::{error::Error, session::Session, wiggle_abi::fastly_geo::FastlyGeo},
    std::convert::TryFrom,
    wiggle::GuestPtr,
};

impl FastlyGeo for Session {
    fn lookup(
        &mut self,
        addr_octets: &GuestPtr<u8>,
        addr_len: u32,
        buf: &GuestPtr<u8>,
        buf_len: u32,
        nwritten_out: &GuestPtr<u32>,
    ) -> Result<(), Error> {
        let addr = addr_octets.as_array(addr_len).as_slice()?;
        let ip_addr: IpAddr = match addr_len {
            4 => std::net::IpAddr::V4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3])),
            _ => unimplemented!(),
        };

        let result = self.geoip_lookup(&ip_addr);

        if result.len() > buf_len as usize {
            return Err(Error::BufferLengthError {
                buf: "geoip_lookup",
                len: "geoip_lookup_max_len"
            });
        }

        let result_len =
            u32::try_from(result.len()).expect("smaller than value_max_len means it must fit");


        let mut buf_ptr = buf.as_array(result_len).as_slice_mut()?;
        buf_ptr.copy_from_slice(result.as_bytes());
        nwritten_out.write(result_len)?;
        Ok(())
    }
}
