//! fastly_geo` hostcall implementations.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    convert::TryInto
};

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
        let octets = addr_octets
            .as_array(addr_len)
            .iter()
            .map(|v| v.unwrap().read().unwrap())
            .collect::<Vec<u8>>();

        let ip_addr: IpAddr = match addr_len {
            4 => IpAddr::V4(Ipv4Addr::from(TryInto::<[u8; 4]>::try_into(octets).unwrap())),
            16 => IpAddr::V6(Ipv6Addr::from(TryInto::<[u8; 16]>::try_into(octets).unwrap())),
            _ => return Err(Error::InvalidArgument),
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
