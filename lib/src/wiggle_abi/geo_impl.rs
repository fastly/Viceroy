//! fastly_geo` hostcall implementations.

use {
    crate::{error::Error, session::Session, wiggle_abi::fastly_geo::FastlyGeo},
    wiggle::GuestPtr,
};

impl FastlyGeo for Session {
    #[allow(unused_variables)] // FIXME: Remove this directive once implemented.
    fn lookup(
        &mut self,
        addr_octets: &GuestPtr<u8>,
        add_len: u32,
        buf: &GuestPtr<u8>,
        buf_len: u32,
        nwritten_out: &GuestPtr<u32>,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("GeoIP"))
    }
}
