//! fastly_uap` hostcall implementations.

use {
    crate::{error::Error, session::Session, wiggle_abi::fastly_uap::FastlyUap},
    wiggle::{GuestMemory, GuestPtr},
};

impl FastlyUap for Session {
    fn parse(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        _user_agent: GuestPtr<str>,
        _family: GuestPtr<u8>,
        _family_len: u32,
        _family_nwritten_out: GuestPtr<u32>,
        _major: GuestPtr<u8>,
        _major_len: u32,
        _major_nwritten_out: GuestPtr<u32>,
        _minor: GuestPtr<u8>,
        _minor_len: u32,
        _minor_nwritten_out: GuestPtr<u32>,
        _patch: GuestPtr<u8>,
        _patch_len: u32,
        _patch_nwritten_out: GuestPtr<u32>,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("Useragent parsing"))
    }
}
