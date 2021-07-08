//! fastly_uap` hostcall implementations.

use {
    crate::{error::Error, session::Session, wiggle_abi::fastly_uap::FastlyUap},
    wiggle::GuestPtr,
};

impl FastlyUap for Session {
    #[allow(unused_variables)] // FIXME KTM 2020-06-25: Remove this directive once implemented.
    fn parse<'a>(
        &mut self,
        user_agent: &GuestPtr<'a, str>,
        family: &GuestPtr<'a, u8>,
        family_len: u32,
        family_nwritten_out: &GuestPtr<'a, u32>,
        major: &GuestPtr<'a, u8>,
        major_len: u32,
        major_nwritten_out: &GuestPtr<'a, u32>,
        minor: &GuestPtr<'a, u8>,
        minor_len: u32,
        minor_nwritten_out: &GuestPtr<'a, u32>,
        patch: &GuestPtr<'a, u8>,
        patch_len: u32,
        patch_nwritten_out: &GuestPtr<'a, u32>,
    ) -> Result<(), Error> {
        todo!()
    }
}
