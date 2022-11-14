//! fastly_purge` hostcall implementations.

use {
    super::types::{PurgeOptions, PurgeOptionsMask},
    crate::{error::Error, session::Session, wiggle_abi::fastly_purge::FastlyPurge},
    wiggle::GuestPtr,
};

impl FastlyPurge for Session {
    #[allow(unused_variables)] // FIXME FDE 2022-09-26: Remove this directive once implemented.
    fn purge_surrogate_key<'a>(
        &mut self,
        surrogate_key: &GuestPtr<'a, str>,
        options_mask: PurgeOptionsMask,
        options: &GuestPtr<'a, PurgeOptions<'a>>,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("FastlyPurge"))
    }
}
