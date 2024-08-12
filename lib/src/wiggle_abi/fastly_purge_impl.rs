//! fastly_purge` hostcall implementations.

use {
    super::types::{PurgeOptions, PurgeOptionsMask},
    crate::{error::Error, session::Session, wiggle_abi::fastly_purge::FastlyPurge},
    wiggle::{GuestMemory, GuestPtr},
};

impl FastlyPurge for Session {
    fn purge_surrogate_key(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        _surrogate_key: GuestPtr<str>,
        _options_mask: PurgeOptionsMask,
        _options: GuestPtr<PurgeOptions>,
    ) -> Result<(), Error> {
        Err(Error::NotAvailable("FastlyPurge"))
    }
}
