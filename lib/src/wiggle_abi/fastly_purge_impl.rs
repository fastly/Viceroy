//! fastly_purge` hostcall implementations.

use {
    super::types::{PurgeOptions, PurgeOptionsMask},
    crate::{error::Error, session::Session, wiggle_abi::fastly_purge::FastlyPurge},
    wiggle::{GuestMemory, GuestPtr},
};

impl FastlyPurge for Session {
    fn purge_surrogate_key(
        &mut self,
        memory: &mut GuestMemory<'_>,
        surrogate_key: GuestPtr<str>,
        options_mask: PurgeOptionsMask,
        _options: GuestPtr<PurgeOptions>,
    ) -> Result<(), Error> {
        if options_mask.contains(PurgeOptionsMask::SOFT_PURGE) {
            return Err(Error::NotAvailable("soft purge"));
        }
        if options_mask.contains(PurgeOptionsMask::RET_BUF) {
            return Err(Error::NotAvailable("purge response"));
        }

        let key = memory
            .as_str(surrogate_key)?
            .ok_or(Error::SharedMemory)?
            .parse()?;
        let purged = self.cache().purge(key);
        tracing::debug!("{purged} variants purged");
        Ok(())
    }
}
