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
        mut options_mask: PurgeOptionsMask,
        _options: GuestPtr<PurgeOptions>,
    ) -> Result<(), Error> {
        let soft_purge = options_mask.contains(PurgeOptionsMask::SOFT_PURGE);
        options_mask &= !PurgeOptionsMask::SOFT_PURGE;

        if options_mask != PurgeOptionsMask::empty() {
            return Err(Error::Unsupported {
                msg: "unsupported purge option",
            });
        }

        let key = memory
            .as_str(surrogate_key)?
            .ok_or(Error::SharedMemory)?
            .parse()?;
        let purged = self.cache().purge(key, soft_purge);
        tracing::debug!("{purged} variants purged");
        Ok(())
    }
}
