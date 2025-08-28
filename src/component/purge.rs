use {
    super::fastly::api::{purge, types},
    crate::{
        error::Error,
        linking::{ComponentCtx, SessionView},
    },
};

impl purge::Host for ComponentCtx {
    async fn purge_surrogate_key(
        &mut self,
        surrogate_key: String,
        mut options: purge::PurgeOptionsMask,
        _max_len: u64,
    ) -> Result<Option<String>, types::Error> {
        let soft_purge = options.contains(purge::PurgeOptionsMask::SOFT_PURGE);
        // We handle SOFT_PURGE below; clear it.
        options &= !purge::PurgeOptionsMask::SOFT_PURGE;

        if options != purge::PurgeOptionsMask::empty() {
            return Err(Error::Unsupported {
                msg: "unsupported purge option",
            }
            .into());
        }

        let surrogate_key = surrogate_key.parse()?;
        let purged = self.session().cache().purge(surrogate_key, soft_purge);
        tracing::debug!("{purged} variants purged");
        Ok(None)
    }
}
