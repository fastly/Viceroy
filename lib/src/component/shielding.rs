use super::fastly::api::{shielding, types};
use crate::linking::ComponentCtx;

#[async_trait::async_trait]
impl shielding::Host for ComponentCtx {
    async fn shield_info(&mut self, name: Vec<u8>, _max_len: u64) -> Result<Vec<u8>, types::Error> {
        // Validate input name and return the unsupported error.
        let _name = String::from_utf8(name)?;

        Err(types::Error::Unsupported)
    }

    async fn backend_for_shield(
        &mut self,
        name: Vec<u8>,
        options_mask: shielding::ShieldBackendOptionsMask,
        options: shielding::ShieldBackendOptions,
        _max_len: u64,
    ) -> Result<Vec<u8>, types::Error> {
        // Validate our inputs and return the unsupported error.
        let _target_shield = String::from_utf8(name)?;

        if options_mask.contains(shielding::ShieldBackendOptionsMask::CACHE_KEY) {
            let _ = String::from_utf8(options.cache_key)?;
        }

        Err(types::Error::Unsupported)
    }
}
