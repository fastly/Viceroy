use std::result::Result;

use crate::component::bindings::fastly::adapter::adapter_shielding;
use crate::component::bindings::fastly::compute::types;
use crate::linking::ComponentCtx;

use wasmtime::component::Resource;

impl adapter_shielding::Host for ComponentCtx {
    fn backend_for_shield(
        &mut self,
        target_shield: String,
        options: Option<Resource<adapter_shielding::ShieldBackendOptions>>,
        max_len: u64,
    ) -> Result<String, types::Error> {
        crate::component::shielding::backend_for_shield(
            &mut self.session,
            &mut self.wasi_table,
            &target_shield,
            options,
            max_len,
        )
    }
}
