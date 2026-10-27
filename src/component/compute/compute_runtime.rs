use crate::component::bindings::fastly::compute::{compute_runtime, types};
use crate::linking::ComponentCtx;
use std::sync::atomic::Ordering;
use wasmtime::component::Resource;

impl compute_runtime::Host for ComponentCtx {
    fn get_vcpu_ms(&mut self) -> u64 {
        self.sandbox().active_cpu_time_us.load(Ordering::SeqCst) / 1000
    }

    fn get_heap_mib(&mut self) -> compute_runtime::MemoryMib {
        self.sandbox().get_heap_usage_mib()
    }

    fn get_sandbox_id(&mut self) -> String {
        format!("{:032x}", self.sandbox().sandbox_id())
    }

    fn get_hostname(&mut self) -> String {
        "localhost".to_owned()
    }

    fn get_pop(&mut self) -> String {
        "XXX".to_owned()
    }

    fn get_region(&mut self) -> String {
        "Somewhere".to_owned()
    }

    fn get_cache_generation(&mut self) -> u64 {
        0
    }

    fn get_customer_id(&mut self) -> String {
        "0000000000000000000000".to_owned()
    }

    fn get_is_staging(&mut self) -> bool {
        false
    }

    fn get_service_id(&mut self) -> String {
        "0000000000000000000000".to_owned()
    }

    fn get_service_version(&mut self) -> u64 {
        0
    }

    fn get_namespace_id(&mut self) -> String {
        "".to_owned()
    }
}

pub struct Products;

impl compute_runtime::HostProducts for ComponentCtx {
    fn new(&mut self) -> wasmtime::Result<Resource<Products>> {
        Ok(self.wasi_table.push(Products)?)
    }

    fn has_domain_inspector(&mut self, _h: Resource<Products>) -> Result<bool, types::Error> {
        Ok(false)
    }

    fn has_image_optimizer(&mut self, _h: Resource<Products>) -> Result<bool, types::Error> {
        Ok(false)
    }

    fn has_origin_inspector(&mut self, _h: Resource<Products>) -> Result<bool, types::Error> {
        Ok(false)
    }

    fn drop(&mut self, h: Resource<Products>) -> wasmtime::Result<()> {
        self.wasi_table.delete(h)?;
        Ok(())
    }
}
