use crate::component::bindings::fastly::compute::compute_runtime;
use crate::linking::ComponentCtx;
use std::sync::atomic::Ordering;

impl compute_runtime::Host for ComponentCtx {
    fn get_vcpu_ms(&mut self) -> u64 {
        self.session().active_cpu_time_us.load(Ordering::SeqCst) / 1000
    }

    fn get_heap_mib(&mut self) -> compute_runtime::MemoryMib {
        self.session().get_heap_usage_mib()
    }

    fn get_sandbox_id(&mut self) -> String {
        format!("{:032x}", self.session().session_id())
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
