use crate::component::fastly::compute::compute_runtime;
use crate::linking::{ComponentCtx, SessionView};
use std::sync::atomic::Ordering;

impl compute_runtime::Host for ComponentCtx {
    async fn get_vcpu_ms(&mut self) -> u64 {
        self.session().active_cpu_time_us.load(Ordering::SeqCst) / 1000
    }

    async fn get_session_id(&mut self) -> String {
        format!("{:032x}", self.session().session_id())
    }

    async fn get_hostname(&mut self) -> String {
        "localhost".to_owned()
    }

    async fn get_pop(&mut self) -> String {
        "XXX".to_owned()
    }

    async fn get_region(&mut self) -> String {
        "Somewhere".to_owned()
    }

    async fn get_cache_generation(&mut self) -> u64 {
        0
    }

    async fn get_customer_id(&mut self) -> String {
        "0000000000000000000000".to_owned()
    }

    async fn get_is_staging(&mut self) -> bool {
        false
    }

    async fn get_service_id(&mut self) -> String {
        "0000000000000000000000".to_owned()
    }

    async fn get_service_version(&mut self) -> u64 {
        0
    }

    async fn get_namespace_id(&mut self) -> String {
        "".to_owned()
    }
}
