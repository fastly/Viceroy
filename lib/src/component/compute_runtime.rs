use super::fastly::api::{compute_runtime, types};
use crate::linking::{ComponentCtx, SessionView};
use std::sync::atomic::Ordering;

impl compute_runtime::Host for ComponentCtx {
    async fn get_vcpu_ms(&mut self) -> Result<u64, types::Error> {
        Ok(self.session().active_cpu_time_us.load(Ordering::SeqCst) / 1000)
    }
}
