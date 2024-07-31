use super::fastly::api::{types, compute_runtime};
use crate::session::Session;
use std::sync::atomic::Ordering;

#[async_trait::async_trait]
impl compute_runtime::Host for Session {
    async fn get_vcpu_ms(&mut self) -> Result<u64, types::Error> {
        Ok(self.active_cpu_time_us.load(Ordering::SeqCst) / 1000)
    }
}
