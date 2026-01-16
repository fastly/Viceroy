use crate::error::Error;
use crate::session::Session;
use crate::wiggle_abi::fastly_compute_runtime::FastlyComputeRuntime;
use std::sync::atomic::Ordering;
use wiggle::GuestMemory;

impl FastlyComputeRuntime for Session {
    fn get_vcpu_ms(&mut self, _memory: &mut GuestMemory<'_>) -> Result<u64, Error> {
        // we internally track microseconds, because our wasmtime tick length
        // is too short for ms to work. but we want to shrink this to ms to
        // try to minimize timing attacks.
        Ok(self.active_cpu_time_us.load(Ordering::SeqCst) / 1000)
    }

    fn get_heap_mib(&mut self, _memory: &mut GuestMemory<'_>) -> Result<u32, Error> {
        Ok(self.get_heap_usage_mib())
    }
}
