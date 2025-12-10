use crate::component::{bindings::fastly::adapter::adapter_erl, bindings::fastly::compute::types};
use crate::linking::ComponentCtx;

impl adapter_erl::Host for ComponentCtx {
    fn check_rate(
        &mut self,
        rc: String,
        entry: String,
        delta: u32,
        window: u32,
        limit: u32,
        pb: String,
        ttl: u32,
    ) -> Result<bool, types::Error> {
        crate::component::erl::check_rate(
            &mut self.session,
            &rc,
            entry,
            delta,
            window,
            limit,
            &pb,
            ttl,
        )
    }

    fn ratecounter_increment(
        &mut self,
        rc: String,
        entry: String,
        delta: u32,
    ) -> Result<(), types::Error> {
        crate::component::erl::ratecounter_increment(&mut self.session, &rc, entry, delta)
    }

    fn ratecounter_lookup_rate(
        &mut self,
        rc: String,
        entry: String,
        window: u32,
    ) -> Result<u32, types::Error> {
        crate::component::erl::ratecounter_lookup_rate(&mut self.session, &rc, entry, window)
    }

    fn ratecounter_lookup_count(
        &mut self,
        rc: String,
        entry: String,
        duration: u32,
    ) -> Result<u32, types::Error> {
        crate::component::erl::ratecounter_lookup_count(&mut self.session, &rc, entry, duration)
    }

    fn penaltybox_add(&mut self, pb: String, entry: String, ttl: u32) -> Result<(), types::Error> {
        crate::component::erl::penaltybox_add(&mut self.session, &pb, entry, ttl)
    }

    fn penaltybox_has(&mut self, pb: String, entry: String) -> Result<bool, types::Error> {
        crate::component::erl::penaltybox_has(&mut self.session, &pb, entry)
    }
}
