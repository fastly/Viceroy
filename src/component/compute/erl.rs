use {
    crate::component::bindings::fastly::compute::{erl, types},
    crate::linking::ComponentCtx,
};

impl erl::Host for ComponentCtx {
    fn check_rate(
        &mut self,
        _rc: String,
        _entry: String,
        _delta: u32,
        _window: u32,
        _limit: u32,
        _pb: String,
        _ttl: u32,
    ) -> Result<u32, types::Error> {
        Ok(0)
    }

    fn ratecounter_increment(
        &mut self,
        _rc: String,
        _entry: String,
        _delta: u32,
    ) -> Result<(), types::Error> {
        Ok(())
    }

    fn ratecounter_lookup_rate(
        &mut self,
        _rc: String,
        _entry: String,
        _window: u32,
    ) -> Result<u32, types::Error> {
        Ok(0)
    }

    fn ratecounter_lookup_count(
        &mut self,
        _rc: String,
        _entry: String,
        _duration: u32,
    ) -> Result<u32, types::Error> {
        Ok(0)
    }

    fn penaltybox_add(
        &mut self,
        _pb: String,
        _entry: String,
        _ttl: u32,
    ) -> Result<(), types::Error> {
        Ok(())
    }

    fn penaltybox_has(&mut self, _pb: String, _entry: String) -> Result<bool, types::Error> {
        Ok(false)
    }
}
