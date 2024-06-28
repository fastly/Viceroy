use {
    super::fastly::api::{erl, types},
    crate::session::Session,
};

#[async_trait::async_trait]
impl erl::Host for Session {
    async fn check_rate(
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

    async fn ratecounter_increment(
        &mut self,
        _rc: String,
        _entry: String,
        _delta: u32,
    ) -> Result<(), types::Error> {
        Ok(())
    }

    async fn ratecounter_lookup_rate(
        &mut self,
        _rc: String,
        _entry: String,
        _window: u32,
    ) -> Result<u32, types::Error> {
        Ok(0)
    }

    async fn ratecounter_lookup_count(
        &mut self,
        _rc: String,
        _entry: String,
        _duration: u32,
    ) -> Result<u32, types::Error> {
        Ok(0)
    }

    async fn penaltybox_add(
        &mut self,
        _pb: String,
        _entry: String,
        _ttl: u32,
    ) -> Result<(), types::Error> {
        Ok(())
    }

    async fn penaltybox_has(&mut self, _pb: String, _entry: String) -> Result<u32, types::Error> {
        Ok(0)
    }
}
