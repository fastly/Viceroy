use crate::{
    error::Error,
    session::Session,
    wiggle_abi::fastly_erl::FastlyErl,
    wiggle_abi::{GuestMemory, GuestPtr},
};

impl FastlyErl for Session {
    fn check_rate(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        _rc: GuestPtr<str>,
        _entry: GuestPtr<str>,
        _delta: u32,
        _window: u32,
        _limit: u32,
        _pb: GuestPtr<str>,
        _ttl: u32,
    ) -> std::result::Result<u32, Error> {
        Ok(0)
    }

    fn ratecounter_increment(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        _rc: GuestPtr<str>,
        _entry: GuestPtr<str>,
        _delta: u32,
    ) -> std::result::Result<(), Error> {
        Ok(())
    }

    fn ratecounter_lookup_rate(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        _rc: GuestPtr<str>,
        _entry: GuestPtr<str>,
        _window: u32,
    ) -> std::result::Result<u32, Error> {
        Ok(0)
    }

    fn ratecounter_lookup_count(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        _rc: GuestPtr<str>,
        _entry: GuestPtr<str>,
        _duration: u32,
    ) -> std::result::Result<u32, Error> {
        Ok(0)
    }

    fn penaltybox_add(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        _pb: GuestPtr<str>,
        _entry: GuestPtr<str>,
        _ttl: u32,
    ) -> std::result::Result<(), Error> {
        Ok(())
    }

    fn penaltybox_has(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        _pb: GuestPtr<str>,
        _entry: GuestPtr<str>,
    ) -> std::result::Result<u32, Error> {
        Ok(0)
    }
}
