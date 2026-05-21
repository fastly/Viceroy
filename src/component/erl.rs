use {crate::component::bindings::fastly::compute::types, crate::sandbox::Sandbox};

#[allow(clippy::too_many_arguments)]
pub(crate) fn check_rate(
    _sandbox: &mut Sandbox,
    _rc: &str,
    _entry: String,
    _delta: u32,
    _window: u32,
    _limit: u32,
    _pb: &str,
    _ttl: u32,
) -> Result<bool, types::Error> {
    Ok(false)
}

pub(crate) fn ratecounter_increment(
    _sandbox: &mut Sandbox,
    _rc: &str,
    _entry: String,
    _delta: u32,
) -> Result<(), types::Error> {
    Ok(())
}

pub(crate) fn ratecounter_lookup_rate(
    _sandbox: &mut Sandbox,
    _rc: &str,
    _entry: String,
    _window: u32,
) -> Result<u32, types::Error> {
    Ok(0)
}

pub(crate) fn ratecounter_lookup_count(
    _sandbox: &mut Sandbox,
    _rc: &str,
    _entry: String,
    _duration: u32,
) -> Result<u32, types::Error> {
    Ok(0)
}

pub(crate) fn penaltybox_add(
    _sandbox: &mut Sandbox,
    _pb: &str,
    _entry: String,
    _ttl: u32,
) -> Result<(), types::Error> {
    Ok(())
}

pub(crate) fn penaltybox_has(
    _sandbox: &mut Sandbox,
    _pb: &str,
    _entry: String,
) -> Result<bool, types::Error> {
    Ok(false)
}
