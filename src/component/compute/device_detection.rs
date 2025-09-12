use {
    crate::component::bindings::fastly::compute::{device_detection, types},
    crate::linking::ComponentCtx,
};

impl device_detection::Host for ComponentCtx {
    fn lookup(&mut self, user_agent: String, max_len: u64) -> Result<Option<String>, types::Error> {
        if let Some(result) = self.session().device_detection_lookup(&user_agent) {
            if result.len() > max_len as usize {
                return Err(types::Error::BufferLen(
                    u64::try_from(result.len()).unwrap_or(0),
                ));
            }

            Ok(Some(result))
        } else {
            Ok(None)
        }
    }
}
