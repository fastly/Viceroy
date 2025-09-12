use {
    super::fastly::api::{device_detection, types},
    crate::linking::{ComponentCtx, SessionView},
};

impl device_detection::Host for ComponentCtx {
    async fn lookup(
        &mut self,
        user_agent: String,
        max_len: u64,
    ) -> Result<Option<Vec<u8>>, types::Error> {
        if let Some(result) = self.session().device_detection_lookup(&user_agent) {
            if result.len() > max_len as usize {
                return Err(types::Error::BufferLen(
                    u64::try_from(result.len()).unwrap_or(0),
                ));
            }

            Ok(Some(result.into_bytes()))
        } else {
            Ok(None)
        }
    }
}
