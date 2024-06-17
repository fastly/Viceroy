use {
    super::fastly::api::{log, types},
    crate::session::Session,
    lazy_static::lazy_static,
};

fn is_reserved_endpoint(name: &[u8]) -> bool {
    use regex::bytes::{RegexSet, RegexSetBuilder};
    const RESERVED_ENDPOINTS: &[&str] = &["^stdout$", "^stderr$", "^fst_managed_"];
    lazy_static! {
        static ref RESERVED_ENDPOINT_RE: RegexSet = RegexSetBuilder::new(RESERVED_ENDPOINTS)
            .case_insensitive(true)
            .build()
            .unwrap();
    }
    RESERVED_ENDPOINT_RE.is_match(name)
}

#[async_trait::async_trait]
impl log::Host for Session {
    async fn endpoint_get(&mut self, name: String) -> Result<log::Handle, types::Error> {
        let name = name.as_bytes();

        if is_reserved_endpoint(name) {
            return Err(types::Error::InvalidArgument.into());
        }

        Ok(self.log_endpoint_handle(name).into())
    }

    async fn write(&mut self, h: log::Handle, msg: String) -> Result<u32, types::Error> {
        let endpoint = self.log_endpoint(h.into())?;
        let msg = msg.as_bytes();
        endpoint.write_entry(&msg)?;
        Ok(u32::try_from(msg.len()).unwrap())
    }
}
