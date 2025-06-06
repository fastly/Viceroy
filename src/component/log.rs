use {
    super::fastly::api::{log, types},
    crate::component::component::Resource,
    crate::linking::ComponentCtx,
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
impl log::HostHandle for ComponentCtx {
    async fn endpoint_get(&mut self, name: String) -> Result<Resource<log::Handle>, types::Error> {
        let name = name.as_bytes();

        if is_reserved_endpoint(name) {
            return Err(types::Error::InvalidArgument.into());
        }

        Ok(self.session.log_endpoint_handle(name).into())
    }

    async fn write(&mut self, h: Resource<log::Handle>, msg: Vec<u8>) -> Result<u32, types::Error> {
        let endpoint = self.session.log_endpoint(h.into())?;
        endpoint.write_entry(&msg)?;
        Ok(u32::try_from(msg.len()).unwrap())
    }

    async fn drop(&mut self, _h: Resource<log::Handle>) -> anyhow::Result<()> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl log::Host for ComponentCtx {}
