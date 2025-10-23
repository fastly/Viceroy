use {
    crate::component::bindings::fastly::compute::{log, types},
    crate::linking::{ComponentCtx, SessionView},
    lazy_static::lazy_static,
    wasmtime::component::Resource,
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

impl log::Host for ComponentCtx {}

impl log::HostEndpoint for ComponentCtx {
    fn open(&mut self, name: String) -> Result<Resource<log::Endpoint>, types::OpenError> {
        let name = name.as_bytes();

        if is_reserved_endpoint(name) {
            return Err(types::OpenError::Reserved);
        }

        Ok(self.session_mut().log_endpoint_handle(name).into())
    }

    fn write(&mut self, h: Resource<log::Endpoint>, msg: Vec<u8>) {
        let endpoint = self.session().log_endpoint(h.into()).unwrap();

        // The log API is infallible, so if we get an error, warn about it
        // rather than bubbling it up through the log API.
        match endpoint.write_entry(&msg) {
            Ok(()) => {}
            Err(err) => tracing::error!("Error writing log message: {:?}", err),
        }
    }

    fn drop(&mut self, _endpoint: Resource<log::Endpoint>) -> wasmtime::Result<()> {
        Ok(())
    }
}
