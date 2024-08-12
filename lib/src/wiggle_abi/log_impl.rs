//! fastly_log` hostcall implementations.

use {
    crate::{
        error::Error,
        session::Session,
        wiggle_abi::{fastly_log::FastlyLog, types::EndpointHandle},
    },
    anyhow::anyhow,
    lazy_static::lazy_static,
    wiggle::{GuestMemory, GuestPtr},
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

impl FastlyLog for Session {
    fn endpoint_get(
        &mut self,
        memory: &mut GuestMemory<'_>,
        name: GuestPtr<[u8]>,
    ) -> Result<EndpointHandle, Error> {
        let name = memory.as_slice(name)?.ok_or(Error::SharedMemory)?;

        if is_reserved_endpoint(&name) {
            return Err(Error::InvalidArgument);
        }

        Ok(self.log_endpoint_handle(&name))
    }

    fn write(
        &mut self,
        memory: &mut GuestMemory<'_>,
        endpoint_handle: EndpointHandle,
        msg: GuestPtr<[u8]>,
    ) -> Result<u32, Error> {
        let endpoint = self.log_endpoint(endpoint_handle)?;
        let msg = memory.as_slice(msg)?.ok_or(Error::SharedMemory)?;
        endpoint
            .write_entry(&msg)
            .map(|_| msg.len() as u32)
            .map_err(|e| Error::Other(anyhow!(e)))
    }
}
