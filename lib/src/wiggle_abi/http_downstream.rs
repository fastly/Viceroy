use std::time::Duration;

use crate::error::Error;
use crate::session::{AsyncItemHandle, Session};
use crate::wiggle_abi::fastly_http_downstream::FastlyHttpDownstream;
use crate::wiggle_abi::types::{
    BodyHandle, NextRequestOptions, NextRequestOptionsMask, RequestHandle, RequestPromiseHandle,
};

use wiggle::{GuestMemory, GuestPtr};

#[wiggle::async_trait]
impl FastlyHttpDownstream for Session {
    async fn next_request(
        &mut self,
        memory: &mut GuestMemory<'_>,
        options_mask: NextRequestOptionsMask,
        options: GuestPtr<NextRequestOptions>,
    ) -> Result<RequestPromiseHandle, Error> {
        let options = memory.read(options)?;
        let timeout = options_mask
            .contains(NextRequestOptionsMask::TIMEOUT)
            .then(|| Duration::from_millis(options.timeout_ms));
        let handle = self.register_pending_downstream_req(timeout).await?;
        Ok(handle.as_u32().into())
    }

    async fn next_request_abandon(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        handle: RequestPromiseHandle,
    ) -> Result<(), Error> {
        let handle = AsyncItemHandle::from_u32(handle.into());
        self.abandon_pending_downstream_req(handle)?;
        Ok(())
    }

    async fn next_request_wait(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        handle: RequestPromiseHandle,
    ) -> Result<(RequestHandle, BodyHandle), Error> {
        let handle = AsyncItemHandle::from_u32(handle.into());
        let (req, body) = self.resolve_pending_downstream_req(handle).await?;
        Ok((req, body))
    }
}
