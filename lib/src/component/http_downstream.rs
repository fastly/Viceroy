use std::time::Duration;

use crate::component::fastly::api::{http_downstream, http_types, types};
use crate::linking::ComponentCtx;
use crate::session::AsyncItemHandle;

#[async_trait::async_trait]
impl http_downstream::Host for ComponentCtx {
    async fn next_request(
        &mut self,
        options_mask: http_downstream::NextRequestOptionsMask,
        options: http_downstream::NextRequestOptions,
    ) -> Result<http_types::RequestPromiseHandle, types::Error> {
        let timeout = options_mask
            .contains(http_downstream::NextRequestOptionsMask::TIMEOUT)
            .then(|| Duration::from_millis(options.timeout_ms));
        let handle = self
            .session
            .register_pending_downstream_req(timeout)
            .await?;

        Ok(handle.as_u32().into())
    }

    async fn next_request_abandon(
        &mut self,
        handle: http_types::RequestPromiseHandle,
    ) -> Result<(), types::Error> {
        let handle = AsyncItemHandle::from_u32(handle.into());
        self.session.abandon_pending_downstream_req(handle)?;
        Ok(())
    }

    async fn next_request_wait(
        &mut self,
        handle: http_types::RequestPromiseHandle,
    ) -> Result<(http_types::RequestHandle, http_types::BodyHandle), types::Error> {
        let handle = AsyncItemHandle::from_u32(handle.into());
        let (req, body) = self.session.resolve_pending_downstream_req(handle).await?;

        Ok((req.into(), body.into()))
    }
}
