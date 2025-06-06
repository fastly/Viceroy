use {
    super::fastly::api::{async_io, types},
    crate::component::component::Resource,
    crate::{linking::ComponentCtx, wiggle_abi},
    futures::FutureExt,
    std::time::Duration,
};

#[async_trait::async_trait]
impl async_io::Host for ComponentCtx {
    async fn select(
        &mut self,
        hs: Vec<Resource<async_io::Handle>>,
        timeout_ms: u32,
    ) -> Result<Option<u32>, types::Error> {
        if hs.is_empty() && timeout_ms == 0 {
            return Err(types::Error::InvalidArgument);
        }

        let select_fut = self.session.select_impl(
            hs.into_iter()
                .map(|i| wiggle_abi::types::AsyncItemHandle::from(i).into()),
        );

        if timeout_ms == 0 {
            let h = select_fut.await?;
            return Ok(Some(h as u32));
        }

        let res = tokio::time::timeout(Duration::from_millis(timeout_ms as u64), select_fut).await;

        match res {
            // got a handle
            Ok(Ok(h)) => Ok(Some(h as u32)),

            // timeout elapsed
            Err(_) => Ok(None),

            // some other error happened, but the future resolved
            Ok(Err(e)) => Err(e.into()),
        }
    }
}

#[async_trait::async_trait]
impl async_io::HostHandle for ComponentCtx {
    async fn is_ready(&mut self, handle: Resource<async_io::Handle>) -> Result<bool, types::Error> {
        let handle = wiggle_abi::types::AsyncItemHandle::from(handle);
        Ok(self
            .session
            .async_item_mut(handle.into())?
            .await_ready()
            .now_or_never()
            .is_some())
    }

    async fn drop(&mut self, _handle: Resource<async_io::Handle>) -> anyhow::Result<()> {
        Ok(())
    }
}
