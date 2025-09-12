use {
    super::fastly::api::{async_io, types},
    crate::{
        linking::{ComponentCtx, SessionView},
        wiggle_abi,
    },
    futures::FutureExt,
    std::time::Duration,
};

impl async_io::Host for ComponentCtx {
    async fn select(
        &mut self,
        hs: Vec<async_io::Handle>,
        timeout_ms: u32,
    ) -> Result<Option<u32>, types::Error> {
        if hs.is_empty() && timeout_ms == 0 {
            return Err(types::Error::InvalidArgument.into());
        }

        let select_fut = self.session_mut().select_impl(
            hs.iter()
                .copied()
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

    async fn is_ready(&mut self, handle: async_io::Handle) -> Result<bool, types::Error> {
        let handle = wiggle_abi::types::AsyncItemHandle::from(handle);
        Ok(self
            .session_mut()
            .async_item_mut(handle.into())?
            .await_ready()
            .now_or_never()
            .is_some())
    }
}
