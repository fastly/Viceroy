use {
    crate::component::bindings::fastly::compute::async_io,
    crate::{
        linking::{ComponentCtx, SessionView},
        wiggle_abi,
    },
    anyhow::bail,
    futures::FutureExt,
    std::time::Duration,
    wasmtime::component::Resource,
};

impl async_io::Host for ComponentCtx {
    async fn select(&mut self, hs: Vec<Resource<async_io::Pollable>>) -> wasmtime::Result<u32> {
        if hs.is_empty() {
            bail!("`select` without a timeout must have at least one handle");
        }

        let select_fut = self.session_mut().select_impl(
            hs.into_iter()
                .map(|i| wiggle_abi::types::AsyncItemHandle::from(i).into()),
        );

        let h = select_fut.await.unwrap();
        Ok(h as u32)
    }

    async fn select_with_timeout(
        &mut self,
        hs: Vec<Resource<async_io::Pollable>>,
        timeout_ms: u32,
    ) -> Option<u32> {
        let select_fut = self.session_mut().select_impl(hs.into_iter().map(|i| {
            crate::session::AsyncItemHandle::from(wiggle_abi::types::AsyncItemHandle::from(i))
        }));

        tokio::time::timeout(Duration::from_millis(timeout_ms as u64), select_fut)
            .await
            .ok()
            .map(|h| h.unwrap() as u32)
    }
}

impl async_io::HostPollable for ComponentCtx {
    fn new_ready(&mut self) -> Resource<async_io::Pollable> {
        wiggle_abi::types::AsyncItemHandle::from(self.session_mut().new_ready()).into()
    }

    fn is_ready(&mut self, handle: Resource<async_io::Pollable>) -> bool {
        let handle = wiggle_abi::types::AsyncItemHandle::from(handle);
        self.session_mut()
            .async_item_mut(handle.into())
            .unwrap()
            .await_ready()
            .now_or_never()
            .is_some()
    }

    fn drop(&mut self, handle: Resource<async_io::Pollable>) -> wasmtime::Result<()> {
        let handle = wiggle_abi::types::AsyncItemHandle::from(handle).into();

        // Use `.take_async_item` instead of manipulating
        // `self.session_mut().async_items` directly, so that any extra state
        // associated with the item is also cleared.
        let _ = self.session_mut().take_async_item(handle).unwrap();

        Ok(())
    }
}
