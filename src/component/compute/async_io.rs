use {
    crate::{
        component::bindings::fastly::compute::async_io,
        linking::{ComponentCtx, SessionView},
        session::AsyncItem,
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

    fn drop(&mut self, h: Resource<async_io::Pollable>) -> wasmtime::Result<()> {
        let handle: wiggle_abi::types::AsyncItemHandle = h.into();

        {
            let it = self.session_mut().async_item_mut(handle.into())?;

            // In the WIT ABI, CacheEntry, CacheReplace, and HttpCacheEntry AsyncItems are not
            // async_io::Pollables. Insteady, their primary handles "own" the AsyncItem,
            // and the Pollable "borrows" from it.
            //
            // But! Those handles have the same ID when presented to the host.
            // So if we encounter a Pollable to one of those types here, we need to keep
            // the AsyncItem in the table, and just let drop() clean up the Resource.
            //
            // Note that we don't cover HTTP cache items here; we don't support the HTTP caching
            // API, so the guest won't have a valid handle to an HTTP cache item.
            if matches!(*it, AsyncItem::PendingCache(_)) {
                // Don't remove from the session.async_items set; this is "just" the Pollable for the
                // item, not the real thing.
                return Ok(());
            };
        }

        // Use `.take_async_item` instead of manipulating
        // `self.session_mut().async_items` directly, so that any extra state
        // associated with the item is also cleared.
        let _ = self.session_mut().take_async_item(handle.into())?;

        Ok(())
    }
}
