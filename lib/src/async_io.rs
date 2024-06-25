use {
    crate::{
        error::Error,
        session::Session,
        wiggle_abi::{fastly_async_io::FastlyAsyncIo, types::AsyncItemHandle},
    },
    futures::{FutureExt, TryFutureExt},
    std::time::Duration,
    tokio::time::timeout,
    wiggle::{GuestMemory, GuestPtr},
};

#[wiggle::async_trait]
impl FastlyAsyncIo for Session {
    async fn select(
        &mut self,
        memory: &mut GuestMemory<'_>,
        handles: GuestPtr<[AsyncItemHandle]>,
        timeout_ms: u32,
    ) -> Result<u32, Error> {
        let handles = handles.cast::<[u32]>();
        if handles.len() == 0 && timeout_ms == 0 {
            return Err(Error::InvalidArgument);
        }

        let select_fut = self
            .select_impl(
                memory
                    // TODO: `GuestMemory::as_slice` only supports guest pointers to u8 slices in
                    // wiggle 22.0.0, but `GuestMemory::to_vec` supports guest pointers to slices
                    // of arbitrary types. As `GuestMemory::to_vec` will copy the contents of the
                    // slice out of guest memory, we should switch this to `GuestMemory::as_slice`
                    // once it is polymorphic in the element type of the slice.
                    .to_vec(handles)?
                    .into_iter()
                    .map(|i| AsyncItemHandle::from(i).into()),
            )
            .map_ok(|done_idx| done_idx as u32);

        if timeout_ms == 0 {
            select_fut.await
        } else {
            timeout(Duration::from_millis(timeout_ms as u64), select_fut)
                .await
                .unwrap_or(Ok(u32::MAX))
        }
    }
    fn is_ready(
        &mut self,
        _memory: &mut GuestMemory<'_>,
        handle: AsyncItemHandle,
    ) -> Result<u32, Error> {
        if self
            .async_item_mut(handle.into())?
            .await_ready()
            .now_or_never()
            .is_some()
        {
            Ok(1)
        } else {
            Ok(0)
        }
    }
}
