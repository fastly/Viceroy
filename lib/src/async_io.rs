use {
    crate::{
        error::Error,
        session::Session,
        wiggle_abi::{fastly_async_io::FastlyAsyncIo, types::AsyncItemHandle},
    },
    futures::{FutureExt, TryFutureExt},
    std::time::Duration,
    tokio::time::timeout,
    wiggle::GuestPtr,
};

#[wiggle::async_trait]
impl FastlyAsyncIo for Session {
    async fn select<'a>(
        &mut self,
        handles: &GuestPtr<'a, [AsyncItemHandle]>,
        timeout_ms: u32,
    ) -> Result<u32, Error> {
        let handles = GuestPtr::<'a, [u32]>::new(handles.mem(), handles.offset())
            .as_slice()?
            .ok_or(Error::SharedMemory)?;
        if handles.len() == 0 && timeout_ms == 0 {
            return Err(Error::InvalidArgument);
        }

        let select_fut = self
            .select_impl(
                handles
                    .iter()
                    .copied()
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
    fn is_ready(&mut self, handle: AsyncItemHandle) -> Result<u32, Error> {
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
