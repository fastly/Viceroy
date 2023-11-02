use crate::object_store::ObjectStoreError;
use crate::{body::Body, error::Error, streaming_body::StreamingBody};
use anyhow::anyhow;
use futures::Future;
use futures::FutureExt;
use http::Response;
use tokio::sync::oneshot;

pub type PendingKvLookupTask = PeekableTask<Result<Vec<u8>, ObjectStoreError>>;
pub type PendingKvInsertTask = PeekableTask<Result<(), ObjectStoreError>>;

/// Represents either a full body, or the write end of a streaming body.
///
/// This enum is needed because we reuse the handle for a body when it is transformed into a streaming
/// body (writeable only). It is used within the body handle map in `Session`.
#[derive(Debug)]
pub enum AsyncItem {
    Body(Body),
    StreamingBody(StreamingBody),
    PendingReq(PeekableTask<Response<Body>>),
    PendingKvLookup(PendingKvLookupTask),
    PendingKvInsert(PendingKvInsertTask),
}

impl AsyncItem {
    pub fn is_streaming(&self) -> bool {
        matches!(self, Self::StreamingBody(_))
    }

    pub fn as_body(&self) -> Option<&Body> {
        match self {
            Self::Body(body) => Some(body),
            _ => None,
        }
    }

    pub fn as_body_mut(&mut self) -> Option<&mut Body> {
        match self {
            Self::Body(body) => Some(body),
            _ => None,
        }
    }

    pub fn into_body(self) -> Option<Body> {
        match self {
            Self::Body(body) => Some(body),
            _ => None,
        }
    }

    pub fn as_streaming_mut(&mut self) -> Option<&mut StreamingBody> {
        match self {
            Self::StreamingBody(sender) => Some(sender),
            _ => None,
        }
    }

    pub fn into_streaming(self) -> Option<StreamingBody> {
        match self {
            Self::StreamingBody(streaming) => Some(streaming),
            _ => None,
        }
    }

    pub fn begin_streaming(&mut self) -> Option<Body> {
        if self.is_streaming() {
            return None;
        }

        let (streaming, receiver) = StreamingBody::new();
        if let Self::Body(mut body) = std::mem::replace(self, Self::StreamingBody(streaming)) {
            body.push_back(receiver);
            Some(body)
        } else {
            unreachable!("!self.is_streaming, but was actually streaming");
        }
    }

    pub fn as_pending_kv_lookup(&self) -> Option<&PendingKvLookupTask> {
        match self {
            Self::PendingKvLookup(req) => Some(req),
            _ => None,
        }
    }

    pub fn into_pending_kv_lookup(self) -> Option<PendingKvLookupTask> {
        match self {
            Self::PendingKvLookup(req) => Some(req),
            _ => None,
        }
    }

    pub fn as_pending_kv_insert(&self) -> Option<&PendingKvInsertTask> {
        match self {
            Self::PendingKvInsert(req) => Some(req),
            _ => None,
        }
    }

    pub fn into_pending_kv_insert(self) -> Option<PendingKvInsertTask> {
        match self {
            Self::PendingKvInsert(req) => Some(req),
            _ => None,
        }
    }

    pub fn as_pending_req(&self) -> Option<&PeekableTask<Response<Body>>> {
        match self {
            Self::PendingReq(req) => Some(req),
            _ => None,
        }
    }

    pub fn as_pending_req_mut(&mut self) -> Option<&mut PeekableTask<Response<Body>>> {
        match self {
            Self::PendingReq(req) => Some(req),
            _ => None,
        }
    }

    pub fn into_pending_req(self) -> Option<PeekableTask<Response<Body>>> {
        match self {
            Self::PendingReq(req) => Some(req),
            _ => None,
        }
    }

    pub async fn await_ready(&mut self) {
        match self {
            Self::StreamingBody(body) => body.await_ready().await,
            Self::Body(body) => body.await_ready().await,
            Self::PendingReq(req) => req.await_ready().await,
            Self::PendingKvLookup(obj) => obj.await_ready().await,
            Self::PendingKvInsert(obj) => obj.await_ready().await,
        }
    }

    pub fn is_ready(&mut self) -> bool {
        self.await_ready().now_or_never().is_some()
    }
}

impl From<PeekableTask<Response<Body>>> for AsyncItem {
    fn from(req: PeekableTask<Response<Body>>) -> Self {
        Self::PendingReq(req)
    }
}

impl From<PendingKvLookupTask> for AsyncItem {
    fn from(task: PendingKvLookupTask) -> Self {
        Self::PendingKvLookup(task)
    }
}

impl From<PendingKvInsertTask> for AsyncItem {
    fn from(task: PendingKvInsertTask) -> Self {
        Self::PendingKvInsert(task)
    }
}

#[derive(Debug)]
pub enum PeekableTask<T> {
    Waiting(oneshot::Receiver<Result<T, Error>>),
    Complete(Result<T, Error>),
}

impl<T: Send + 'static> PeekableTask<T> {
    pub async fn spawn(fut: impl Future<Output = Result<T, Error>> + 'static + Send) -> Self {
        let (sender, receiver) = oneshot::channel();
        tokio::task::spawn(async move { sender.send(fut.await) });
        Self::Waiting(receiver)
    }

    pub fn complete(t: T) -> Self {
        PeekableTask::Complete(Ok(t))
    }

    /// Block until a response is ready.
    pub async fn await_ready(&mut self) {
        if let PeekableTask::Waiting(rx) = self {
            if let Ok(v) = rx.await {
                *self = PeekableTask::Complete(v)
            } else {
                // todo, not the correct error type
                *self = PeekableTask::Complete(Err(anyhow!(
                    "peekable task sender unexpectedly dropped"
                )
                .into()));
            }
        }
    }

    pub async fn recv(self) -> Result<T, Error> {
        match self {
            PeekableTask::Waiting(rx) => rx
                .await
                .map_err(|_| anyhow!("peekable task sender unexpectedly dropped"))?,
            PeekableTask::Complete(res) => res,
        }
    }

    pub fn get_mut(&mut self) -> Option<&mut Result<T, Error>> {
        if let PeekableTask::Complete(res) = self {
            Some(res)
        } else {
            None
        }
    }
}
