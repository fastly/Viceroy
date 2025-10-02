use std::time::{Duration, Instant};

use crate::cache::CacheEntry;
use crate::downstream::DownstreamRequest;
use crate::execute::NextRequest;
use crate::object_store::{KvStoreError, ObjectValue};
use crate::{body::Body, error::Error, streaming_body::StreamingBody};
use anyhow::anyhow;
use futures::Future;
use futures::FutureExt;
use http::Response;
use tokio::sync::oneshot;

#[derive(Debug)]
pub struct PendingKvLookupTask(PeekableTask<Result<Option<ObjectValue>, KvStoreError>>);
impl PendingKvLookupTask {
    pub fn new(t: PeekableTask<Result<Option<ObjectValue>, KvStoreError>>) -> PendingKvLookupTask {
        PendingKvLookupTask(t)
    }
    pub fn task(self) -> PeekableTask<Result<Option<ObjectValue>, KvStoreError>> {
        self.0
    }
}

#[derive(Debug)]
pub struct PendingKvInsertTask(PeekableTask<Result<(), KvStoreError>>);
impl PendingKvInsertTask {
    pub fn new(t: PeekableTask<Result<(), KvStoreError>>) -> PendingKvInsertTask {
        PendingKvInsertTask(t)
    }
    pub fn task(self) -> PeekableTask<Result<(), KvStoreError>> {
        self.0
    }
}

#[derive(Debug)]
pub struct PendingKvDeleteTask(PeekableTask<Result<bool, KvStoreError>>);
impl PendingKvDeleteTask {
    pub fn new(t: PeekableTask<Result<bool, KvStoreError>>) -> PendingKvDeleteTask {
        PendingKvDeleteTask(t)
    }
    pub fn task(self) -> PeekableTask<Result<bool, KvStoreError>> {
        self.0
    }
}

#[derive(Debug)]
pub struct PendingKvListTask(PeekableTask<Result<Vec<u8>, KvStoreError>>);
impl PendingKvListTask {
    pub fn new(t: PeekableTask<Result<Vec<u8>, KvStoreError>>) -> PendingKvListTask {
        PendingKvListTask(t)
    }
    pub fn task(self) -> PeekableTask<Result<Vec<u8>, KvStoreError>> {
        self.0
    }
}

/// This is very similar to a [PeekableTask] task, but is intentionally
/// set up so that it has no spawned tokio tasks separating us from the
/// [oneshot::Sender] and detecting when it's dropped.
///
/// The `try_recv()` method can be used to make sure that we safely recover
/// any pending requests that are sent to us without dropping them.
#[derive(Debug)]
pub enum PendingDownstreamReqTask {
    Complete(Result<NextRequest, Error>),
    Waiting(oneshot::Receiver<NextRequest>, Instant),
}

impl PendingDownstreamReqTask {
    pub fn new(
        rx: Option<oneshot::Receiver<NextRequest>>,
        timeout: Duration,
    ) -> PendingDownstreamReqTask {
        if let Some(rx) = rx {
            PendingDownstreamReqTask::Waiting(rx, Instant::now() + timeout)
        } else {
            PendingDownstreamReqTask::Complete(Err(Error::NoDownstreamReqsAvailable))
        }
    }

    /// Receive a downstream request.
    ///
    /// This will block until the sender side of the channel is either dropped
    /// or sends us a value.
    pub async fn recv(mut self) -> Result<DownstreamRequest, Error> {
        self.await_ready().await;

        let Self::Complete(res) = self else {
            return Err(Error::NoDownstreamReqsAvailable);
        };

        res?.into_request().ok_or(Error::NoDownstreamReqsAvailable)
    }

    /// Drive this task to completion.
    ///
    /// If we have passed the deadline for the task, we try to recover any request
    /// in the channel. If there is none, then the timed out task will resolve to
    /// [Error::NoDownstreamReqsAvailable].
    ///
    /// ## Cancel Safety
    ///
    /// Note that this method is used with [FutureExt::now_or_never] in [AsyncItem::is_ready], and
    /// should therefore be kept cancel safe.
    pub async fn await_ready(&mut self) {
        if let Self::Waiting(rx, deadline) = self {
            let v = if Instant::now() > *deadline {
                rx.close();
                rx.try_recv().ok()
            } else {
                tokio::time::timeout_at((*deadline).into(), rx)
                    .await
                    .ok()
                    .and_then(|r| r.ok())
            };

            let res = v.ok_or(Error::NoDownstreamReqsAvailable);
            *self = Self::Complete(res);
        }
    }
}

/// An async item, waiting for a cache lookup to complete.
#[derive(Debug)]
pub struct PendingCacheTask(PeekableTask<CacheEntry>);
impl PendingCacheTask {
    pub fn new(t: PeekableTask<CacheEntry>) -> PendingCacheTask {
        PendingCacheTask(t)
    }
    pub fn task(self) -> PeekableTask<CacheEntry> {
        self.0
    }

    /// Get a mutable reference to the CacheEntry, possibly blocking until it becomes available.
    pub async fn as_mut(&mut self) -> &mut Result<CacheEntry, Error> {
        self.0.await_ready().await;
        self.0
            .get_mut()
            .expect("internal error: PeekableTask was not ready after AwaitReady")
    }
}

/// Represents either a full body, or the write end of a streaming body.
///
/// This enum is needed because we reuse the handle for a body when it is transformed into a streaming
/// body (writeable only). It is used within the body handle map in `Session`.
#[derive(Debug)]
pub enum AsyncItem {
    Body(Body),
    StreamingBody(StreamingBody),
    PendingReq(PeekableTask<Response<Body>>),
    PendingDownstream(PendingDownstreamReqTask),
    PendingKvLookup(PendingKvLookupTask),
    PendingKvInsert(PendingKvInsertTask),
    PendingKvDelete(PendingKvDeleteTask),
    PendingKvList(PendingKvListTask),
    PendingCache(PendingCacheTask),
    Ready,
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

    pub fn as_pending_kv_delete(&self) -> Option<&PendingKvDeleteTask> {
        match self {
            Self::PendingKvDelete(req) => Some(req),
            _ => None,
        }
    }

    pub fn into_pending_kv_delete(self) -> Option<PendingKvDeleteTask> {
        match self {
            Self::PendingKvDelete(req) => Some(req),
            _ => None,
        }
    }

    pub fn as_pending_kv_list(&self) -> Option<&PendingKvListTask> {
        match self {
            Self::PendingKvList(req) => Some(req),
            _ => None,
        }
    }

    pub fn into_pending_kv_list(self) -> Option<PendingKvListTask> {
        match self {
            Self::PendingKvList(req) => Some(req),
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

    pub fn as_pending_cache(&self) -> Option<&PendingCacheTask> {
        match self {
            Self::PendingCache(op) => Some(op),
            _ => None,
        }
    }

    pub fn as_pending_cache_mut(&mut self) -> Option<&mut PendingCacheTask> {
        match self {
            Self::PendingCache(op) => Some(op),
            _ => None,
        }
    }

    pub fn into_pending_cache(self) -> Option<PendingCacheTask> {
        match self {
            Self::PendingCache(op) => Some(op),
            _ => None,
        }
    }

    pub fn into_pending_req(self) -> Option<PeekableTask<Response<Body>>> {
        match self {
            Self::PendingReq(req) => Some(req),
            _ => None,
        }
    }

    pub fn as_pending_downstream_req_mut(&mut self) -> Option<&mut PendingDownstreamReqTask> {
        match self {
            Self::PendingDownstream(req) => Some(req),
            _ => None,
        }
    }

    pub fn into_pending_downstream_req(self) -> Option<PendingDownstreamReqTask> {
        match self {
            Self::PendingDownstream(req) => Some(req),
            _ => None,
        }
    }

    pub async fn await_ready(&mut self) {
        match self {
            Self::StreamingBody(body) => body.await_ready().await,
            Self::Body(body) => body.await_ready().await,
            Self::PendingReq(req) => req.await_ready().await,
            Self::PendingDownstream(req) => req.await_ready().await,
            Self::PendingKvLookup(req) => req.0.await_ready().await,
            Self::PendingKvInsert(req) => req.0.await_ready().await,
            Self::PendingKvDelete(req) => req.0.await_ready().await,
            Self::PendingKvList(req) => req.0.await_ready().await,
            Self::PendingCache(req) => req.0.await_ready().await,
            Self::Ready => (),
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

impl From<PendingKvDeleteTask> for AsyncItem {
    fn from(task: PendingKvDeleteTask) -> Self {
        Self::PendingKvDelete(task)
    }
}

impl From<PendingKvListTask> for AsyncItem {
    fn from(task: PendingKvListTask) -> Self {
        Self::PendingKvList(task)
    }
}

impl From<PendingCacheTask> for AsyncItem {
    fn from(task: PendingCacheTask) -> Self {
        Self::PendingCache(task)
    }
}

impl From<PendingDownstreamReqTask> for AsyncItem {
    fn from(task: PendingDownstreamReqTask) -> Self {
        Self::PendingDownstream(task)
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
