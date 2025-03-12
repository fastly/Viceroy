//! Provides `CollectingBody`, a body that can be concurrently written-to (via a `StreamingBody`
//! handle) and read-from (via multiple `Body`) handles.

// TODO: cceckman-at-fastly: Temporary, I promise.
#![allow(unused)]

use bytes::Bytes;
use http::HeaderMap;
use http_body::Body as HttpBody;
use tokio::sync::watch;

use crate::{
    body::{Body, Chunk},
    error,
    streaming_body::StreamingBody,
    Error,
};

/// CollectingBody is a body for caching and request collapsing.
/// It allows writing a body while concurrently\* reading it, from multiple readers.
///
/// CollectingBody primarily exists to implement the cache APIs. Cache APIs allow three things to
/// happen concurrently:
/// - Streaming in a body, from an `insert`/`replace`-style request, implemented via StreamingBody
/// - Storage of that body in the cache
/// - Streaming out of the body, from a `lookup`/`TransactionInsertBuilder:execute_and_stream_back`
///   request, from the same or a different session
///
/// CollectingBody provides a place for this to happen. It accepts a `Body` as a source of data,
/// e.g. one from a `StreamingBody` or an origin response; stores the data for future retrieval;
/// and can return new `Body`s from `::read` that produce the full content.
#[derive(Debug)]
pub struct CollectingBody {
    inner: watch::Receiver<CollectingBodyInner>,
}

impl Default for CollectingBodyInner {
    fn default() -> Self {
        CollectingBodyInner::Streaming(Vec::default())
    }
}

impl CollectingBody {
    /// Create a new CollectingBody that stores & streams from the provided Body.
    ///
    /// Writes to the StreamingBody are collected, and propagated to all readers of this
    /// CollectingBody.
    // TODO: Expected length?
    pub fn new(from: Body) -> CollectingBody {
        let (tx, rx) = watch::channel(CollectingBodyInner::default());
        let body = CollectingBody { inner: rx };
        tokio::task::spawn(Self::tee(from, tx));
        body
    }

    /// "tee" a single Body to the watch channel.
    ///
    /// This is the worker thread behind a CollectingBody. It reads the data from the provided body
    /// into a `tokio::sync::watch` channel, which (a) accumulates the body + trailers and (b)
    /// notifies any subscribed readers of the updates. The readers can safely miss updates or
    /// start late, as they always can eventually read the state.
    async fn tee(mut rx: Body, tx: watch::Sender<CollectingBodyInner>) {
        // IMPORTANT IMPLEMENTATION NOTE:
        //
        // Make sure every path out of this function results in either state.errors.is_some() or
        // state.trailers.is_some().

        // Read data first:
        while let Some(chunk) = rx.data().await {
            match chunk {
                Ok(data) => {
                    tx.send_modify(move |state| {
                        if let CollectingBodyInner::Streaming(ref mut chunks) = state {
                            chunks.push(data);
                        } else {
                            panic!("received data after CollectingBody is complete");
                        }
                    });
                }
                Err(Error::Again) => continue,
                Err(e) => {
                    tx.send_modify(move |state| {
                        *state = CollectingBodyInner::Error(e);
                    });
                    return;
                }
            }
        }

        // Then wait for trailers (if any) to be present:
        let trailers = rx.trailers().await;
        tx.send_modify(move |state| match trailers {
            Ok(trailers) => {
                let CollectingBodyInner::Streaming(chunks) = state else {
                    panic!("received trailers after CollectingBody is complete")
                };
                let mut body = Vec::new();
                std::mem::swap(&mut body, chunks);
                *state = CollectingBodyInner::Complete {
                    body,
                    trailers: trailers.unwrap_or_default(),
                }
            }
            Err(e) => *state = CollectingBodyInner::Error(e),
        });
    }

    /// Get a new read handle to this body.
    pub fn read(&self) -> Result<Body, error::Error> {
        let mut upstream = self.inner.clone();
        let (mut tx, rx) = StreamingBody::new();
        tokio::task::spawn(async move {
            let mut next_chunk = 0;

            while upstream.changed().await.is_ok() {
                // If there's an error, the Channel is closed.
                //
                // This should only happen if the sender has hung up, i.e. if the object has
                // been evicted from the cache *and* the writer is done. In which case:
                // - If the writer shut down cleanly, great, we've already shut down cleanly
                //      too.
                // - If the writer didn't, we don't either.

                // We'll need to .await to send chunks, but we can't do that while holding a read
                // lock on the watch channel.
                // Open a new scope for the lock, copy out the work we need to do, then release the
                // lock at the end of the scope.
                let (send_chunks, trailers) = {
                    // Acquire the read lock:
                    let current_value = upstream.borrow_and_update();
                    let send_chunks: Vec<Bytes> = current_value
                        .chunks()
                        .map(|v| v.iter().cloned().collect())
                        .unwrap_or_default();
                    let trailers = current_value.trailers().cloned();
                    if current_value.is_error() {
                        // To trigger a guest error, it is sufficient to
                        // TODO: cceckman-at-fastly: Do we need to do something with the error message?
                        // To trigger a guest error, it appears sufficient to not .finish() the StreamingBody.
                        return;
                    }
                    (send_chunks, trailers)
                };

                // Good data:
                for chunk in send_chunks {
                    if tx.send_chunk(chunk).await.is_err() {
                        // Reader hung up; we don't care any more.
                        return;
                    }
                    next_chunk += 1;
                }
                // Finished data:
                if let Some(trailers) = trailers {
                    for (k, v) in trailers.iter() {
                        tx.append_trailer(k.clone(), v.clone());
                    }
                    // We don't wait for the channel to be closed;
                    // if the object stays in the cache, the object will be around ~forever.
                    // Trailers sent -> we're done.
                    let _ = tx.finish();
                    return;
                }
            }
        });
        let c: Chunk = rx.into();
        let b: Body = c.into();
        Ok(b)
    }
}

/// The state of a CollectingBody, within the pubsub (watch) channel.
#[derive(Debug)]
enum CollectingBodyInner {
    // TODO: cceckman-at-fastly: consider SmallVec, optimizing for the "there is a single chunk"
    // case
    Streaming(Vec<Bytes>),
    Complete {
        body: Vec<Bytes>,
        trailers: HeaderMap,
    },
    Error(Error),
}

impl CollectingBodyInner {
    fn chunks(&self) -> Option<&Vec<Bytes>> {
        match self {
            CollectingBodyInner::Streaming(body) | CollectingBodyInner::Complete { body, .. } => {
                Some(body)
            }
            _ => None,
        }
    }
    fn trailers(&self) -> Option<&HeaderMap> {
        match self {
            CollectingBodyInner::Complete { trailers, .. } => Some(trailers),
            _ => None,
        }
    }
    fn is_error(&self) -> bool {
        matches!(self, CollectingBodyInner::Error(_))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use http::{HeaderName, HeaderValue};
    use tokio::task::JoinSet;

    use crate::{
        body::{Body, Chunk},
        collecting_body::CollectingBody,
        streaming_body::StreamingBody,
        Error,
    };

    #[tokio::test]
    async fn stream_and_collect() {
        let (mut tx, rx) = StreamingBody::new();
        let chunk: Chunk = rx.into();
        let body: Body = chunk.into();
        let collect = CollectingBody::new(body);

        let data: Vec<u8> = (0..10).collect();

        // Single-byte chunks:
        for i in 0..data.len() {
            tx.send_chunk(&data[i..i + 1]).await.unwrap();
        }
        tx.finish().unwrap();
        let read = collect.read().unwrap();
        let bytes = read.read_into_vec().await.unwrap();
        assert_eq!(&bytes, &data);
    }

    #[tokio::test]
    async fn stream_and_receive() {
        let (mut tx, rx) = StreamingBody::new();
        let chunk: Chunk = rx.into();
        let body: Body = chunk.into();
        let collect = CollectingBody::new(body);

        let data: Arc<Vec<u8>> = Arc::new((0..10).collect());

        let mut set = JoinSet::new();
        // Readers:
        set.spawn({
            let data = Arc::clone(&data);
            let read = collect.read().unwrap();

            async move {
                let bytes = read.read_into_vec().await.unwrap();
                assert_eq!(&bytes, &*data);
            }
        });
        set.spawn({
            let data = Arc::clone(&data);
            let read = collect.read().unwrap();

            async move {
                let bytes = read.read_into_vec().await.unwrap();
                assert_eq!(&bytes, &*data);
            }
        });
        // Writer:
        set.spawn(async move {
            // Single-byte chunks:
            for i in 0..data.len() {
                // Intentionally yield to interleave tasks.
                tokio::task::yield_now().await;
                tx.send_chunk(&data[i..i + 1]).await.unwrap();
            }
            tx.finish().unwrap();
        });

        set.join_all().await;
    }

    #[tokio::test]
    async fn partial_read_partial_stream() {
        let (mut tx, rx) = StreamingBody::new();
        let chunk: Chunk = rx.into();
        let body: Body = chunk.into();
        let collect = CollectingBody::new(body);

        let data: Arc<Vec<u8>> = Arc::new((0..10).collect());
        tx.send_chunk(&data[0..2]).await.unwrap();
        tx.send_chunk(&data[2..5]).await.unwrap();

        // Now start the concurrent read + write:
        let reader = {
            let data = Arc::clone(&data);
            tokio::task::spawn(async move {
                let read = collect.read().unwrap();
                let bytes = read.read_into_vec().await.unwrap();
                assert_eq!(&bytes, &*data);
            })
        };
        // Try to catch the reader up:
        tokio::task::yield_now().await;

        // Finish the write:
        tx.send_chunk(&data[5..7]).await.unwrap();
        tx.send_chunk(&data[7..]).await.unwrap();
        tx.finish().unwrap();

        reader.await.unwrap();
    }

    #[tokio::test]
    async fn unfinished_stream() {
        let (mut tx, rx) = StreamingBody::new();
        let chunk: Chunk = rx.into();
        let body: Body = chunk.into();
        let collect = CollectingBody::new(body);

        let data: Arc<Vec<u8>> = Arc::new((0..10).collect());
        tx.send_chunk(&data[0..2]).await.unwrap();
        tx.send_chunk(&data[2..5]).await.unwrap();

        // Start a concurrent read, read some of it:
        let reader = {
            tokio::task::spawn(async move {
                let read = collect.read().unwrap();
                let err = read.read_into_vec().await.unwrap_err();
                let Error::UnfinishedStreamingBody = err else {
                    panic!("incorrect error type for streaming error")
                };
            })
        };
        // Try to catch the reader up:
        tokio::task::yield_now().await;

        // Write more, but drop without .finish()ing.
        tx.send_chunk(&data[5..7]).await.unwrap();
        std::mem::drop(tx);

        reader.await.unwrap();
    }

    #[tokio::test]
    async fn reads_trailers() {
        let (mut tx, rx) = StreamingBody::new();
        let chunk: Chunk = rx.into();
        let body: Body = chunk.into();
        let collect = CollectingBody::new(body);
        // Start a concurrent read, read some of it:
        let reader = {
            tokio::task::spawn(async move {
                let mut body = collect.read().unwrap();
                body.await_ready().await;
                let v = body.trailers.get("~^.^~").unwrap();
                assert_eq!(v, r#""is a cat *and* a valid header name""#);

                let data = body.read_into_vec().await.unwrap();
                assert!(data.is_empty());
            })
        };
        tokio::task::yield_now();

        tx.append_trailer(
            HeaderName::from_static("~^.^~"),
            HeaderValue::from_static(r#""is a cat *and* a valid header name""#),
        );
        tx.finish();

        reader.await.unwrap();
    }
}
