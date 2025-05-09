//! Provides `CollectingBody`, a body that can be concurrently written-to (via a `StreamingBody`
//! handle) and read-from (via multiple `Body`) handles.

use std::ops::RangeInclusive;

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
/// It allows writing a body while concurrently reading it, from multiple readers.
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

/// The range requested from the cache item.
#[derive(Debug, Default)]
pub enum RequestedRange {
    #[default]
    Entire,
    StartingFrom(u64),
    Bounded(RangeInclusive<u64>),
}

impl CollectingBody {
    /// Returns the length of the body, if it is complete.
    pub fn length(&self) -> Option<u64> {
        let state = self.inner.borrow();
        match *state {
            CollectingBodyInner::Streaming(_) => None,
            CollectingBodyInner::Complete { ref body, .. } => {
                Some(body.iter().map(|chunk| chunk.len()).sum::<usize>() as u64)
            }
            CollectingBodyInner::Error(_) => None,
        }
    }

    /// Create a new CollectingBody that stores & streams from the provided Body.
    ///
    /// Writes to the StreamingBody are collected, and propagated to all readers of this
    /// CollectingBody.
    // TODO: Expected length?
    pub fn new(from: Body, length: Option<u64>) -> CollectingBody {
        let (tx, rx) = watch::channel(CollectingBodyInner::default());
        let body = CollectingBody { inner: rx };
        tokio::task::spawn(Self::tee(from, tx, length));
        body
    }

    /// "tee" a single Body to the watch channel.
    ///
    /// This is the worker thread behind a CollectingBody. It reads the data from the provided body
    /// into a `tokio::sync::watch` channel, which (a) accumulates the body + trailers and (b)
    /// notifies any subscribed readers of the updates. The readers can safely miss updates or
    /// start late, as they always can eventually read the state.
    async fn tee(
        mut rx: Body,
        tx: watch::Sender<CollectingBodyInner>,
        expected_length: Option<u64>,
    ) {
        // IMPORTANT IMPLEMENTATION NOTE:
        // This should always exit with the watched state as Error or Complete.

        // Read data first:
        let mut length = 0;
        while let Some(chunk) = rx.data().await {
            match chunk {
                Ok(data) => {
                    tx.send_modify(|state| {
                        if let CollectingBodyInner::Streaming(ref mut chunks) = state {
                            length += data.len();
                            chunks.push(data);
                        } else {
                            panic!("received data after CollectingBody is complete");
                        }

                        // Generate length-exceeded error before exiting send_modify.
                        match expected_length {
                            Some(expected_length) if (length as u64) > expected_length => {
                                *state = CollectingBodyInner::Error(Error::UnfinishedStreamingBody);
                            }
                            _ => (),
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

        // We're done with all the data.
        // Check that we didn't underfill.
        match expected_length {
            Some(expected_length) if (length as u64) != expected_length => {
                tx.send_modify(move |state| {
                    *state = CollectingBodyInner::Error(Error::UnfinishedStreamingBody);
                });
                return;
            }
            _ => (),
        }

        // Then wait for trailers (if any) to be present, which is the "finish" signal.
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
    ///
    /// `from` and `to` indicate the range to read; (0, None) indicates "read the whole object".
    /// Both bounds are inclusive (unlike the range operator).
    pub fn read(&self, range: RequestedRange) -> Result<Body, error::Error> {
        let mut upstream = self.inner.clone();
        let (mut tx, rx) = StreamingBody::new();
        tokio::task::spawn(async move {
            let mut next_chunk = 0;
            let mut cursor: u64 = 0;

            let range = match range {
                RequestedRange::Entire => 0..=u64::MAX,
                RequestedRange::Bounded(v) => v,
                RequestedRange::StartingFrom(start) => start..=u64::MAX,
            };

            // The receiver tracks the "current" value, and assumes that the value at the receiver
            // is "seen" to begin with.
            // So we have a do-while loop, with the "changed" condition at the bottom.
            loop {
                // We'll need to .await to send chunks, but we can't do that while holding a read
                // lock on the watch channel.
                // Open a new scope for the lock, copy out the work we need to do, then release the
                // lock at the end of the scope.
                let (send_chunks, trailers) = {
                    // Acquire the read lock:
                    let current_value = upstream.borrow_and_update();
                    let send_chunks: Vec<Bytes> = current_value.chunks()[next_chunk..].to_owned();
                    let trailers = current_value.trailers().cloned();
                    if let CollectingBodyInner::Error(ref e) = *current_value {
                        // To trigger a guest error, it is sufficient to not .finish() the
                        // StreamingBody (so, early return).
                        // As of 2025-03-21, though, this code is new, so we don't want to
                        // completely swallow errors!
                        tracing::warn!("error in reading from CollectingBody: {e}");
                        return;
                    }
                    (send_chunks, trailers)
                };

                // If send_chunks is nonempty, it contains data for us to forward.
                // Commit to processing all these chunks:
                next_chunk += send_chunks.len();
                for chunk in send_chunks {
                    let chunk_bounds = cursor..=(cursor + chunk.len() as u64 - 1);
                    cursor += chunk.len() as u64;

                    // What might we send from this chunk; inclusive start and end.
                    let absolute_start = std::cmp::max(*range.start(), *chunk_bounds.start());
                    let absolute_end = std::cmp::min(*range.end(), *chunk_bounds.end());

                    // Fast path, "send the whole chunk":
                    let to_send = if range.contains(&chunk_bounds.start())
                        && range.contains(chunk_bounds.end())
                    {
                        Some(chunk)
                    } else if absolute_end >= absolute_start {
                        // Some overlap. Create a subslice.
                        let r = ((absolute_start - chunk_bounds.start()) as usize)
                            ..=((absolute_end - chunk_bounds.start()) as usize);
                        Some(Bytes::copy_from_slice(&chunk[r]))
                    } else {
                        // No overlap.
                        None
                    };

                    let Some(to_send) = to_send else { continue };
                    if tx.send_chunk(to_send).await.is_err() {
                        // Reader hung up; we don't care any more.
                        return;
                    }
                }
                // And we may have gotten the trailers, which are the "body is done" signal:
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

                // Now that we've processed the current state, wait for a change.
                //

                if upstream.changed().await.is_err() {
                    return;
                    // If there's an error, the Channel is closed.
                    //
                    // This should only happen if the sender has hung up, i.e. if the object has
                    // been evicted from the cache *and* the writer is done. In which case:
                    // - If the writer shut down cleanly, great, we've already shut down cleanly
                    //      too.
                    // - If the writer didn't, we don't either.
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
    /// The chunks currently available.
    fn chunks(&self) -> &[Bytes] {
        match self {
            CollectingBodyInner::Streaming(body) | CollectingBodyInner::Complete { body, .. } => {
                body
            }
            _ => &[],
        }
    }

    /// The trailers provided.
    ///
    /// Trailers are only present (Some()) if streaming is complete;
    /// None indicates streaming is still in progress.
    fn trailers(&self) -> Option<&HeaderMap> {
        match self {
            CollectingBodyInner::Complete { trailers, .. } => Some(trailers),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use std::sync::Arc;

    use http::{HeaderName, HeaderValue};
    use tokio::{sync::oneshot, task::JoinSet};

    use crate::{
        body::{Body, Chunk},
        collecting_body::{CollectingBody, RequestedRange::*},
        streaming_body::StreamingBody,
        Error,
    };

    #[tokio::test]
    async fn stream_and_collect() {
        let (mut tx, rx) = StreamingBody::new();
        let chunk: Chunk = rx.into();
        let body: Body = chunk.into();
        let collect = CollectingBody::new(body, None);

        let data: Vec<u8> = (0..10).collect();

        // Single-byte chunks:
        for i in 0..data.len() {
            tx.send_chunk(&data[i..i + 1]).await.unwrap();
        }
        tx.finish().unwrap();
        let read = collect.read(Entire).unwrap();
        let bytes = read.read_into_vec().await.unwrap();
        assert_eq!(&bytes, &data);
    }

    #[tokio::test]
    async fn stream_and_receive() {
        let (mut tx, rx) = StreamingBody::new();
        let chunk: Chunk = rx.into();
        let body: Body = chunk.into();
        let collect = CollectingBody::new(body, None);

        let data: Arc<Vec<u8>> = Arc::new((0..10).collect());

        let mut set = JoinSet::new();
        // Readers:
        set.spawn({
            let data = Arc::clone(&data);
            let read = collect.read(Entire).unwrap();

            async move {
                let bytes = read.read_into_vec().await.unwrap();
                assert_eq!(&bytes, &*data);
            }
        });
        set.spawn({
            let data = Arc::clone(&data);
            let read = collect.read(Entire).unwrap();

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
        let collect = CollectingBody::new(body, None);

        let data: Arc<Vec<u8>> = Arc::new((0..10).collect());
        tx.send_chunk(&data[0..2]).await.unwrap();
        tx.send_chunk(&data[2..5]).await.unwrap();

        let (send, recv) = oneshot::channel();

        // Now start the concurrent read + write:
        let reader = {
            let data = Arc::clone(&data);
            tokio::task::spawn(async move {
                let mut read = collect.read(Entire).unwrap();

                // Wait for the body to have some data ready...
                read.await_ready().await;
                // Then signal the writer to write further
                send.send(()).unwrap();
                let bytes = read.read_into_vec().await.unwrap();
                assert_eq!(&bytes, &*data);
            })
        };
        // Wait until the reader is caught up with what is written so far:
        recv.await.unwrap();

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
        let collect = CollectingBody::new(body, None);

        let data: Arc<Vec<u8>> = Arc::new((0..10).collect());
        tx.send_chunk(&data[0..2]).await.unwrap();
        tx.send_chunk(&data[2..5]).await.unwrap();

        let (send, recv) = oneshot::channel();

        // Start a concurrent read, read some of it:
        let reader = {
            tokio::task::spawn(async move {
                let mut read = collect.read(Entire).unwrap();
                read.await_ready().await;
                send.send(()).unwrap();

                let err = read.read_into_vec().await.unwrap_err();
                let Error::UnfinishedStreamingBody = err else {
                    panic!("incorrect error type for streaming error")
                };
            })
        };
        // Try to catch the reader up:
        recv.await.unwrap();

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
        let collect = CollectingBody::new(body, None);
        // Start a concurrent read, read some of it:
        let reader = {
            tokio::task::spawn(async move {
                let mut body = collect.read(Entire).unwrap();

                while !body.trailers_ready {
                    body.await_ready().await
                }

                let v = body.trailers.get("~^.^~").unwrap();
                assert_eq!(v, r#""is a cat *and* a valid header name""#);

                let data = body.read_into_vec().await.unwrap();
                assert!(data.is_empty());
            })
        };

        tx.append_trailer(
            HeaderName::from_static("~^.^~"),
            HeaderValue::from_static(r#""is a cat *and* a valid header name""#),
        );
        tx.finish().unwrap();

        reader.await.unwrap();
    }

    #[tokio::test]
    async fn completed_stream() {
        let (mut tx, rx) = StreamingBody::new();
        // Write the full stream before reading:
        let chunk: Chunk = rx.into();
        let body: Body = chunk.into();
        tx.send_chunk(b"hello".as_slice()).await.unwrap();
        tx.finish().unwrap();

        let collect = CollectingBody::new(body, None);
        let data = collect.read(Entire).unwrap().read_into_vec().await.unwrap();
        assert_eq!(data, b"hello");
    }

    #[tokio::test]
    async fn precise_length() {
        let (mut tx, rx) = StreamingBody::new();
        // Write the full stream before reading:
        let chunk: Chunk = rx.into();
        let body: Body = chunk.into();
        const BODY: &[u8] = b"hello";
        tx.send_chunk(BODY).await.unwrap();
        tx.finish().unwrap();

        let collect = CollectingBody::new(body, Some(BODY.len() as u64));
        let data = collect.read(Entire).unwrap().read_into_vec().await.unwrap();
        assert_eq!(data, BODY);
    }

    #[tokio::test]
    async fn error_on_underfill() {
        let (mut tx, rx) = StreamingBody::new();

        let collect = CollectingBody::new(Body::from(Chunk::from(rx)), Some(10));

        tx.send_chunk(b"hello".as_slice()).await.unwrap();
        tx.finish().unwrap();

        let err = collect
            .read(Entire)
            .unwrap()
            .read_into_vec()
            .await
            .unwrap_err();
        assert!(matches!(err, Error::UnfinishedStreamingBody));
    }

    #[tokio::test]
    async fn error_on_overfill() {
        let (mut tx, rx) = StreamingBody::new();

        let collect = CollectingBody::new(Body::from(Chunk::from(rx)), Some(2));

        tx.send_chunk(b"hello".as_slice()).await.unwrap();
        tx.finish().unwrap();

        let err = collect
            .read(Entire)
            .unwrap()
            .read_into_vec()
            .await
            .unwrap_err();
        assert!(matches!(err, Error::UnfinishedStreamingBody));
    }
    /// Proptest strategy for a streaming body - a sequence of chunks.
    fn streaming_body() -> impl Strategy<Value = Vec<Vec<u8>>> {
        let chunk_strategy = proptest::collection::vec(any::<u8>(), 2..16);
        let body_strategy = proptest::collection::vec(chunk_strategy, 1..8);
        body_strategy
    }

    /// Proptest strategy for a streaming body, plus start and end bounds.
    fn body_and_doubly_bounded_range() -> impl Strategy<Value = (Vec<Vec<u8>>, usize, usize)> {
        streaming_body()
            .prop_flat_map(|body| {
                let total_len = body.iter().map(|v| v.len()).sum::<usize>();
                assert!(total_len >= 2);
                (Just(body), Just(total_len))
            })
            .prop_flat_map(|(body, total_len)| (Just(body), Just(total_len), 0..(total_len - 1)))
            .prop_flat_map(|(body, total_len, start)| (Just(body), Just(start), start..total_len))
    }

    async fn test_both_bounded_range(
        yield_points: Vec<bool>,
        body: Vec<Vec<u8>>,
        start: usize,
        end: usize,
    ) -> Result<(), TestCaseError> {
        let flat_body: Vec<u8> = body.iter().flatten().map(|&b| b).collect();

        let (mut tx, rx) = StreamingBody::new();
        let collect = CollectingBody::new(Body::from(Chunk::from(rx)), None);
        let mut js = tokio::task::JoinSet::new();
        js.spawn(async move {
            // Sender task.
            for (i, chunk) in body.into_iter().enumerate() {
                tx.send_chunk(chunk).await.unwrap();
                // Fuzz the scheduling:
                if yield_points[i % yield_points.len()] {
                    tokio::task::yield_now().await;
                }
            }
            tx.finish().unwrap();
            Ok(())
        });
        js.spawn(async move {
            // Receiver task.
            let data = collect
                .read(Bounded((start as u64)..=(end as u64)))
                .unwrap()
                .read_into_vec()
                .await
                .unwrap();
            prop_assert_eq!(&data, &flat_body[start..=end]);
            Ok(())
        });
        for result in js.join_all().await {
            result?;
        }
        Ok(())
    }

    proptest! {
        #[test]
        fn both_bounded_range(
            yield_points in proptest::collection::vec(any::<bool>(), 1..20),
            content in body_and_doubly_bounded_range(),
        ) {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            let (body, start, end) = content;
            return rt.block_on(test_both_bounded_range(yield_points, body, start,end));
        }
    }

    async fn test_start_bounded_range(
        yield_points: Vec<bool>,
        body: Vec<Vec<u8>>,
        start: usize,
    ) -> Result<(), TestCaseError> {
        let flat_body: Vec<u8> = body.iter().flatten().map(|&b| b).collect();

        let (mut tx, rx) = StreamingBody::new();
        let collect = CollectingBody::new(Body::from(Chunk::from(rx)), None);
        let mut js = tokio::task::JoinSet::new();
        js.spawn(async move {
            // Sender task.
            for (i, chunk) in body.into_iter().enumerate() {
                tx.send_chunk(chunk).await.unwrap();
                // Fuzz the scheduling:
                if yield_points[i % yield_points.len()] {
                    tokio::task::yield_now().await;
                }
            }
            tx.finish().unwrap();
            Ok(())
        });
        js.spawn(async move {
            // Receiver task.
            let data = collect
                .read(StartingFrom(start as u64))
                .unwrap()
                .read_into_vec()
                .await
                .unwrap();
            prop_assert_eq!(&data, &flat_body[start..]);
            Ok(())
        });
        for result in js.join_all().await {
            result?;
        }
        Ok(())
    }

    proptest! {
        #[test]
        fn start_bounded_range(
            yield_points in proptest::collection::vec(any::<bool>(), 1..20),
            content in body_and_doubly_bounded_range(),
        ) {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            let (body, start, _) = content;
            return rt.block_on(test_start_bounded_range(yield_points, body, start));
        }
    }
}
