use futures::stream::{Stream, StreamExt};
use hyper::body::{Body, Bytes, HttpBody};
use std::collections::VecDeque;
use std::fmt;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

/// The "tee" needs a cloneable error that can be given to both forks of the output stream.
#[derive(Clone, Debug)]
pub struct StringError(String);

impl fmt::Display for StringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StringError {}

#[derive(Debug, Default, Clone)]
struct ConsumerState {
    waker: Option<Waker>,
    cursor: usize,
    active: bool,
}

/// The shared state between the two output streams.
#[derive(Debug)]
struct SharedState {
    /// The buffer holds chunks or an error from the source stream.
    buffer: VecDeque<Result<Bytes, StringError>>,
    /// The absolute index of the first element in the buffer.
    offset: usize,
    /// True if the source stream has finished.
    is_done: bool,
    /// State for the two consumer streams.
    consumers: [ConsumerState; 2],
}

impl Default for SharedState {
    fn default() -> Self {
        Self {
            buffer: VecDeque::new(),
            offset: 0,
            is_done: false,
            consumers: [
                ConsumerState {
                    active: true,
                    ..Default::default()
                },
                ConsumerState {
                    active: true,
                    ..Default::default()
                },
            ],
        }
    }
}

/// A stream that is one of two outputs from the tee operation.
#[derive(Debug)]
pub struct BodyTeeStream {
    shared: Arc<Mutex<SharedState>>,
    id: usize,
}

/// Tees a Body into two independent, error-propagating, and memory-safe streams.
pub async fn tee(mut hyper_body: Body) -> (Body, Body) {
    if HttpBody::size_hint(&hyper_body).exact().is_some() {
        // If the size is known, we MUST buffer the body to preserve the
        // Content-Length.
        let bytes = hyper::body::to_bytes(hyper_body)
            .await
            .expect("Failed to buffer known-size body");
        // `Bytes` is cheap to clone.
        return (hyper::Body::from(bytes.clone()), hyper::Body::from(bytes));
    }

    let shared_state = Arc::new(Mutex::new(SharedState::default()));

    let s1 = BodyTeeStream {
        shared: shared_state.clone(),
        id: 0,
    };

    let s2 = BodyTeeStream {
        shared: shared_state.clone(),
        id: 1,
    };

    tokio::spawn(async move {
        loop {
            let result = hyper_body.next().await;
            let mut state = shared_state.lock().unwrap();

            let finished = if let Some(item) = result {
                // Convert any error into our simple, cloneable StringError.
                let item_to_store = item.map_err(|e| StringError(e.to_string()));
                let is_err = item_to_store.is_err();
                state.buffer.push_back(item_to_store);
                is_err
            } else {
                true
            };

            if finished {
                state.is_done = true;
            }

            for consumer in state.consumers.iter_mut().filter(|c| c.active) {
                if let Some(waker) = consumer.waker.take() {
                    waker.wake();
                }
            }

            drain_buffer(&mut state);

            if finished {
                break;
            }
        }
    });

    (Body::wrap_stream(s1), Body::wrap_stream(s2))
}

impl HttpBody for BodyTeeStream {
    type Data = Bytes;
    // The error type must be convertible into hyper's error type. A boxed
    // standard error is the idiomatic way to do this.
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_data(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Data, Self::Error>>> {
        let this = self.get_mut();
        let mut state = this.shared.lock().unwrap();

        let SharedState {
            buffer,
            offset,
            is_done,
            consumers,
            ..
        } = &mut *state;

        let consumer = &mut consumers[this.id];

        if consumer.cursor >= *offset {
            let buffer_index = consumer.cursor - *offset;
            if let Some(result) = buffer.get(buffer_index) {
                consumer.cursor += 1;
                // FIX: When we read from the buffer, explicitly cast the boxed concrete
                // error to a boxed trait object to satisfy the type checker.
                return Poll::Ready(Some(result.clone().map_err(|e| Box::new(e) as Self::Error)));
            }
        }

        if *is_done {
            return Poll::Ready(None);
        }

        consumer.waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn poll_trailers(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Option<http::HeaderMap>, Self::Error>> {
        Poll::Ready(Ok(None))
    }

    fn is_end_stream(&self) -> bool {
        let state = self.shared.lock().unwrap();
        if !state.is_done {
            return false;
        }
        let consumer = &state.consumers[self.id];
        let total_buffered_chunks = state.offset + state.buffer.len();
        consumer.cursor >= total_buffered_chunks
    }
}

// so it can be used with `Body::wrap_stream`.
impl Stream for BodyTeeStream {
    type Item = Result<Bytes, Box<dyn std::error::Error + Send + Sync>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.poll_data(cx)
    }
}

impl Drop for BodyTeeStream {
    fn drop(&mut self) {
        let mut state = self.shared.lock().unwrap();
        state.consumers[self.id].active = false;

        let other_id = 1 - self.id;
        if state.consumers[other_id].active {
            if let Some(waker) = state.consumers[other_id].waker.take() {
                waker.wake();
            }
        }

        drain_buffer(&mut state);
    }
}

/// Helper to remove chunks from the buffer that all active consumers have read.
fn drain_buffer(state: &mut SharedState) {
    let min_cursor = state
        .consumers
        .iter()
        .filter(|c| c.active)
        .map(|c| c.cursor)
        .min()
        .unwrap_or(state.offset + state.buffer.len());

    let to_drain = min_cursor.saturating_sub(state.offset);
    if to_drain > 0 {
        state.buffer.drain(0..to_drain);
        state.offset += to_drain;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream::{self, StreamExt};
    use hyper::{body::Bytes, Body};
    use std::convert::Infallible;

    #[tokio::test]
    async fn test_simple_duplication() {
        let chunks = vec!["hello", " ", "world"];
        let stream = stream::iter(chunks.clone()).map(|s| Ok::<_, Infallible>(Bytes::from(s)));
        let body = Body::wrap_stream(stream);

        let (body1, body2) = tee(body).await;

        let res1_fut = body1
            .map(|chunk_res| chunk_res.unwrap())
            .collect::<Vec<_>>();
        let res2_fut = body2
            .map(|chunk_res| chunk_res.unwrap())
            .collect::<Vec<_>>();

        let (res1, res2) = futures::join!(res1_fut, res2_fut);

        let res1_str: Vec<&str> = res1
            .iter()
            .map(|b| std::str::from_utf8(b).unwrap())
            .collect();
        let res2_str: Vec<&str> = res2
            .iter()
            .map(|b| std::str::from_utf8(b).unwrap())
            .collect();

        assert_eq!(res1_str, chunks);
        assert_eq!(res2_str, chunks);
    }

    #[tokio::test]
    async fn test_error_propagation() {
        let error = std::io::Error::new(std::io::ErrorKind::Other, "test error");
        let stream = stream::iter(vec![
            Ok(Bytes::from("one")),
            Err(error),
            Ok(Bytes::from("two")),
        ]);
        let body = Body::wrap_stream(stream);

        let (mut body1, mut body2) = tee(body).await;

        assert_eq!(body1.next().await.unwrap().unwrap(), Bytes::from("one"));
        let err1 = body1.next().await.unwrap().unwrap_err();
        assert!(
            err1.to_string().contains("test error"),
            "Got error: {}",
            err1
        );
        assert!(
            body1.next().await.is_none(),
            "Stream should end after error"
        );

        assert_eq!(body2.next().await.unwrap().unwrap(), Bytes::from("one"));
        let err2 = body2.next().await.unwrap().unwrap_err();
        assert!(
            err2.to_string().contains("test error"),
            "Got error: {}",
            err1
        );
        assert!(
            body2.next().await.is_none(),
            "Stream should end after error"
        );
    }

    #[tokio::test]
    async fn test_error_with_one_consumer_dropped() {
        let error = std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "aborted");
        let stream = stream::iter(vec![Ok(Bytes::from("first")), Err(error)]);
        let body = Body::wrap_stream(stream);

        let (mut body1, body2) = tee(body).await;

        drop(body2);

        assert_eq!(body1.next().await.unwrap().unwrap(), Bytes::from("first"));
        let err1 = body1.next().await.unwrap().unwrap_err();
        assert!(err1.to_string().contains("aborted"));
        assert!(
            body1.next().await.is_none(),
            "Stream should end after error"
        );
    }

    #[tokio::test]
    async fn test_size_hint_preservation() {
        let data = "this has a known size";
        let body = Body::from(data);
        let original_size_hint = HttpBody::size_hint(&body);

        assert_eq!(original_size_hint.exact(), Some(data.len() as u64));

        let (body1, body2) = tee(body).await;

        assert_eq!(
            HttpBody::size_hint(&body1).exact(),
            original_size_hint.exact()
        );
        assert_eq!(
            HttpBody::size_hint(&body2).exact(),
            original_size_hint.exact()
        );

        let body1_bytes = hyper::body::to_bytes(body1).await.unwrap();
        let body2_bytes = hyper::body::to_bytes(body2).await.unwrap();

        assert_eq!(body1_bytes, data.as_bytes());
        assert_eq!(body2_bytes, data.as_bytes());
    }
}
