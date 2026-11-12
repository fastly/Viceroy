//! A tee for [`http_body::Body`]. Splits a body into two independent readers,
//! which cooperate to read the source body.
//!
//! Both readers receive the same data, trailers, and errors. Either reader
//! advances the position in source body. If one advances faster than the other,
//! data is retained until caught up.

use bytes::Buf;
use futures_util::task::AtomicWaker;
use http_body::{Body, Frame, SizeHint};
use std::{
    collections::VecDeque,
    error::Error,
    fmt,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Wake, Waker},
};

/// The "tee" needs a cloneable error that can be given to both forks of the output stream.
pub struct TeeError<E>(Arc<E>);

impl<E: fmt::Debug> fmt::Debug for TeeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.0.as_ref(), f)
    }
}

impl<E> PartialEq for TeeError<E>
where
    E: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

// manual clone impl is required since the derive macro
// isn't smart enough to know that Arc<E> is clonable without E being clonable
impl<E> Clone for TeeError<E> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<E: fmt::Display> fmt::Display for TeeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The Arc adds no context, so preserve the underlying error's formatting.
        fmt::Display::fmt(self.0.as_ref(), f)
    }
}

impl<E: Error> Error for TeeError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.source()
    }
}

type TeeFrame<D, E> = Result<Frame<D>, TeeError<E>>;

/// A simple wrapper around two AtomicWakers for each reader, that wakes both.
#[derive(Default)]
struct ReadersWake {
    readers: [AtomicWaker; 2],
}

impl Wake for ReadersWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        for reader in &self.readers {
            reader.wake();
        }
    }
}

struct ConsumerState<D, E> {
    queue: VecDeque<TeeFrame<D, E>>,
}

impl<D, E> Default for ConsumerState<D, E> {
    fn default() -> Self {
        Self {
            queue: VecDeque::new(),
        }
    }
}

/// - `Some`: The source is available for a reader to poll under the state lock.
/// - `None`: The source ended or failed and has been discarded.
type SourceState<B> = Option<Pin<Box<B>>>;

struct State<B: Body> {
    source: SourceState<B>,
    /// State for each live reader.
    readers: [Option<ConsumerState<B::Data, B::Error>>; 2],
}

struct Shared<B: Body> {
    state: Mutex<State<B>>,
    wake: Arc<ReadersWake>,
    /// A [`Waker`] constructed from the same `Arc<ReadersWake>`,
    /// so that the child readers are notified when the source body is ready to be polled.
    /// Storing it here saves us from constructing it on every poll of the source body.
    source_waker: Waker,
}

impl<B: Body> Shared<B> {
    fn register_waker(&self, id: usize, waker: &Waker) {
        self.wake.readers[id].register(waker);
    }
    fn drop_waker(&self, id: usize) {
        drop(self.wake.readers[id].take());
    }
}

/// The result of a reader polling the shared state.
enum Outcome<D, E> {
    Frame {
        frame: TeeFrame<D, E>,
        terminal: bool,
    },
    /// The reader has no more frames.
    End,
    /// No frame is available yet. The reader's registered waker will be woken
    /// when that changes.
    Pending,
}

impl<B> Shared<B>
where
    B: Body,
    B::Data: Clone,
{
    /// Produces the next frame for reader `id`, either from its queue or by
    /// polling the source.
    ///
    /// The ReaderState for this `id` must be present in [State::readers]
    /// when this function is called.
    fn poll_reader(&self, id: usize) -> Outcome<B::Data, B::Error> {
        // id is 0 or 1, so other_idx becomes 1 or 0
        let other_idx = 1 - id;
        let mut state = self.state.lock().unwrap();
        // Only this body's Drop removes its reader entry, and Drop cannot
        // run while poll_frame (our caller) holds an exclusive borrow.
        let reader = state.readers[id].as_mut().unwrap();

        // First check if we have any queued frames.
        if let Some(frame) = reader.queue.pop_front() {
            // This was the last frame if the queue is empty and the source is done.
            let terminal = reader.queue.is_empty() && state.source.is_none();
            return Outcome::Frame { frame, terminal };
        }

        // Otherwise, poll the source body
        // terminal occurs if the stream produced Ready(None),
        // an error, or it hinted that it was the last frame (is_end_stream).
        let (frame, terminal) = match &mut state.source {
            None => return Outcome::End,
            Some(source) => {
                let mut source_cx = Context::from_waker(&self.source_waker);
                match source.as_mut().poll_frame(&mut source_cx) {
                    Poll::Pending => (None, false),
                    Poll::Ready(None) => (None, true),
                    // TODO: we're treating an error as terminal because that's what the prior
                    // implementation did. But nothing in the Body trait or its documentation
                    // requires that an error terminates the stream. We might want to reconsider
                    // this behavior, but I don't know what the downstream consequences would be.
                    Poll::Ready(Some(Err(error))) => (Some(Err(TeeError(Arc::new(error)))), true),
                    Poll::Ready(Some(Ok(frame))) => (Some(Ok(frame)), source.is_end_stream()),
                }
            }
        };

        // If we have a frame and the other reader is alive then enqueue a copy
        // for the other reader
        if let Some(reader) = &mut state.readers[other_idx]
            && let Some(frame) = &frame
        {
            reader.queue.push_back(clone_tee_frame(frame));
        }
        let completed_source = if terminal { state.source.take() } else { None };
        // drop the lock
        drop(state);

        // Some user-provided bodies may have complicated drop impls,
        // so drop outside of the mutex to keep lock duration short
        drop(completed_source);

        // wake the other reader if we have new data or we're done reading
        if frame.is_some() || terminal {
            self.wake.readers[other_idx].wake();
        }

        match frame {
            Some(frame) => Outcome::Frame { frame, terminal },
            None if terminal => Outcome::End,
            None => Outcome::Pending,
        }
    }
}

/// One of the readers returned by [`tee`].
///
/// Readers are independent and hold a queue of unread frames. When dropped they
/// release their queue. The other reader is still free to continue reading.
/// Dropping all readers drops the source body.
pub struct TeeBody<B: Body> {
    shared: Arc<Shared<B>>,
    id: usize,
    size_hint: SizeHint,
    finished: bool,
}

impl<B: Body> fmt::Debug for TeeBody<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TeeBody")
            .field("reader", &self.id)
            .field("size_hint", &self.size_hint)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

/// Tees a Body into two independent, error-propagating, and memory-safe streams.
///
/// This implementation clones the body's data frames, so ensure that the data
/// is cheap to clone (for example [`bytes::Bytes`]).
pub fn tee<B>(body: B) -> (TeeBody<B>, TeeBody<B>)
where
    B: Body,
    B::Data: Clone,
{
    let size_hint = body.size_hint();
    let finished = body.is_end_stream();
    let wake = Arc::new(ReadersWake::default());
    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            source: (!finished).then(|| Box::pin(body)),
            readers: std::array::from_fn(|_| Some(ConsumerState::default())),
        }),
        source_waker: Waker::from(wake.clone()),
        wake,
    });
    let first = TeeBody {
        shared: shared.clone(),
        id: 0,
        size_hint,
        finished,
    };
    let second = TeeBody {
        shared,
        id: 1,
        size_hint,
        finished,
    };
    (first, second)
}

impl<B: Body> TeeBody<B> {
    fn finish(&mut self) {
        self.finished = true;
        self.size_hint = SizeHint::with_exact(0);
        self.shared.drop_waker(self.id);
    }

    /// Updates this reader using a frame result from the source body.
    ///
    /// Updates the size hint based on the received data. If this is the last
    /// frame, or if the result is an error, then finish() is called.
    ///
    /// NB. The hint is derived from the source's hint at construction, minus
    /// the data this reader has received. We could compute it dynamically from the
    /// source's current `size_hint()` plus queued bytes, but that would require
    /// locking the state mutex, and isn't useful unless tee is used with a `Body`
    /// that doesn't know its size up-front.
    fn deliver(
        &mut self,
        result: TeeFrame<B::Data, B::Error>,
        last: bool,
    ) -> TeeFrame<B::Data, B::Error> {
        if let Ok(frame) = &result
            && let Some(data) = frame.data_ref()
        {
            let bytes = data.remaining() as u64;
            let lower = self.size_hint.lower().saturating_sub(bytes);
            // saturating_sub for upper would be misleading,
            // we'd be asserting that there's no more data when
            // more than the original hinted amount had already been provided.
            let upper = self
                .size_hint
                .upper()
                .and_then(|upper| upper.checked_sub(bytes));
            let mut hint = SizeHint::new();
            hint.set_lower(lower);
            if let Some(upper) = upper {
                hint.set_upper(upper);
            }
            self.size_hint = hint;
        }
        if last || result.is_err() {
            self.finish();
        }
        result
    }
}

impl<B> Body for TeeBody<B>
where
    B: Body,
    B::Data: Clone,
{
    type Data = B::Data;
    type Error = TeeError<B::Error>;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.finished {
            return Poll::Ready(None);
        }
        this.shared.register_waker(this.id, cx.waker());

        match this.shared.poll_reader(this.id) {
            Outcome::Frame { frame, terminal } => Poll::Ready(Some(this.deliver(frame, terminal))),
            Outcome::End => {
                this.finish();
                Poll::Ready(None)
            }
            Outcome::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> SizeHint {
        self.size_hint
    }

    fn is_end_stream(&self) -> bool {
        self.finished
    }
}

impl<B: Body> Drop for TeeBody<B> {
    fn drop(&mut self) {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        // remove this reader from the shared state
        let reader = state.readers[self.id].take();
        drop(state);
        drop(reader);
        self.shared.drop_waker(self.id);
    }
}

/// Frame does not implement Clone (even when its held data is Clone).
fn clone_tee_frame<D: Clone, E>(result: &TeeFrame<D, E>) -> TeeFrame<D, E> {
    match result {
        Err(error) => Err(error.clone()),
        Ok(frame) => {
            if let Some(data) = frame.data_ref() {
                Ok(Frame::data(data.clone()))
            } else if let Some(trailers) = frame.trailers_ref() {
                Ok(Frame::trailers(trailers.clone()))
            } else {
                // This should be unlikely, considering the Frame type
                // only has Data & Trailers variants, but there's no guarantee
                // that it stays that way in the future - the enum is not public.
                panic!("unsupported frame type, not data or trailers");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    use bytes::Bytes;
    use futures::stream::StreamExt as _;
    use futures_util::stream;
    use http::{HeaderMap, HeaderValue};
    use http_body_util::{BodyExt as _, StreamBody};
    use proptest::prelude::*;

    #[tokio::test]
    async fn test_simple_duplication() {
        let chunks = vec!["hello", " ", "world"];
        let stream =
            stream::iter(chunks.clone()).map(|s| Ok::<_, Infallible>(Frame::data(Bytes::from(s))));
        let body = StreamBody::new(stream);

        let (body1, body2) = tee(body);

        let res1_fut = body1
            .into_data_stream()
            .map(|chunk| chunk.unwrap())
            .collect::<Vec<_>>();
        let res2_fut = body2
            .into_data_stream()
            .map(|chunk| chunk.unwrap())
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
        let error = std::io::Error::other("test error");
        let stream = stream::iter(vec![
            Ok(Frame::data(Bytes::from("one"))),
            Err(error),
            Ok(Frame::data(Bytes::from("two"))),
        ]);
        let body = StreamBody::new(stream);

        let (mut body1, mut body2) = tee(body);

        assert_eq!(
            body1.frame().await.unwrap().unwrap().into_data().unwrap(),
            Bytes::from("one")
        );
        let err1 = body1.frame().await.unwrap().unwrap_err();
        assert!(
            err1.to_string().contains("test error"),
            "Got error: {}",
            err1
        );
        assert!(
            body1.frame().await.is_none(),
            "Stream should end after error"
        );

        assert_eq!(
            body2.frame().await.unwrap().unwrap().into_data().unwrap(),
            Bytes::from("one")
        );
        let err2 = body2.frame().await.unwrap().unwrap_err();
        assert!(
            err2.to_string().contains("test error"),
            "Got error: {}",
            err2
        );
        assert!(
            body2.frame().await.is_none(),
            "Stream should end after error"
        );
    }

    #[tokio::test]
    async fn test_error_with_one_consumer_dropped() {
        let error = std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "aborted");
        let stream = stream::iter(vec![Ok(Frame::data(Bytes::from("first"))), Err(error)]);
        let body = StreamBody::new(stream);

        let (mut body1, body2) = tee(body);

        drop(body2);

        assert_eq!(
            body1.frame().await.unwrap().unwrap().into_data().unwrap(),
            Bytes::from("first")
        );
        let err1 = body1.frame().await.unwrap().unwrap_err();
        assert!(err1.to_string().contains("aborted"));
        assert!(
            body1.frame().await.is_none(),
            "Stream should end after error"
        );
    }

    #[tokio::test]
    async fn test_size_hint_preservation() {
        let data = "this has a known size";
        let body = http_body_util::Full::new(Bytes::from_static(data.as_bytes()));
        let original_size_hint = body.size_hint();

        assert_eq!(original_size_hint.exact(), Some(data.len() as u64));

        let (body1, body2) = tee(body);

        assert_eq!(body1.size_hint().exact(), original_size_hint.exact());
        assert_eq!(body2.size_hint().exact(), original_size_hint.exact());

        let body1_bytes = body1.collect().await.unwrap().to_bytes();
        let body2_bytes = body2.collect().await.unwrap().to_bytes();

        assert_eq!(body1_bytes, data.as_bytes());
        assert_eq!(body2_bytes, data.as_bytes());
    }

    /// An empty body shouldn't be retained or polled.
    /// The source body is dropped when empty.
    #[test]
    fn empty_source_dropped() {
        use std::sync::atomic::{AtomicBool, Ordering};

        // body that panics if stream is ended.
        // if stream isn't ended, returns a single empty frame and then ends.
        struct OnceBody(Arc<AtomicBool>);
        impl Body for OnceBody {
            type Data = Bytes;
            type Error = ();
            fn poll_frame(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
                if !self.0.swap(true, Ordering::SeqCst) {
                    Poll::Ready(Some(Ok(Frame::data(Bytes::new()))))
                } else {
                    panic!("source body polled after end");
                }
            }
            fn is_end_stream(&self) -> bool {
                self.0.load(Ordering::SeqCst)
            }
        }

        // an already finished body is immediately dropped
        {
            let inner = Arc::new(AtomicBool::new(true));
            let (mut first, mut second) = tee(OnceBody(inner.clone()));
            assert_eq!(
                Arc::strong_count(&inner),
                1,
                "source body should be dropped"
            );
            assert!(first.is_end_stream());
            assert!(second.is_end_stream());

            let mut cx = Context::from_waker(Waker::noop());
            assert!(matches!(
                Pin::new(&mut first).poll_frame(&mut cx),
                Poll::Ready(None)
            ));
            assert!(matches!(
                Pin::new(&mut second).poll_frame(&mut cx),
                Poll::Ready(None)
            ));
        }

        // source body is dropped as soon as it completes
        {
            let inner = Arc::new(AtomicBool::new(false));
            let (mut first, mut second) = tee(OnceBody(inner.clone()));
            // body is stored in the Arc wrapped shared state
            assert_eq!(Arc::strong_count(&inner), 2);
            assert!(!first.is_end_stream());
            assert!(!second.is_end_stream());

            let mut cx = Context::from_waker(Waker::noop());
            assert!(matches!(
                Pin::new(&mut first).poll_frame(&mut cx),
                Poll::Ready(Some(Ok(_)))
            ));
            // held body should have been dropped since
            // it reported end of stream
            assert_eq!(Arc::strong_count(&inner), 1);
            // yet, we can still poll the second since frame is buffered
            assert!(matches!(
                Pin::new(&mut second).poll_frame(&mut cx),
                Poll::Ready(Some(Ok(_)))
            ));
        }
    }

    /// - When both readers are dropped, the source body is dropped too.
    /// - When a reader is dropped, any buffered frames for it are dropped.
    /// - Reading a buffered frame releases it from the reader's buffer.
    #[test]
    fn reader_state_lifetime() {
        // data that tracks whether it was dropped
        #[derive(Clone)]
        struct Tracked(Arc<()>);
        impl Default for Tracked {
            fn default() -> Self {
                Self(Arc::new(()))
            }
        }
        impl bytes::Buf for Tracked {
            fn remaining(&self) -> usize {
                1
            }
            fn chunk(&self) -> &[u8] {
                &[0]
            }
            fn advance(&mut self, _cnt: usize) {}
        }

        let list = [Tracked::default(), Tracked::default(), Tracked::default()];
        assert!(list.iter().all(|t| Arc::strong_count(&t.0) == 1));

        let body = StreamBody::new(stream::iter(
            list.iter()
                .cloned()
                .map(|t| Ok(Frame::data(t)))
                .collect::<Vec<Result<_, Infallible>>>(),
        ));

        let (mut first, mut second) = tee(body);
        // should only have 2 strong references to each tracked
        // one for our original list, one for the queue in StreamBody.
        assert!(list.iter().all(|t| Arc::strong_count(&t.0) == 2));

        let mut cx = Context::from_waker(Waker::noop());
        let mut read_data = |reader: &mut TeeBody<_>| {
            let Poll::Ready(Some(Ok(frame))) = Pin::new(reader).poll_frame(&mut cx) else {
                panic!("expected a data frame");
            };
            frame.into_data().ok().expect("expected data, not trailers")
        };

        // poll a frame using the first reader
        // assert that the second reader has a copy of the frame in its queue
        let first_data = read_data(&mut first);
        assert!(Arc::ptr_eq(&first_data.0, &list[0].0));
        assert_eq!(Arc::strong_count(&list[0].0), 3);
        drop(first_data);
        assert_eq!(Arc::strong_count(&list[0].0), 2);

        // poll the second reader: the delivered frame must leave its buffer.
        let second_data = read_data(&mut second);
        assert!(Arc::ptr_eq(&second_data.0, &list[0].0));
        assert_eq!(Arc::strong_count(&list[0].0), 2);
        // Dropping the delivered data leaves only our original reference,
        // even though both readers are still alive.
        drop(second_data);
        assert_eq!(Arc::strong_count(&list[0].0), 1);

        // poll the first again, count should bump for the second frame.
        let first_data = read_data(&mut first);
        assert!(Arc::ptr_eq(&first_data.0, &list[1].0));
        assert_eq!(Arc::strong_count(&list[1].0), 3);
        drop(first_data);
        assert_eq!(Arc::strong_count(&list[1].0), 2);

        // drop the second reader, second frame's count should drop
        // indicating that the reader's queue was dropped
        drop(second);
        assert_eq!(Arc::strong_count(&list[1].0), 1);
        // The third frame is still held by the unexhausted source body.
        assert_eq!(Arc::strong_count(&list[2].0), 2);

        // drop the first reader. the source body is dropped with it
        drop(first);
        assert!(list.iter().all(|t| Arc::strong_count(&t.0) == 1));
    }

    /// Reading a new frame properly updates the size hint
    #[test]
    fn size_hints_update() {
        let data = |s: &'static str| Ok(ExpectedFrame::Data(Bytes::from_static(s.as_bytes())));
        let trailers = Ok(ExpectedFrame::Trailers(HeaderMap::new()));
        let frames = [data("abc"), data("defg"), trailers];
        let mut cx = Context::from_waker(Waker::noop());
        let mut poll = |reader: &mut TeeBody<_>| {
            let Poll::Ready(frame) = Pin::new(reader).poll_frame(&mut cx) else {
                panic!("source is always ready");
            };
            frame.map(|f| f.expect("source never errors"))
        };
        let bounds = |reader: &TeeBody<_>| {
            let hint = reader.size_hint();
            (hint.lower(), hint.upper())
        };

        // an unbounded upper stays unbounded, the lower bound saturates,
        // and the hint becomes exactly 0 at end of stream.
        {
            let source = Hinted::new(body_from_frames(&frames), 5, None);
            let (mut first, _second) = tee(source);
            assert!(poll(&mut first).is_some_and(|f| f.is_data()));
            assert_eq!(bounds(&first), (2, None));
            assert!(poll(&mut first).is_some_and(|f| f.is_data()));
            assert_eq!(bounds(&first), (0, None));
            assert!(poll(&mut first).is_some_and(|f| f.is_trailers()));
            assert_eq!(bounds(&first), (0, None));
            assert!(poll(&mut first).is_none());
            assert_eq!(bounds(&first), (0, Some(0)));
        }

        // a source that sends more than its upper bound loses the bound,
        // since more data may still follow
        {
            let source = Hinted::new(body_from_frames(&frames), 1, Some(5));
            let (mut first, _second) = tee(source);
            assert!(poll(&mut first).is_some_and(|f| f.is_data()));
            assert_eq!(bounds(&first), (0, Some(2)));
            assert!(poll(&mut first).is_some_and(|f| f.is_data()));
            assert_eq!(bounds(&first), (0, None));
            assert!(!first.is_end_stream());
            // the bound stays dropped for the rest of the stream
            assert!(poll(&mut first).is_some_and(|f| f.is_trailers()));
            assert_eq!(bounds(&first), (0, None));
            assert!(poll(&mut first).is_none());
            assert_eq!(bounds(&first), (0, Some(0)));
        }
    }

    proptest! {
        /// An error from the source body is delivered to both readers.
        /// An error terminates the child streams.
        #[test]
        fn both_readers_see_error(
            (expected, poll_order) in arb_body_and_poll_order(true)
        ) {
            // poll through the whole poll sequence.
            // compare the errors to see they're equal: same position, same value
            // assert that no reader read past the error

            let (first, second) = tee(body_from_frames(&expected));
            let mut readers = [first, second];
            // tracks the position of each reader in expected
            let mut positions = [0; 2];
            let mut errors: [Option<(usize, TeeError<TestError>)>; 2] = [None, None];
            let mut cx = Context::from_waker(Waker::noop());

            let mut check_next_frame = |id: usize| {
                match Pin::new(&mut readers[id]).poll_frame(&mut cx) {
                    Poll::Ready(Some(val)) => {
                        if let Err(err) = val {
                            prop_assert!(errors[id].is_none(), "reader {id} received multiple errors");
                            errors[id] = Some((positions[id], err));
                        }
                        positions[id] += 1;
                    }
                    Poll::Ready(None) => {},
                    other => return Err(proptest::test_runner::TestCaseError::fail(
                        format!("reader {id} unexpectedly returned {other:?}"),
                    )),
                };
                Ok(())
            };

            for id in poll_order {
                check_next_frame(id)?;
            }
            // Extra polls past the schedule must not produce anything either.
            for id in 0..2 {
                check_next_frame(id)?;
                check_next_frame(id)?;
            }

            if expected.is_empty() {
                return Ok(());
            }

            // arb_body_frames(true) always generates at least one error
            // (if any frames were generated at all).
            let first_error = expected
                .iter()
                .position(Result::is_err)
                .expect("arb_body_frames(true) generated no error");
            for (id, error) in errors.iter().enumerate() {
                let Some((position, _)) = error else {
                    return Err(proptest::test_runner::TestCaseError::fail(
                        format!("reader {id} never received an error"),
                    ));
                };
                prop_assert_eq!(*position, first_error, "reader {} error position", id);
            }
            prop_assert_eq!(&errors[0], &errors[1]);
            // nothing past the first error was delivered
            prop_assert_eq!(positions, [first_error + 1; 2]);
            prop_assert!(readers.iter().all(Body::is_end_stream));
        }

        /// Reader poll order can be arbitrary, the readers see the same frame
        /// sequence regardless of which reader polls first.
        #[test]
        fn reads_can_complete_in_any_order(
            (expected, poll_order) in arb_body_and_poll_order(false),
        ) {
            // poll through the whole poll sequence, checking as
            // we go against the expected frame for the reader's position.
            // check that the stream returns eof after the last frame.
            // check that both readers read all frames.

            let (first, second) = tee(body_from_frames(&expected));
            let mut readers = [first, second];
            // tracks the position of each reader in expected
            let mut positions = [0; 2];
            let mut cx = Context::from_waker(Waker::noop());

            // Check one poll against this reader's next expected frame.
            // Return whether it produced a frame (false means end of stream).
            let mut check_next_frame = |id: usize| {
                let actual = match Pin::new(&mut readers[id]).poll_frame(&mut cx) {
                    Poll::Ready(Some(Ok(frame))) => Some(Ok(frame.into())),
                    Poll::Ready(None) => None,
                    other => return Err(proptest::test_runner::TestCaseError::fail(
                        format!("reader {id} unexpectedly returned {other:?}"),
                    )),
                };
                prop_assert_eq!(
                    actual.as_ref(),
                    expected.get(positions[id]),
                    "reader {} at frame {}", id, positions[id],
                );
                if actual.is_some() {
                    positions[id] += 1;
                }
                Ok(actual.is_some())
            };

            // The permutation reads every frame once from each reader.
            for id in poll_order {
                prop_assert!(check_next_frame(id)?);
            }

            // Both readers must now return EOF, and keep returning it.
            for id in 0..2 {
                prop_assert!(!check_next_frame(id)?);
                prop_assert!(!check_next_frame(id)?);
            }
            // check that both positions are at the end of the expected sequence
            prop_assert_eq!(positions, [expected.len(); 2]);
            // and that all readers report end of stream
            prop_assert!(readers.iter().all(Body::is_end_stream));
        }

        /// When the source reports an accurate exact size, each reader's hint is
        /// exactly the number of data bytes it has left to read, regardless of
        /// poll order.
        #[test]
        fn exact_size_hint_tracks_remaining(
            (expected, poll_order) in arb_body_and_poll_order(false),
        ) {
            let data_len = |frame: &TestFrame| match frame {
                Ok(ExpectedFrame::Data(data)) => data.len() as u64,
                _ => 0,
            };
            let total: u64 = expected.iter().map(data_len).sum();
            let source = Hinted::new(body_from_frames(&expected), total, Some(total));
            let (first, second) = tee(source);
            let mut readers = [first, second];
            let mut positions = [0; 2];
            let mut cx = Context::from_waker(Waker::noop());

            for id in poll_order {
                let polled = Pin::new(&mut readers[id]).poll_frame(&mut cx);
                prop_assert!(matches!(polled, Poll::Ready(Some(Ok(_)))));
                positions[id] += 1;
                for (id, reader) in readers.iter().enumerate() {
                    let remaining: u64 = expected[positions[id]..].iter().map(data_len).sum();
                    prop_assert_eq!(
                        reader.size_hint().exact(),
                        Some(remaining),
                        "reader {} at frame {}", id, positions[id],
                    );
                }
            }
            for reader in &mut readers {
                prop_assert!(matches!(
                    Pin::new(&mut *reader).poll_frame(&mut cx),
                    Poll::Ready(None)
                ));
                prop_assert_eq!(reader.size_hint().exact(), Some(0));
            }
        }
    }

    /// Wraps a body, overriding its size hint.
    struct Hinted<B> {
        body: B,
        hint: SizeHint,
    }
    impl<B> Hinted<B> {
        fn new(body: B, lower: u64, upper: Option<u64>) -> Self {
            let mut hint = SizeHint::new();
            hint.set_lower(lower);
            if let Some(upper) = upper {
                hint.set_upper(upper);
            }
            Self { body, hint }
        }
    }
    impl<B: Body + Unpin> Body for Hinted<B> {
        type Data = B::Data;
        type Error = B::Error;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Pin::new(&mut self.body).poll_frame(cx)
        }
        fn size_hint(&self) -> SizeHint {
            self.hint
        }
        fn is_end_stream(&self) -> bool {
            self.body.is_end_stream()
        }
    }

    #[derive(Clone, Debug, PartialEq)]
    enum ExpectedFrame {
        Data(Bytes),
        Trailers(HeaderMap),
    }
    #[derive(Clone, Copy, Debug, PartialEq)]
    struct TestError(u32);
    type TestFrame = Result<ExpectedFrame, TestError>;

    impl From<Frame<Bytes>> for ExpectedFrame {
        fn from(frame: Frame<Bytes>) -> Self {
            if let Some(data) = frame.data_ref() {
                Self::Data(data.clone())
            } else if let Some(trailers) = frame.trailers_ref() {
                Self::Trailers(trailers.clone())
            } else {
                panic!("unsupported frame type, not data or trailers");
            }
        }
    }
    impl From<ExpectedFrame> for Frame<Bytes> {
        fn from(expected: ExpectedFrame) -> Self {
            match expected {
                ExpectedFrame::Data(data) => Frame::data(data),
                ExpectedFrame::Trailers(trailers) => Frame::trailers(trailers),
            }
        }
    }

    const MAX_FRAMES: usize = 32;

    /// Generate arbitrary frame sequences, including multiple trailers and data
    /// after trailers: the tee should preserve even nonstandard source sequences.
    ///
    /// When `err` is false, every item is `Ok`. When `err` is true, the sequence
    /// contains at least one `Err`, followed by more arbitrary items (frames and
    /// further errors) that the source still yields but readers must not see.
    fn arb_body_frames(err: bool) -> impl Strategy<Value = Vec<TestFrame>> {
        let frame = || {
            prop_oneof![
                prop::collection::vec(any::<u8>(), 0..64)
                    .prop_map(|data| ExpectedFrame::Data(Bytes::from(data))),
                "[a-z0-9]{0,32}".prop_map(|value| {
                    let mut trailers = HeaderMap::new();
                    trailers.insert("x-trailer", HeaderValue::from_str(&value).unwrap());
                    ExpectedFrame::Trailers(trailers)
                }),
            ]
        };
        let error = || any::<u32>().prop_map(TestError);

        // generate 1-3 errors if err is true, otherwise 0
        let err_range = if err { 1..=3 } else { 0..=0 };

        (
            prop::collection::vec(frame().prop_map(Ok), 0..=MAX_FRAMES),
            prop::collection::vec((any::<prop::sample::Index>(), error()), err_range),
        )
            .prop_map(move |(mut frames, errs)| {
                if !frames.is_empty() {
                    for (idx, error) in errs {
                        let idx = idx.index(frames.len());
                        frames[idx] = Err(error);
                    }
                }
                frames
            })
    }

    /// Constructs a http body from a list of frames
    fn body_from_frames(
        frames: &[TestFrame],
    ) -> impl Body<Data = Bytes, Error = TestError> + Unpin + use<> {
        let frames: Vec<_> = frames.iter().cloned().map(|f| f.map(Into::into)).collect();
        StreamBody::new(stream::iter(frames))
    }

    /// Pair frames with a shuffled schedule containing one poll per frame per reader.
    fn arb_body_and_poll_order(err: bool) -> impl Strategy<Value = (Vec<TestFrame>, Vec<usize>)> {
        (
            arb_body_frames(err),
            // One choice per poll, generated independently of frames so they
            // shrink separately. `false` picks reader 0, `true` picks reader 1.
            prop::collection::vec(any::<bool>(), 2 * MAX_FRAMES),
        )
            .prop_map(|(frames, picks)| {
                let mut remaining = [frames.len(); 2];
                let poll_order = picks
                    .into_iter()
                    .take(2 * frames.len())
                    .map(|pick| {
                        let id = pick as usize;
                        // once a reader has all its polls, the rest go to the other
                        let id = if remaining[id] > 0 { id } else { 1 - id };
                        remaining[id] -= 1;
                        id
                    })
                    .collect();
                (frames, poll_order)
            })
    }
}
