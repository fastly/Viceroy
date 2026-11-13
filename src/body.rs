//! Body type, for request and response bodies.

use {
    crate::{
        Error,
        error::{self, BoxError, HyperError},
        streaming_body::StreamingBodyItem,
    },
    bytes::{Buf, BufMut, BytesMut},
    flate2::write::GzDecoder,
    http::header::HeaderMap,
    http_body::{Body as HttpBody, Frame, SizeHint},
    http_body_util::{BodyExt, StreamBody, combinators::BoxBody},
    hyper::body::Incoming,
    std::{
        collections::VecDeque,
        io::Write,
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    },
    tokio::{sync::mpsc, time::Instant},
};

type DecoderState = Box<GzDecoder<bytes::buf::Writer<BytesMut>>>;

/// A type-erased HTTP body, with errors already mapped into our [`Error`] type.
type BoxedBody = BoxBody<bytes::Bytes, Error>;

/// Box an arbitrary [`http_body::Body`], mapping its errors into a [`HyperError`].
fn box_body<B>(body: B) -> BoxedBody
where
    B: HttpBody<Data = bytes::Bytes> + Send + Sync + 'static,
    B::Error: Into<BoxError>,
{
    body.map_err(|e| HyperError::new(e).into()).boxed()
}

/// A chunk of bytes in a [`Body`].
///
/// A chunk represents a block of data in a body. Representing bodies as chunks allows us to append
/// one body to another without copying, and makes it possible from parts of the body to come from
/// different sources, including ongoing asynchronous streaming.
#[derive(Debug)]
pub enum Chunk {
    /// An owned byte buffer, e.g. one we've allocated while writing to a `Body`.
    Bytes(bytes::Bytes),
    /// Wraps an arbitrary http body.
    ///
    /// We use this variant for data that's incoming from a Hyper request or response.
    HttpBody(BoxedBody),
    /// A channel for bodies that may be written to after headers have been sent, such as after
    /// `send_downstream_streaming` or `send_async_streaming`.
    ///
    /// Since the channel yields chunks, this variant represents a *stream* of chunks rather than
    /// one individual chunk. That stream is effectively "flattened" on-demand, as the `Body`
    /// containing it is read.
    Channel(mpsc::Receiver<StreamingBodyItem>),
    /// A version of `HttpBody` that assumes that the interior data is gzip-compressed.
    CompressedHttpBody(DecoderState, BoxedBody),
}

impl Chunk {
    /// Wrap an arbitrary [`http_body::Body`] as a chunk.
    pub fn http_body<B>(body: B) -> Chunk
    where
        B: HttpBody<Data = bytes::Bytes> + Send + Sync + 'static,
        B::Error: Into<BoxError>,
    {
        Chunk::HttpBody(box_body(body))
    }

    /// Wrap an arbitrary gzip-compressed [`http_body::Body`] as a chunk that will be decompressed
    /// as it is read.
    pub fn compressed_body<B>(body: B) -> Chunk
    where
        B: HttpBody<Data = bytes::Bytes> + Send + Sync + 'static,
        B::Error: Into<BoxError>,
    {
        let initial_state = Box::new(GzDecoder::new(BytesMut::new().writer()));
        Chunk::CompressedHttpBody(initial_state, box_body(body))
    }
}

impl From<&[u8]> for Chunk {
    fn from(bytes: &[u8]) -> Self {
        Self::Bytes(bytes::Bytes::copy_from_slice(bytes))
    }
}

impl From<&'static str> for Chunk {
    fn from(s: &'static str) -> Self {
        Self::Bytes(bytes::Bytes::from_static(s.as_bytes()))
    }
}

impl From<Vec<u8>> for Chunk {
    fn from(vec: Vec<u8>) -> Self {
        Self::Bytes(vec.into())
    }
}

impl From<String> for Chunk {
    fn from(s: String) -> Self {
        Self::Bytes(s.into())
    }
}

impl From<bytes::Bytes> for Chunk {
    fn from(bytes: bytes::Bytes) -> Self {
        Self::Bytes(bytes)
    }
}

impl From<Incoming> for Chunk {
    fn from(body: Incoming) -> Self {
        Chunk::http_body(body)
    }
}

impl From<mpsc::Receiver<StreamingBodyItem>> for Chunk {
    fn from(chan: mpsc::Receiver<StreamingBodyItem>) -> Self {
        Chunk::Channel(chan)
    }
}

/// An HTTP request or response body.
///
/// Most importantly, this type implements [`http_body::Body`][body-trait]. It also
/// has facilities to write to an existing body, and to append bodies to one another.
///
/// [body-trait]: https://docs.rs/http-body/latest/http_body/trait.Body.html
#[derive(Debug)]
pub struct Body {
    chunks: VecDeque<Chunk>,
    between_bytes_timeout: Duration,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    pub(crate) trailers: HeaderMap,
    pub(crate) trailers_ready: bool,
    /// Whether the accumulated trailers have been yielded as the final frame of this body.
    /// We need a separate flag, instead of emptying `trailers`, since other code attempts
    /// to access the cached trailers map, which can occur after the body has been fully read.
    trailers_sent: bool,
}

impl Default for Body {
    fn default() -> Self {
        Body {
            chunks: VecDeque::new(),
            between_bytes_timeout: Duration::MAX,
            sleep: None,
            trailers: HeaderMap::new(),
            trailers_ready: false,
            trailers_sent: false,
        }
    }
}

impl Body {
    /// Construct a body from an arbitrary [`http_body::Body`].
    pub fn http_body<B>(body: B) -> Body
    where
        B: HttpBody<Data = bytes::Bytes> + Send + Sync + 'static,
        B::Error: Into<BoxError>,
    {
        Chunk::HttpBody(box_body(body)).into()
    }

    /// Wrap an arbitrary gzip-compressed [`http_body::Body`] as a chunk that will be decompressed
    /// as it is read.
    pub fn compressed_body<B>(body: B) -> Body
    where
        B: HttpBody<Data = bytes::Bytes> + Send + Sync + 'static,
        B::Error: Into<BoxError>,
    {
        let initial_state = Box::new(GzDecoder::new(BytesMut::new().writer()));
        Chunk::CompressedHttpBody(initial_state, box_body(body)).into()
    }

    /// Get a new, empty body.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Push a new chunk onto the body.
    pub fn push_back(&mut self, chunk: impl Into<Chunk>) {
        self.chunks.push_back(chunk.into());
    }

    /// Push a new chunk onto the front of the body.
    pub fn push_front(&mut self, chunk: impl Into<Chunk>) {
        self.chunks.push_front(chunk.into());
    }

    /// Append another body to this body.
    pub fn append(&mut self, body: Self) {
        self.extend(body)
    }

    /// Analogue to the AsyncRead traits, but without running through std::io::Result.
    ///
    /// Attempts to read at least one byte into the buffer.
    /// Waits until at least one byte is available. If an error is encountered,
    /// returns the error; if the stream ends, returns Ok(0).
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, error::Error> {
        // poll_data doesn't return empty chunks, so we can be sure that if we
        // get a chunk, it has at least one byte.
        let Some(result) = std::future::poll_fn(|cx| self.poll_data(cx)).await else {
            return Ok(0);
        };
        let mut src = result?;

        let copy_len = std::cmp::min(buf.len(), src.len());
        buf[..copy_len].copy_from_slice(&src[..copy_len]);
        src.advance(copy_len);
        // re-queue if anything remains
        if !src.is_empty() {
            self.chunks.push_front(Chunk::Bytes(src));
        }
        Ok(copy_len)
    }

    /// Read the entire body into a byte vector.
    pub async fn read_into_vec(self) -> Result<Vec<u8>, error::Error> {
        Ok(self.collect().await?.to_bytes().into())
    }

    /// Read the entire body into a `String`
    ///
    /// # Panics
    ///
    /// Panics if the body is not valid UTF-8.
    pub async fn read_into_string(self) -> Result<String, error::Error> {
        Ok(String::from_utf8(self.read_into_vec().await?).expect("Body was not UTF-8"))
    }

    /// Block until the body has a chunk ready (or is known to be empty).
    pub async fn await_ready(&mut self) {
        // Attempt to read data, blocking until some is available (or `None` signals data EOF).
        // Trailers are accumulated without consuming their final frame.
        match std::future::poll_fn(|cx| self.poll_data(cx)).await {
            // If we did get a chunk, put it back; subsequent read attempts will find this chunk
            // without additional blocking.
            Some(Ok(chunk)) => self.chunks.push_front(Chunk::Bytes(chunk)),
            // Likewise "put back" an error, as a body that yields only that error, so that it is
            // reported by the next read rather than swallowed.
            Some(Err(e)) => {
                let error_body = StreamBody::new(futures::stream::iter([Err(e)]));
                self.chunks.push_front(Chunk::HttpBody(error_body.boxed()));
            }
            None => {}
        }
    }

    pub fn len(&self) -> Option<u64> {
        let mut len = 0u64;

        for chunk in &self.chunks {
            match chunk {
                Chunk::Bytes(bytes) => len = len.checked_add(bytes.len() as u64)?,
                Chunk::HttpBody(body) => len = len.checked_add(body.size_hint().exact()?)?,
                _ => return None,
            }
        }

        Some(len)
    }

    pub fn is_empty(&self) -> Option<bool> {
        self.len().map(|len| len == 0)
    }
}

impl<T: Into<Chunk>> From<T> for Body {
    fn from(chunk: T) -> Self {
        let mut body = Body::empty();
        body.push_back(chunk);
        body
    }
}

impl Extend<Chunk> for Body {
    fn extend<I: IntoIterator<Item = Chunk>>(&mut self, iter: I) {
        self.chunks.extend(iter);
    }
}

impl IntoIterator for Body {
    type Item = Chunk;
    type IntoIter = <VecDeque<Chunk> as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        self.chunks.into_iter()
    }
}

impl Body {
    pub fn set_between_bytes_timeout(&mut self, timeout: Duration) {
        self.between_bytes_timeout = timeout;
        self.sleep = Some(Box::pin(tokio::time::sleep(timeout)));
    }

    fn reset_between_bytes_timeout_timer(&mut self) {
        if let Some(sleep) = self.sleep.as_mut() {
            sleep
                .as_mut()
                .reset(Instant::now() + self.between_bytes_timeout);
        }
    }

    fn check_timeout_on_pending(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Option<Result<bytes::Bytes, error::Error>>> {
        if let Some(sleep) = &mut self.sleep
            && sleep.as_mut().poll(cx).is_ready()
        {
            return Poll::Ready(Some(Err(Error::BetweenBytesTimeout)));
        }

        Poll::Pending
    }

    /// Unified poll handling for a boxed body, which can be normal or
    /// compressed. Decompression is handled through the `BodyTransform` trait.
    ///
    /// Calls `poll_frame` on the body and handles the result: - For pending
    /// frames, checks the timeout - For EOF, calls the transform's `on_finish`
    /// method and returns the result. We mark the body as exhausted, so it
    /// won't be re-queued for polling. Byte timeouts are only reset if the
    /// transform produced data. - For errors, returns the error - For data
    /// frames, we reset the between bytes timeout, and call the transform's
    /// `on_data` method to process the bytes. An error from the transform
    /// exhausts the body. - For trailer frames, we accumulate the trailers and
    /// return `Poll::Ready(None)` without exhausting the body, so it will be
    /// re-queued for polling.
    fn poll_body(
        &mut self,
        body: &mut BoxedBody,
        cx: &mut Context,
        mut transform: impl BodyTransform,
    ) -> BodyPoll {
        match Pin::new(body).poll_frame(cx) {
            Poll::Pending => Pin::new(self).check_timeout_on_pending(cx).into(),
            // no more frames from this body, but the transform may have some
            // final data to yield.
            Poll::Ready(None) => match transform.on_finish() {
                Err(e) => BodyPoll {
                    finished: true,
                    result: Poll::Ready(Some(Err(e))),
                },
                Ok(d) => {
                    // we don't reset the between-bytes timeout here, it should
                    // only be reset based on incoming bytes not on any final
                    // bytes left in a decoder buffer. incoming bytes are
                    // handled in the Poll:Ready(Some(Ok(frame))) branch below
                    BodyPoll {
                        finished: true,
                        result: Poll::Ready(d.map(Ok)),
                    }
                }
            },
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))).into(),
            Poll::Ready(Some(Ok(frame))) => {
                match frame.into_data() {
                    Ok(data) => {
                        if !data.is_empty() {
                            self.reset_between_bytes_timeout_timer();
                        }
                        let data = match transform.on_data(data) {
                            Ok(data) => data,
                            Err(e) => {
                                return BodyPoll {
                                    finished: true,
                                    result: Poll::Ready(Some(Err(e))),
                                };
                            }
                        };

                        Poll::Ready(Some(Ok(data))).into()
                    }
                    Err(frame) => {
                        // Trailers are accumulated, and yielded once all chunks are
                        // exhausted. Any other kind of frame is unknown to us, so skip it.
                        if let Ok(header_map) = frame.into_trailers() {
                            // `HeaderMap::extend` overwrites any existing headers with the same name
                            // which we don't want.
                            for (k, v) in header_map.iter() {
                                self.trailers.append(k, v.clone());
                            }
                        }
                        // indicates the loop should continue,
                        // we haven't marked body as finished so it'll be re-queued
                        Poll::Ready(None).into()
                    }
                }
            }
        }
    }

    /// Polls the queue of chunks for data. Accumulates any trailer frames but
    /// does not yield them.
    ///
    /// Produced data is guaranteed to be non-empty.
    fn poll_data(&mut self, cx: &mut Context) -> Poll<Option<Result<bytes::Bytes, error::Error>>> {
        while let Some(mut chunk) = self.chunks.pop_front() {
            let body_poll = match chunk {
                Chunk::Bytes(bytes) => {
                    if bytes.is_empty() {
                        // nothing to yield, so move on to the next chunk
                        continue;
                    }
                    self.reset_between_bytes_timeout_timer();
                    return Poll::Ready(Some(Ok(bytes)));
                }
                Chunk::Channel(ref mut receiver) => {
                    match Pin::new(receiver).poll_recv(cx) {
                        Poll::Pending => {
                            // put the channel back, so we can poll it again next time
                            self.chunks.push_front(chunk);
                            return Pin::new(self).check_timeout_on_pending(cx);
                        }
                        Poll::Ready(None) => {
                            // the channel completed without a Finish message, so yield an error
                            return Poll::Ready(Some(Err(Error::UnfinishedStreamingBody)));
                        }
                        Poll::Ready(Some(StreamingBodyItem::Chunk(inner))) => {
                            // put the channel back first, so we can poll it again after the chunk it
                            // just yielded
                            self.chunks.push_front(chunk);
                            // now push the chunk which will be polled appropriately the next time
                            // through the loop
                            self.chunks.push_front(inner);
                            // TODO: is this reset correct? The inner chunk may not actually hold
                            // any bytes, and the StreamingBodyItem is just for flattening/framing
                            self.reset_between_bytes_timeout_timer();
                            continue;
                        }
                        Poll::Ready(Some(StreamingBodyItem::Finished(trailers))) => {
                            // `HeaderMap::extend` overwrites any existing headers with the same name
                            // which we don't want.
                            for (k, v) in trailers.iter() {
                                self.trailers.append(k, v.clone());
                            }
                            // it shouldn't be possible for any more chunks to arrive on this
                            // channel, but just in case we won't try to read them; dropping the
                            // receiver means we won't hit the `Ready(None)` case above that
                            // indicates an unfinished streaming body
                            continue;
                        }
                    }
                }
                Chunk::HttpBody(ref mut body) => self.poll_body(body, cx, NoTransform),
                Chunk::CompressedHttpBody(ref mut decoder_state, ref mut body) => {
                    self.poll_body(body, cx, decoder_state)
                }
            };

            if !body_poll.finished {
                // put the body back, so we can poll it again next time
                self.chunks.push_front(chunk);
            }
            match body_poll.result {
                // chunk may be finished, continue to the next
                // (which may be the same chunk if it was re-pushed above)
                Poll::Ready(None) => continue,
                // skip empty frames
                Poll::Ready(Some(Ok(bytes))) if bytes.is_empty() => continue,
                result => return result,
            }
        }

        // With no more chunks arriving we can mark trailers as being ready.
        self.trailers_ready = true;
        Poll::Ready(None)
    }
}

/// Result of polling a body for data once
struct BodyPoll {
    /// Body is exhausted, don't requeue it for further polling
    finished: bool,
    /// A Poll result containing data (no Frame/trailers)
    result: Poll<Option<Result<bytes::Bytes, error::Error>>>,
}
impl From<Poll<Option<Result<bytes::Bytes, error::Error>>>> for BodyPoll {
    fn from(poll: Poll<Option<Result<bytes::Bytes, error::Error>>>) -> Self {
        BodyPoll {
            finished: false,
            result: poll,
        }
    }
}

/// Allows transforming the bytes of a body as they are read
/// with `Body::poll_body`.
///
/// This is used for decompressing gzip-compressed bodies.
trait BodyTransform {
    fn on_data(&mut self, data: bytes::Bytes) -> Result<bytes::Bytes, error::Error> {
        Ok(data)
    }
    fn on_finish(&mut self) -> Result<Option<bytes::Bytes>, error::Error> {
        Ok(None)
    }
}
struct NoTransform;
impl BodyTransform for NoTransform {}

impl BodyTransform for &mut DecoderState {
    fn on_data(&mut self, data: bytes::Bytes) -> Result<bytes::Bytes, error::Error> {
        self.write_all(&data)?;
        self.flush()?;
        Ok(self.get_mut().get_mut().split().freeze())
    }

    fn on_finish(&mut self) -> Result<Option<bytes::Bytes>, error::Error> {
        self.try_finish()?;
        Ok(Some(self.get_mut().get_mut().split().freeze()))
    }
}

impl HttpBody for Body {
    type Data = bytes::Bytes;
    type Error = error::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.poll_data(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(inner)) => Poll::Ready(Some(inner.map(Frame::data))),
            Poll::Ready(None) => {
                // Yield any accumulated trailers as the final frame, exactly once.
                if !self.trailers_sent && !self.trailers.is_empty() {
                    self.trailers_sent = true;
                    return Poll::Ready(Some(Ok(Frame::trailers(self.trailers.clone()))));
                }

                Poll::Ready(None) // The queue of chunks is now empty!
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.chunks.is_empty() && (self.trailers_sent || self.trailers.is_empty())
    }

    /// This is an optional method, but implementing it correctly allows us to reduce the number of
    /// cases where bodies get sent with chunked Transfer-Encoding instead of Content-Length.
    fn size_hint(&self) -> SizeHint {
        let mut size = 0;
        for chunk in self.chunks.iter() {
            match chunk {
                // If this is a streaming body or a compressed chunk, immediately give up on the hint.
                Chunk::Channel(_) => return SizeHint::default(),
                Chunk::CompressedHttpBody(_, _) => return SizeHint::default(),
                Chunk::Bytes(bytes) => size += bytes.len() as u64,
                Chunk::HttpBody(body) => {
                    // An `HttpBody` size hint will either be exact, or wide open. If the latter,
                    // bail out with a wide-open range.
                    if let Some(chunk_size) = body.size_hint().exact() {
                        size += chunk_size;
                    } else {
                        return SizeHint::default();
                    }
                }
            }
        }
        SizeHint::with_exact(size)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use crate::body::Body;
    use bytes::{Bytes, BytesMut};
    use flate2::{Compression, GzBuilder};
    use http::HeaderMap;
    use http_body_util::{
        BodyExt,
        channel::{Channel, Sender},
    };
    use proptest::prelude::*;

    /// Proptest strategy: get a set of Bytes.
    fn some_bytes() -> impl Strategy<Value = Bytes> {
        proptest::collection::vec(any::<u8>(), 0..16).prop_map(|v| v.into())
    }

    // Gzip some bytes, with "best" compression and no header fields.
    fn compress_body(body: &[u8]) -> Bytes {
        let mut encoder =
            GzBuilder::new().buf_read(std::io::Cursor::new(body), Compression::best());
        let mut compressed = Vec::new();
        encoder
            .read_to_end(&mut compressed)
            .expect("failed to compress gzip body");
        compressed.into()
    }

    // Gradually send the provided body to the provided sender, using the provided chunk lengths.
    async fn trickle_body(mut sender: Sender<Bytes>, body: Bytes, chunk_lengths: Vec<usize>) {
        // Put "the whole body" at the back of the chunk-lengths, so we'll send the whole body by
        // the last iteration.
        let all_chunks = chunk_lengths.into_iter().chain(std::iter::once(body.len()));
        let mut remaining: &[u8] = &body;
        for chunk_length in all_chunks {
            if remaining.is_empty() {
                break;
            }
            let len = std::cmp::min(remaining.len(), chunk_length);
            let to_send = &remaining[..len];
            remaining = &remaining[len..];
            let Ok(_) = sender.send_data(Bytes::copy_from_slice(to_send)).await else {
                return;
            };
        }
        let _ = sender.send_trailers(HeaderMap::default()).await;
    }

    /// Check that the Body produces the given data, when read using the AsyncRead-like API.
    async fn check_body_read(
        mut body: crate::body::Body,
        want: Bytes,
    ) -> Result<(), TestCaseError> {
        let mut got = BytesMut::new();
        let buf = &mut [0u8; 16];
        while let Ok(n) = body.read(buf).await {
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        prop_assert_eq!(got.len(), want.len());
        for (i, (got, want)) in got.into_iter().zip(want).enumerate() {
            prop_assert_eq!(got, want, "@{}: {} != {}", i, got, want);
        }

        Ok(())
    }

    /// Test that a given body can round-trip, even if the body is split into chunks.
    async fn test_chunked_body(
        bytes: Bytes,
        chunk_lengths: Vec<usize>,
    ) -> Result<(), TestCaseError> {
        let mut js = tokio::task::JoinSet::default();
        let (sender, body) = Channel::new(1);
        js.spawn({
            let bytes = bytes.clone();
            async move {
                trickle_body(sender, bytes, chunk_lengths).await;
                Ok(())
            }
        });
        js.spawn(check_body_read(Body::http_body(body), bytes));
        let results = js.join_all().await;
        for result in results {
            result?;
        }
        Ok(())
    }

    /// Test that a given body can round-trip the Gzip decoder, even if the compressed body
    /// is split into chunks.
    async fn test_gzip_body(
        ungz_bytes: Bytes,
        chunk_lengths: Vec<usize>,
    ) -> Result<(), TestCaseError> {
        let gz_bytes = compress_body(&ungz_bytes);

        let mut js = tokio::task::JoinSet::default();
        let (sender, gz_body) = Channel::new(1);
        js.spawn({
            let gz_bytes = gz_bytes.clone();
            async move {
                trickle_body(sender, gz_bytes, chunk_lengths).await;
                Ok(())
            }
        });
        let ungz_body = Body::compressed_body(gz_body);
        js.spawn(check_body_read(ungz_body, ungz_bytes));
        let results = js.join_all().await;
        for result in results {
            result?;
        }
        Ok(())
    }

    /// Strategy to produce a body and a set of chunk lengths to split it into.
    fn chunk_strategy() -> impl Strategy<Value = (Bytes, Vec<usize>)> {
        some_bytes().prop_flat_map(|bytes| {
            let len = bytes.len();
            let chunk_length_strategy = proptest::collection::vec(0..=len, 0..=(len / 8));
            (Just(bytes), chunk_length_strategy)
        })
    }

    proptest! {
        #[test]
        fn gzip_chunks_reproduce_body(
            (body, chunk_lengths) in chunk_strategy()
        ) {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            rt.block_on(test_gzip_body(body, chunk_lengths))?
        }

    }

    proptest! {
        #[test]
        fn chunks_reproduce_body(
            (body, chunk_lengths) in chunk_strategy()
        ) {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            rt.block_on(test_chunked_body(body, chunk_lengths))?
        }

    }

    /// Trailers are not consumed by `await_ready` or `read`.
    /// Subsequent calls to `poll_frame` will yield the trailers exactly once.
    #[tokio::test]
    async fn data_reads_and_readiness_preserve_trailers() {
        use http_body::Body as _;
        use http_body_util::{BodyExt as _, StreamBody};

        let mut trailers = HeaderMap::new();
        trailers.insert("x-trailer", "value".parse().unwrap());
        let frames = [
            Ok::<_, std::convert::Infallible>(http_body::Frame::data(Bytes::from_static(b"abc"))),
            Ok(http_body::Frame::trailers(trailers.clone())),
        ];
        let mut body = super::Body::http_body(StreamBody::new(futures::stream::iter(frames)));

        // await_ready should peek at the chunk but not consume it
        // we should still have 'abc' to read after this
        body.await_ready().await;

        // now read two bytes
        let mut buf = [0; 2];
        assert_eq!(body.read(&mut buf).await.unwrap(), 2);
        assert_eq!(&buf, b"ab");

        // read should restore the remainder of the chunk
        // so that it can be read again
        assert_eq!(body.read(&mut buf).await.unwrap(), 1);
        assert_eq!(buf[0], b'c');

        // read produces 0 when no data remains
        assert_eq!(body.read(&mut buf).await.unwrap(), 0);

        // now consume the trailers through Body::poll_frame
        // (`BodyExt::frame` is convienience)
        assert_eq!(
            body.frame()
                .await
                .unwrap()
                .unwrap()
                .into_trailers()
                .unwrap(),
            trailers
        );
        // trailers are consumed
        assert!(body.is_end_stream());
        assert!(body.frame().await.is_none());

        // read & await_ready don't affect the presence of trailers
        // a subsequent frame call should be finished, and yield None
        assert_eq!(body.read(&mut buf).await.unwrap(), 0);
        body.await_ready().await;
        assert!(body.frame().await.is_none());
    }

    /// `await_ready` must not swallow errors.
    #[tokio::test]
    async fn await_ready_preserves_errors() {
        use super::Chunk;
        use http_body_util::{BodyExt as _, StreamBody};

        // Construct a http_body::Body that yields a single error.
        // we don't use `Body::http_body` here because it maps errors into `HyperError`
        let mut body = Body::from(Chunk::HttpBody(BodyExt::boxed(StreamBody::new(
            futures::stream::iter([Err(crate::Error::UnfinishedStreamingBody)]),
        ))));

        body.await_ready().await;
        let err = body.collect().await.unwrap_err();
        assert!(
            matches!(err, crate::Error::UnfinishedStreamingBody),
            "{err:?}"
        );
    }
}
