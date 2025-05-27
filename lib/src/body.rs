//! Body type, for request and response bodies.

use futures::FutureExt;

use {
    crate::{error, streaming_body::StreamingBodyItem, Error},
    bytes::{BufMut, BytesMut},
    flate2::write::GzDecoder,
    futures::pin_mut,
    http::header::HeaderMap,
    http_body::{Body as HttpBody, SizeHint},
    std::{
        collections::VecDeque,
        io::Write,
        pin::Pin,
        task::{Context, Poll},
    },
    tokio::sync::mpsc,
};

type DecoderState = Box<GzDecoder<bytes::buf::Writer<BytesMut>>>;

/// A chunk of bytes in a [`Body`].
///
/// A chunk represents a block of data in a body. Representing bodies as chunks allows us to append
/// one body to another without copying, and makes it possible from parts of the body to come from
/// different sources, including ongoing asynchronous streaming.
#[derive(Debug)]
pub enum Chunk {
    /// Wraps Hyper's http body representation.
    ///
    /// We use this variant for both data that's incoming from a Hyper request, and for owned byte
    /// buffers that we've allocated while writing to a `Body`.
    HttpBody(hyper::Body),
    /// A channel for bodies that may be written to after headers have been sent, such as after
    /// `send_downstream_streaming` or `send_async_streaming`.
    ///
    /// Since the channel yields chunks, this variant represents a *stream* of chunks rather than
    /// one individual chunk. That stream is effectively "flattened" on-demand, as the `Body`
    /// containing it is read.
    Channel(mpsc::Receiver<StreamingBodyItem>),
    /// A version of `HttpBody` that assumes that the interior data is gzip-compressed.
    CompressedHttpBody(DecoderState, hyper::Body),
}

impl Chunk {
    pub fn compressed_body(body: hyper::Body) -> Chunk {
        let initial_state = Box::new(GzDecoder::new(BytesMut::new().writer()));
        Chunk::CompressedHttpBody(initial_state, body)
    }
}

impl From<&[u8]> for Chunk {
    fn from(bytes: &[u8]) -> Self {
        Self::HttpBody(hyper::Body::from(bytes.to_vec()))
    }
}

impl From<Vec<u8>> for Chunk {
    fn from(vec: Vec<u8>) -> Self {
        Self::HttpBody(hyper::Body::from(vec))
    }
}

impl From<bytes::Bytes> for Chunk {
    fn from(bytes: bytes::Bytes) -> Self {
        Self::HttpBody(hyper::Body::from(bytes))
    }
}

impl From<hyper::Body> for Chunk {
    fn from(body: hyper::Body) -> Self {
        Chunk::HttpBody(body)
    }
}

impl From<mpsc::Receiver<StreamingBodyItem>> for Chunk {
    fn from(chan: mpsc::Receiver<StreamingBodyItem>) -> Self {
        Chunk::Channel(chan)
    }
}

/// An HTTP request or response body.
///
/// Most importantly, this type implements [`http_body::Body`][body-trait]. This type is an
/// alternative to [`hyper::Body`][hyper-body], with facilities to write to an existing body, and
/// to append bodies to one another.
///
/// [body-trait]: https://docs.rs/http-body/latest/http_body/trait.Body.html
/// [hyper-body]: https://docs.rs/hyper/latest/hyper/body/struct.Body.html
#[derive(Default, Debug)]
pub struct Body {
    chunks: VecDeque<Chunk>,
    pub(crate) trailers: HeaderMap,
    pub(crate) trailers_ready: bool,
}

impl Body {
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

    /// Read the entire body into a byte vector.
    pub async fn read_into_vec(self) -> Result<Vec<u8>, error::Error> {
        let mut body = Box::new(self);
        let mut bytes = Vec::new();

        while let Some(chunk) = body.data().await.transpose()? {
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
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
        // Attempt to read a chunk, blocking until one is available (or `None` signals end of stream)
        if let Some(Ok(chunk)) = self.data().await {
            // If we did get a chunk, put it back; subsequent read attempts will find this chunk without
            // additional blocking.
            self.chunks.push_front(chunk.into())
        }
    }

    pub fn len(&self) -> Option<u64> {
        let mut len = 0u64;

        for chunk in &self.chunks {
            if let Chunk::HttpBody(body) = chunk {
                len = len.checked_add(body.size_hint().exact()?)?;
            } else {
                return None;
            }
        }

        Some(len)
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

impl HttpBody for Body {
    type Data = bytes::Bytes;
    type Error = error::Error;

    fn poll_data(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Option<Result<Self::Data, Self::Error>>> {
        while let Some(mut chunk) = self.chunks.pop_front() {
            match chunk {
                Chunk::HttpBody(mut body) => {
                    let body_mut = &mut body;
                    pin_mut!(body_mut);

                    match body_mut.as_mut().poll_data(cx) {
                        Poll::Pending => {
                            // put the body back, so we can poll it again next time
                            self.chunks.push_front(body.into());
                            return Poll::Pending;
                        }
                        Poll::Ready(None) => {
                            // no more bytes from this body, so continue the loop now that it's been
                            // popped
                            match body_mut.trailers().poll_unpin(cx) {
                                Poll::Pending => {
                                    self.chunks.push_front(body.into());
                                    return Poll::Pending;
                                }

                                Poll::Ready(Err(e)) => {
                                    return Poll::Ready(Some(Err(e.into())));
                                }

                                Poll::Ready(Ok(None)) => continue,

                                Poll::Ready(Ok(Some(header_map))) => {
                                    for (k, v) in header_map.iter() {
                                        self.trailers.append(k, v.clone());
                                    }
                                    continue;
                                }
                            }
                        }
                        Poll::Ready(Some(item)) => {
                            // put the body back, so we can poll it again next time
                            self.chunks.push_front(body.into());
                            return Poll::Ready(Some(item.map_err(Into::into)));
                        }
                    }
                }
                Chunk::Channel(mut receiver) => {
                    let receiver_mut = &mut receiver;
                    pin_mut!(receiver_mut);
                    match receiver_mut.poll_recv(cx) {
                        Poll::Pending => {
                            // put the channel back, so we can poll it again next time
                            self.chunks.push_front(receiver.into());
                            return Poll::Pending;
                        }
                        Poll::Ready(None) => {
                            // the channel completed without a Finish message, so yield an error
                            return Poll::Ready(Some(Err(Error::UnfinishedStreamingBody)));
                        }
                        Poll::Ready(Some(StreamingBodyItem::Chunk(chunk))) => {
                            // put the channel back first, so we can poll it again after the chunk it
                            // just yielded
                            self.chunks.push_front(receiver.into());
                            // now push the chunk which will be polled appropriately the next time
                            // through the loop
                            self.chunks.push_front(chunk);
                            continue;
                        }
                        Poll::Ready(Some(StreamingBodyItem::Finished(trailers))) => {
                            self.trailers.extend(trailers);
                            // it shouldn't be possible for any more chunks to arrive on this
                            // channel, but just in case we won't try to read them; dropping the
                            // receiver means we won't hit the `Ready(None)` case above that
                            // indicates an unfinished streaming body
                            continue;
                        }
                    }
                }
                Chunk::CompressedHttpBody(ref mut decoder_state, ref mut body) => {
                    pin_mut!(body);

                    match body.poll_data(cx) {
                        Poll::Pending => {
                            // put the body back, so we can poll it again next time
                            self.chunks.push_front(chunk);
                            return Poll::Pending;
                        }
                        Poll::Ready(None) => match decoder_state.try_finish() {
                            Err(e) => return Poll::Ready(Some(Err(e.into()))),
                            Ok(()) => {
                                let chunk = decoder_state.get_mut().get_mut().split().freeze();
                                return Poll::Ready(Some(Ok(chunk)));
                            }
                        },
                        Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e.into()))),
                        Poll::Ready(Some(Ok(bytes))) => {
                            match decoder_state.write_all(&bytes) {
                                Err(e) => return Poll::Ready(Some(Err(e.into()))),
                                Ok(()) => {
                                    decoder_state.flush().unwrap();
                                    let resulting_bytes =
                                        decoder_state.get_mut().get_mut().split().freeze();
                                    // put the body back, so we can poll it again next time
                                    self.chunks.push_front(chunk);
                                    if resulting_bytes.is_empty() {
                                        // If we got no bytes from this chunk, it might be just the gzip header
                                        // we'll continue the loop to process more chunks
                                        continue;
                                    } else {
                                        return Poll::Ready(Some(Ok(resulting_bytes)));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // With no more chunks arriving we can mark trailers as being ready.
        self.trailers_ready = true;
        Poll::Ready(None) // The queue of chunks is now empty!
    }

    fn poll_trailers(
        self: Pin<&mut Self>,
        _cx: &mut Context,
    ) -> Poll<Result<Option<HeaderMap>, Self::Error>> {
        if !self.chunks.is_empty() {
            return Poll::Pending;
        }
        if self.trailers.is_empty() {
            Poll::Ready(Ok(None))
        } else {
            Poll::Ready(Ok(Some(self.trailers.clone())))
        }
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

    use bytes::{Buf, Bytes, BytesMut};
    use flate2::{Compression, GzBuilder};
    use http::HeaderMap;
    use http_body::Body as _;
    use proptest::prelude::*;

    use crate::body::Chunk;

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
    async fn trickle_body(mut sender: hyper::body::Sender, body: Bytes, chunk_lengths: Vec<usize>) {
        // Put "the whole body" at the back of the chunk-lengths, so we'll send the whole body by
        // the last iteration.
        let all_chunks = chunk_lengths.into_iter().chain(std::iter::once(body.len()));
        let mut remaining: &[u8] = &body;
        for chunk_length in all_chunks {
            let len = std::cmp::min(remaining.len(), chunk_length);
            if len == 0 {
                break;
            }
            let to_send = &remaining[..len];
            remaining = &remaining[len..];
            let Ok(_) = sender.send_data(Bytes::copy_from_slice(to_send)).await else {
                return;
            };
        }
        let _ = sender.send_trailers(HeaderMap::default()).await;
    }

    /// Test that a given body can round-trip, even if the body is split into chunks.
    async fn test_roundtrip_body(
        bytes: Bytes,
        chunk_lengths: Vec<usize>,
    ) -> Result<(), TestCaseError> {
        let mut js = tokio::task::JoinSet::default();
        let (sender, mut body) = hyper::Body::channel();
        js.spawn({
            let bytes = bytes.clone();
            // let gz_bytes = ungz_bytes.clone();
            async move {
                trickle_body(sender, bytes, chunk_lengths).await;
                Ok(())
            }
        });
        js.spawn(async move {
            let mut received = BytesMut::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.unwrap();
                // Technically permissible, but undesirable.
                // prop_assert_ne!(chunk.len(), 0);
                received.extend_from_slice(&chunk);
            }
            let got_body = received.freeze();
            prop_assert_eq!(got_body.len(), bytes.len());
            for (i, (got, want)) in got_body.into_iter().zip(bytes.into_iter()).enumerate() {
                prop_assert_eq!(got, want, "{}: {} != {}", i, got, want);
            }
            Ok(())
        });
        let results = js.join_all().await;
        for result in results {
            result?;
        }
        Ok(())
    }

    /// Test that a given body can round-trip the Gzip decoder, even if the body
    /// is split into chunks.
    async fn test_ungzip_body(
        ungz_bytes: Bytes,
        chunk_lengths: Vec<usize>,
    ) -> Result<(), TestCaseError> {
        let gz_bytes = compress_body(&ungz_bytes);

        let mut js = tokio::task::JoinSet::default();
        let (sender, gz_body) = hyper::Body::channel();
        js.spawn({
            let gz_bytes = gz_bytes.clone();
            // let gz_bytes = ungz_bytes.clone();
            async move {
                trickle_body(sender, gz_bytes, chunk_lengths).await;
                Ok(())
            }
        });
        let mut ungz_body: crate::body::Body = Chunk::compressed_body(gz_body).into();
        js.spawn(async move {
            let mut received = BytesMut::new();
            while let Some(chunk) = ungz_body.data().await {
                let chunk = chunk.unwrap();
                // Technically permissible, but undesirable.
                // prop_assert_ne!(chunk.len(), 0);
                received.extend_from_slice(&chunk);
            }
            let got_body = received.freeze();
            prop_assert_eq!(got_body.len(), ungz_bytes.len());
            for (i, (got, want)) in got_body.into_iter().zip(ungz_bytes.into_iter()).enumerate() {
                prop_assert_eq!(got, want, "{}: {} != {}", i, got, want);
            }
            Ok(())
        });
        let results = js.join_all().await;
        for result in results {
            result?;
        }
        Ok(())
    }

    // TODO: Update this to support zero-length input chunks.
    // It's possible, in principle, to send a zero-length chunk from the server side;
    // but it appears we don't handle it well.
    proptest! {
        #[test]
        fn gzip_chunks_reproduce_body(
            (body, chunk_lengths) in some_bytes().prop_flat_map(|bytes| {
                    let len = bytes.len();
                    let chunk_length_strategy= proptest::collection::vec(1..=len, 0..=(len/8));
            (Just(bytes), chunk_length_strategy)
            }),
        ) {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            return rt.block_on(test_ungzip_body(body, chunk_lengths));
        }

    }

    // TODO: Update this to support zero-length input chunks.
    // It's possible, in principle, to send a zero-length chunk from the server side;
    // but it appears we don't handle it well.
    proptest! {
        #[test]
        fn chunks_reproduce_body(
            (body, chunk_lengths) in some_bytes().prop_flat_map(|bytes| {
                    let len = bytes.len();
                    let chunk_length_strategy= proptest::collection::vec(1..=len, 0..=(len/8));
            (Just(bytes), chunk_length_strategy)
            }),
        ) {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            return rt.block_on(test_roundtrip_body(body, chunk_lengths));
        }

    }

    #[tokio::test]
    async fn directed_nonempty_chunks() {
        let data = b"hello world";
        let gz_data: Bytes = {
            let mut encoder = GzBuilder::new()
                .mtime(32)
                .buf_read(Bytes::from_static(data).reader(), Compression::best());
            let mut compressed = Vec::new();
            encoder.read_to_end(&mut compressed).unwrap();
            compressed.into()
        };

        let len = gz_data.len();
        for cutpoint in 0..(len - 1) {
            let mut js = tokio::task::JoinSet::default();
            let (mut sender, gz_body) = hyper::Body::channel();
            js.spawn({
                let gz_data = gz_data.clone();
                async move {
                    let head = &gz_data[..cutpoint];
                    let tail = &gz_data[cutpoint..];
                    let Ok(_) = sender.send_data(Bytes::copy_from_slice(head)).await else {
                        return;
                    };
                    // Force yield, so hyper can't collapse adjacent sends.
                    tokio::task::yield_now().await;
                    // Send the remainder:
                    let Ok(_) = sender.send_data(Bytes::copy_from_slice(tail)).await else {
                        return;
                    };
                    tokio::task::yield_now().await;
                    let Ok(_) = sender.send_trailers(HeaderMap::default()).await else {
                        return;
                    };
                }
            });

            let mut ungz_body: crate::body::Body = Chunk::compressed_body(gz_body).into();
            js.spawn(async move {
                let mut received = BytesMut::new();
                while let Some(chunk) = ungz_body.data().await {
                    let chunk = chunk.unwrap();
                    // assert_ne!(chunk.len(), 0);
                    received.extend_from_slice(&chunk);
                }
                let got_body = received.freeze();
                assert_eq!(got_body.len(), data.len());
                for (i, (got, &want)) in got_body.into_iter().zip(data.into_iter()).enumerate() {
                    assert_eq!(got, want, "{i}: {got} != {want}");
                }
            });
            js.join_all().await;

            /*
            let r = test_nonempty_chunks(vec![cutpoint], gz_data.clone()).await;
            if let Err(c) = r {
                panic!("error with cutpoint {cutpoint}: {c}");
            }*/
        }
    }
}
