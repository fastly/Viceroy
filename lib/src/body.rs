//! Body type, for request and response bodies.

use crate::streaming_body::StreamingBodyItem;
use crate::Error;

use {
    crate::error,
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

                    match body_mut.poll_data(cx) {
                        Poll::Pending => {
                            // put the body back, so we can poll it again next time
                            self.chunks.push_front(body.into());
                            return Poll::Pending;
                        }
                        Poll::Ready(None) => {
                            // no more bytes from this body, so continue the loop now that it's been
                            // popped
                            //
                            // TODO ACF 2020-06-01: do something with the body's trailers at this point
                            continue;
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
                        Poll::Ready(Some(StreamingBodyItem::Finished)) => {
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

                                    return Poll::Ready(Some(Ok(resulting_bytes)));
                                }
                            }
                        }
                    }
                }
            }
        }

        Poll::Ready(None) // The queue of chunks is now empty!
    }

    fn poll_trailers(
        self: Pin<&mut Self>,
        _cx: &mut Context,
    ) -> Poll<Result<Option<HeaderMap>, Self::Error>> {
        Poll::Ready(Ok(None)) // `Body` does not currently have trailers.
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
