use crate::{body::Chunk, error::Error};
use http::{HeaderMap, HeaderName, HeaderValue};
use tokio::sync::mpsc;

// Note: this constant and comment is copied from xqd
//
// this isn't a tremendously useful size limiter, as it controls the number of chunks that can be in
// flight before applying backpressure, as opposed to the size of data in those chunks
const STREAMING_CHANNEL_SIZE: usize = 8;

/// The "write end" of a streaming body, used for writing to the body of a streaming upstream request
/// or a streaming downstream response.
///
/// The corresponding "read end" can be found in the [`Chunk`] type.
#[derive(Debug)]
pub struct StreamingBody {
    sender: mpsc::Sender<StreamingBodyItem>,
    pub(crate) trailers: HeaderMap,
}

/// The items sent over the `StreamingBody` channel.
///
/// These are either a [`Chunk`] corresponding to a write, or else a "finish" message. The purpose
/// of the finish message is to ensure that we don't accidentally make incomplete messages appear
/// complete.
///
/// If the streaming body is associated with a `content-length` request or response, the finish
/// message is largely meaningless, as the content length provides the necessary framing information
/// required for recipients to recognize an incomplete message.
///
/// The situation is more delicate with `transfer-encoding: chunked` requests and responses. In
/// these cases, `hyper` will dutifully frame each chunk as it reads them from the `Body`. If the
/// `Body` suddenly returns `Ok(None)`, it will apply the proper `0\r\n\r\n` termination to the
/// message. The finish message ensures that this will only happen when the Wasm program
/// affirmitavely marks the body as finished.
#[derive(Debug)]
pub enum StreamingBodyItem {
    Chunk(Chunk),
    Finished(HeaderMap),
}

impl StreamingBody {
    /// Create a new channel for streaming a body, returning write and read ends as a pair.
    pub fn new() -> (StreamingBody, mpsc::Receiver<StreamingBodyItem>) {
        let (sender, receiver) = mpsc::channel(STREAMING_CHANNEL_SIZE);
        (
            StreamingBody {
                sender,
                trailers: HeaderMap::new(),
            },
            receiver,
        )
    }

    /// Send a single chunk along this body stream.
    ///
    /// Returns a `StreamingChunkSend` error if the underlying channel encounters an error
    /// sending, e.g. due to the receive end being closed.
    pub async fn send_chunk(&mut self, chunk: impl Into<Chunk>) -> Result<(), Error> {
        self.sender
            .send(StreamingBodyItem::Chunk(chunk.into()))
            .await
            .map_err(|_| Error::StreamingChunkSend)
    }

    /// Convenience method for appending trailers.
    pub fn append_trailer(&mut self, name: HeaderName, value: HeaderValue) {
        self.trailers.append(name, value);
    }

    /// Block until the body has room for writing additional chunks.
    pub async fn await_ready(&mut self) {
        let _ = self.sender.reserve().await;
    }

    /// Mark this streaming body as finished, so that it will be terminated correctly.
    ///
    /// This is important primarily for `Transfer-Encoding: chunked` bodies where a premature close
    /// is only noticed if the chunked encoding is not properly terminated.
    pub fn finish(self) -> Result<(), Error> {
        match self
            .sender
            .try_send(StreamingBodyItem::Finished(self.trailers))
        {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Full(StreamingBodyItem::Finished(trailers))) => {
                // If the channel is full, maybe the other end is just taking a while to receive all
                // the bytes. Spawn a task that will send a `finish` message as soon as there's room
                // in the channel.
                tokio::task::spawn(async move {
                    let _ = self
                        .sender
                        .send(StreamingBodyItem::Finished(trailers))
                        .await;
                });
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                unreachable!("Only a StreamingBodyItem::Finished should be reachable")
            }
        }
    }
}
