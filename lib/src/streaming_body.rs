use crate::{body::Chunk, error::Error};
use tokio::sync::mpsc;

// Note: this constant and comment is copied from xqd
//
// this isn't a tremendously useful size limiter, as it controls the number of chunks that can be in
// flight before applying backpressure, as opposed to the size of data in those chunks
const STREAMING_CHANNEL_SIZE: usize = 128;

/// The "write end" of a streaming body, used for writing to the body of a streaming upstream request
/// or a streaming downstream response.
///
/// The corresponding "read end" can be found in the [`Chunk`] type.
#[derive(Debug)]
pub struct StreamingBody {
    sender: mpsc::Sender<Chunk>,
}

impl StreamingBody {
    /// Create a new channel for streaming a body, returning write and read ends as a pair.
    pub fn new() -> (StreamingBody, mpsc::Receiver<Chunk>) {
        let (sender, receiver) = mpsc::channel(STREAMING_CHANNEL_SIZE);
        (StreamingBody { sender }, receiver)
    }

    /// Send a single chunk along this body stream.
    ///
    /// Returns a `StreamingChunkSend` error if the underlying channel encounters an error
    /// sending, e.g. due to the receive end being closed.
    pub async fn send_chunk(&mut self, chunk: impl Into<Chunk>) -> Result<(), Error> {
        self.sender
            .send(chunk.into())
            .await
            .map_err(|_| Error::StreamingChunkSend)
    }
}
