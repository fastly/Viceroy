use std::{
    io::{self, Write},
    sync::{Arc, Mutex},
};

/// A named logging endpoint.
#[derive(Clone)]
pub struct LogEndpoint {
    name: Vec<u8>,
    writer: Arc<Mutex<dyn Write + Send>>,
}

impl LogEndpoint {
    /// Allocate a new `LogEndpoint` with the given name, with log messages sent
    /// to the given writer.
    pub fn new(name: &[u8], writer: Arc<Mutex<dyn Write + Send>>) -> LogEndpoint {
        LogEndpoint {
            name: name.to_owned(),
            writer,
        }
    }

    /// Write a log entry to this endpoint.
    ///
    /// Log entries are prefixed with the endpoint name and terminated with a newline.
    /// Any newlines in the message will be escaped to the string r"\n".
    ///
    /// The entry is written atomically to the writer given to [`LogEndpoint::new`].
    pub fn write_entry(&self, mut msg: &[u8]) -> io::Result<()> {
        const LOG_ENDPOINT_DELIM: &[u8] = b" :: ";

        // Strip any trailing newlines; we will add a newline at the end,
        // and escape any interior newlines.
        if msg.last() == Some(&b'\n') {
            msg = &msg[..msg.len() - 1];
        }

        if msg.is_empty() {
            return Ok(());
        }

        // Accumulate log entry into a buffer before writing, while escaping newlines
        let mut to_write =
            Vec::with_capacity(msg.len() + self.name.len() + LOG_ENDPOINT_DELIM.len() + 1);

        to_write.extend_from_slice(&self.name);
        to_write.extend_from_slice(LOG_ENDPOINT_DELIM);
        for &byte in msg {
            if byte == b'\n' {
                to_write.extend_from_slice(br"\n");
            } else {
                to_write.push(byte);
            }
        }
        to_write.push(b'\n');

        self.writer.lock().unwrap().write_all(&to_write)
    }
}

impl Write for LogEndpoint {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_entry(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.lock().unwrap().flush()
    }
}

impl wasmtime_wasi::StdoutStream for LogEndpoint {
    fn stream(&self) -> Box<dyn wasmtime_wasi::HostOutputStream> {
        Box::new(self.clone())
    }

    fn isatty(&self) -> bool {
        false
    }
}

#[wiggle::async_trait]
impl wasmtime_wasi::Subscribe for LogEndpoint {
    async fn ready(&mut self) {}
}

impl wasmtime_wasi::HostOutputStream for LogEndpoint {
    fn write(&mut self, bytes: bytes::Bytes) -> wasmtime_wasi::StreamResult<()> {
        self.write_entry(&bytes)
            .map_err(|e| wasmtime_wasi::StreamError::LastOperationFailed(anyhow::anyhow!(e)))
    }

    fn flush(&mut self) -> wasmtime_wasi::StreamResult<()> {
        <Self as Write>::flush(self)
            .map_err(|e| wasmtime_wasi::StreamError::LastOperationFailed(anyhow::anyhow!(e)))
    }

    fn check_write(&mut self) -> wasmtime_wasi::StreamResult<usize> {
        Ok(1024 * 1024)
    }
}
